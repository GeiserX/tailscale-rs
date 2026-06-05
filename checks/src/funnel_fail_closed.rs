//! Leak firewall: the public-TLS termination path must stay fail-closed.
//!
//! WHY: `listen_tls` (tailnet `*.ts.net` HTTPS) and `listen_funnel` (public Funnel ingress) both
//! terminate TLS. The fork cannot yet obtain a publicly-trusted certificate (no client-side ACME
//! engine, and a self-hosted control plane provides no `set-dns` DNS-01 publish RPC), and Funnel
//! additionally needs a Tailscale-operated public ingress relay that a self-hosted control plane
//! does not provide. The sacred posture is therefore: obtain a real cert via
//! `cert::get_certificate` (which itself returns `CertError::Unimplemented`), and otherwise surface
//! a typed fail-closed error — NEVER fall back to a self-signed cert or a plaintext downgrade. A
//! self-signed/ephemeral cert minted in the production path would let a listener come up serving
//! the wrong trust material instead of failing closed.
//!
//! WHAT THIS CHECKS: it scans the NON-TEST lines of every file in [`GUARDED`] for cert-minting
//! tokens that only ever belong in `#[cfg(test)]` (e.g. `rcgen`, `generate_simple_self_signed`,
//! `self_signed`). Both `serve.rs` (the listener entry points) and `cert.rs` (where the real
//! `CertifiedKey` assembly primitives `certified_key_from_pem` / `certified_key_from_der` live —
//! the exact spot a self-signed leaf would be wired in) are guarded. Test code legitimately mints
//! an ephemeral self-signed cert to exercise the rustls acceptor wiring; production code must not.
//!
//! To keep this robust without a full parser, the scan ignores everything from the file's
//! `#[cfg(test)]` test module to end-of-file and ignores comment/doc lines. The `#[cfg(test)]`
//! cutoff is matched **only at column 0** (the module-level boundary), and the file must contain
//! **exactly one** such boundary — more than one is treated as an evasion attempt (a stray early
//! `#[cfg(test)]` could truncate the scan and hide minting below it) and hard-fails the check.

use crate::{Args, BoxResult};

/// Files whose production (non-test) portion must never mint a cert.
const GUARDED: &[&str] = &["ts_control/src/serve.rs", "ts_control/src/cert.rs"];

/// Tokens that mint a self-signed / ephemeral cert. Legitimate only under `#[cfg(test)]`.
const FORBIDDEN: &[&str] = &["rcgen", "generate_simple_self_signed", "self_signed"];

/// The column-0 test-module boundary. Matched exactly (no leading whitespace) so an indented,
/// nested `#[cfg(test)]` inside a function body cannot prematurely truncate the production scan.
const TEST_BOUNDARY: &str = "#[cfg(test)]";

pub fn run(_args: &Args) -> BoxResult<()> {
    let mut hits: Vec<String> = Vec::new();

    for path in GUARDED {
        let contents = std::fs::read_to_string(path)?;

        // Find the column-0 test-module boundary. There must be exactly one; more than one is an
        // evasion vector (an early stray `#[cfg(test)]` would truncate the scan), so hard-fail.
        let boundaries: Vec<usize> = contents
            .lines()
            .enumerate()
            .filter(|(_, line)| *line == TEST_BOUNDARY)
            .map(|(i, _)| i)
            .collect();
        let cutoff = match boundaries.as_slice() {
            [one] => *one,
            [] => {
                return Err(format!(
                    "{path}: no column-0 `#[cfg(test)]` test-module boundary found; the leak \
                     firewall relies on exactly one to bound the production scan. If the test \
                     module moved, fix this check. STOP."
                )
                .into());
            }
            many => {
                return Err(format!(
                    "{path}: found {} column-0 `#[cfg(test)]` boundaries (expected exactly 1). A \
                     stray early `#[cfg(test)]` can truncate the leak scan and hide cert-minting \
                     below it. STOP.",
                    many.len()
                )
                .into());
            }
        };

        for (lineno, line) in contents.lines().enumerate().take(cutoff) {
            // Ignore comment / doc lines: the prose explains the fail-closed design and may name
            // the forbidden tokens (e.g. "no self-signed fallback", "ECDSA P-256 via `rcgen`").
            if line.trim_start().starts_with("//") {
                continue;
            }
            if FORBIDDEN.iter().any(|t| line.contains(t)) {
                hits.push(format!("{path}:{}: {}", lineno + 1, line.trim()));
            }
        }
    }

    if !hits.is_empty() {
        eprintln!("Self-signed/ephemeral cert minting leaked into the production TLS path:");
        for hit in &hits {
            eprintln!("  {hit}");
        }
        eprintln!(
            "listen_tls/listen_funnel/cert must stay fail-closed: obtain a real cert via \
             cert::get_certificate or surface a typed error — never mint a self-signed cert or \
             downgrade to plaintext outside #[cfg(test)]. STOP."
        );
        return Err("cert-minting tokens found in a guarded production file".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FORBIDDEN, TEST_BOUNDARY};

    #[test]
    fn forbidden_tokens_catch_self_signed_minting() {
        let leak_rcgen = "let cert = rcgen::generate_simple_self_signed(names).unwrap();";
        let leak_fn = "fn make_self_signed() -> CertifiedKey { ... }";
        assert!(FORBIDDEN.iter().any(|t| leak_rcgen.contains(t)));
        assert!(FORBIDDEN.iter().any(|t| leak_fn.contains(t)));
    }

    #[test]
    fn legitimate_production_lines_do_not_trip() {
        let ok_lines = [
            "let cert = cert::get_certificate(&cfg.name).await?;",
            "Err(FunnelError::Unsupported { detail: MISSING_FUNNEL_RELAY.to_string() })",
            "pub async fn listen_tls(cfg: &ServeConfig) -> Result<TlsAcceptor, CertError> {",
            "pub fn certified_key_from_pem(cert_chain_pem: &[u8], key_pem: &[u8])",
            "let signing_key = ring::sign::any_supported_type(&key).map_err(CertError::Rustls)?;",
        ];
        for line in ok_lines {
            assert!(
                !FORBIDDEN.iter().any(|t| line.contains(t)),
                "false positive on legitimate production line: {line}"
            );
        }
    }

    #[test]
    fn test_boundary_is_column_zero_exact() {
        // The cutoff must match only at column 0, so an indented nested attribute inside a
        // function body cannot prematurely truncate the production scan.
        assert_ne!("    #[cfg(test)]", TEST_BOUNDARY);
        assert_eq!("#[cfg(test)]", TEST_BOUNDARY);
    }
}
