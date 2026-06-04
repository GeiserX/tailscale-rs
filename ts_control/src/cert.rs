//! TLS certificate acquisition for a node's MagicDNS name (`host.tailnet.ts.net`).
//!
//! # What tsnet does (the real protocol — there is NO control `cert/<domain>` RPC)
//!
//! In upstream Tailscale, `tsnet`'s `GetCertificate` mints a *real* publicly
//! trusted certificate for the node's MagicDNS name. Contrary to a common
//! misreading, control does **not** run the ACME order on the node's behalf and
//! there is **no** `POST /machine/<machineKey>/cert/<domain>` endpoint. Instead
//! **the node itself is the ACME client** and talks **directly to Let's
//! Encrypt**; control's *only* role is to publish the DNS-01 challenge TXT record
//! into the `ts.net` zone it controls (the node has no authority over that zone).
//! The real flow upstream is:
//!
//! 1. node generates/loads an ACME account key (ECDSA P-256) and a fresh cert
//!    key, and opens an ACME order for `<name>` directly against Let's Encrypt,
//! 2. for the **DNS-01** challenge, the node computes the challenge digest and
//!    asks control to publish it by sending, over the **Noise (ts2021)** channel,
//!    `POST /machine/set-dns` with body
//!    `tailcfg.SetDNSRequest{ Version: <current cap>, NodeKey: <node pub>,
//!    Name: "_acme-challenge.<name>", Type: "TXT", Value: <digest> }`
//!    (note: `NodeKey` travels in the BODY, not the URL; the response is an empty
//!    `SetDNSResponse{}` with HTTP 200 on success),
//! 3. node tells Let's Encrypt the challenge is ready; LE validates the TXT,
//! 4. node finalizes the order and downloads the signed leaf + chain *from LE*,
//! 5. node assembles a [`rustls::sign::CertifiedKey`] and serves it, renewing at
//!    ~2/3 of lifetime (with ARI).
//!
//! (DNS-01 is used for `*.ts.net`; TLS-ALPN-01 is used for Funnel/BYO domains;
//! HTTP-01 is not used.)
//!
//! ## Gap verdict for THIS fork (fail-closed seam, no fake cert)
//!
//! The control client in this crate (`ts_control::tokio`) implements exactly
//! these control RPCs and **no others**:
//!
//! - `GET /key`            — control/Noise public key fetch ([`crate::tokio::connect`])
//! - `POST /ts2021`        — Noise (ts2021) handshake upgrade
//! - `POST /machine/register` — node registration ([`crate::tokio::register`])
//! - `POST /machine/map`   — netmap stream + endpoint/derp updates
//! - ping-response callback (`/machine/.../ping`)
//!
//! There is **no** `POST /machine/set-dns` client and **no** ACME engine. Neither
//! the DNS-01 TXT publish RPC nor the LE-facing order/challenge/finalize state
//! machine exists, so a node cannot obtain a publicly trusted cert for its
//! `*.ts.net` name here.
//!
//! Because issuing a real cert is impossible and self-signing for production is
//! forbidden (it would not be publicly trusted and would teach callers to expect
//! a working `ListenTLS`), [`get_certificate`] returns
//! [`CertError::Unimplemented`] naming exactly what is missing. This is
//! **fail-closed**: no self-signed fallback, no plaintext downgrade.
//!
//! ## What a future implementation needs (so this seam can be filled in place)
//!
//! - A **client-side ACME engine** (talks to Let's Encrypt directly, not to
//!   control): ACME account key + cert key generation (ECDSA P-256 via `rcgen`,
//!   ring-only), JWS-signed order/authz/challenge/finalize, and leaf+chain
//!   download. Renew at ~2/3 lifetime.
//! - A `POST /machine/set-dns` Noise RPC client to publish the
//!   `_acme-challenge.<name>` TXT record (body carries `NodeKey`; see step 2
//!   above). Add it alongside the existing RPCs in [`crate::tokio`]
//!   (`register.rs` is the template; the Noise transport is `connect.rs`).
//! - Local ACME account-key persistence keyed to the node identity.
//!
//! **Deployment caveat (why this is currently stubbed, not built):** the fork's
//! control plane target is **a self-hosted control plane**, which returns **HTTP 501
//! NotImplemented** for `/machine/set-dns`. A client-side ACME engine therefore
//! cannot complete a DNS-01 challenge against a self-hosted control plane — the issuance path
//! is non-functional until a self-hosted control plane grows `set-dns` + a real backing DNS zone
//! (separate, out-of-repo work). Building the ACME engine here without that would
//! be dead code against the actual control plane.
//!
//! Once both pieces land (and control answers `set-dns`), replace the
//! [`CertError::Unimplemented`] branch in [`get_certificate`] with: open order ->
//! publish TXT via `set-dns` -> finalize -> assemble [`CertifiedKey`] from the
//! LE-returned chain + locally held key via [`certified_key_from_pem`].

use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::CertifiedKey,
};

/// Names exactly what this fork is missing to issue a real cert, surfaced
/// verbatim in [`CertError::Unimplemented`] so the gap is self-documenting at
/// runtime. There is no control `cert/<domain>` RPC in real Tailscale — the node
/// is the ACME client and only needs control to publish the DNS-01 TXT via
/// `POST /machine/set-dns` (which a self-hosted control plane 501s). See the module docs.
pub const MISSING_CERT_RPC: &str = "client-side ACME engine (direct to Let's Encrypt) + a POST /machine/set-dns \
     Noise RPC to publish the _acme-challenge TXT (a self-hosted control plane returns 501 for set-dns)";

/// Errors from certificate acquisition / TLS material assembly.
///
/// Fail-closed by construction: there is no variant that yields a usable cert
/// without a genuine issuance path, and there is deliberately no self-signed
/// production fallback.
#[derive(Debug)]
pub enum CertError {
    /// The control plane in this fork does not expose the RPC(s) needed to mint
    /// a real certificate. `detail` names exactly what is missing.
    Unimplemented {
        /// Names exactly which control RPC is missing (e.g. [`MISSING_CERT_RPC`]).
        detail: String,
    },
    /// An ACME-protocol-level failure (order/challenge/finalize).
    Acme(String),
    /// I/O failure (network, file, etc.).
    Io(std::io::Error),
    /// A rustls / crypto-material failure (bad key, mismatched cert, provider).
    Rustls(tokio_rustls::rustls::Error),
    /// The requested name is not a tailnet (`*.ts.net`-style) name. Anti-leak:
    /// we never mint or serve certs for off-tailnet names.
    NotTailnetName(String),
}

impl core::fmt::Display for CertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CertError::Unimplemented { detail } => {
                write!(
                    f,
                    "certificate acquisition is unimplemented in this fork: {detail}"
                )
            }
            CertError::Acme(e) => write!(f, "ACME error: {e}"),
            CertError::Io(e) => write!(f, "I/O error: {e}"),
            CertError::Rustls(e) => write!(f, "rustls error: {e}"),
            CertError::NotTailnetName(name) => {
                write!(
                    f,
                    "refusing to obtain a certificate for non-tailnet name {name:?}"
                )
            }
        }
    }
}

impl std::error::Error for CertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CertError::Io(e) => Some(e),
            CertError::Rustls(e) => Some(e),
            CertError::Unimplemented { .. } | CertError::Acme(_) | CertError::NotTailnetName(_) => {
                None
            }
        }
    }
}

impl From<std::io::Error> for CertError {
    fn from(e: std::io::Error) -> Self {
        CertError::Io(e)
    }
}

impl From<tokio_rustls::rustls::Error> for CertError {
    fn from(e: tokio_rustls::rustls::Error) -> Self {
        CertError::Rustls(e)
    }
}

/// Returns `true` if `name` looks like a tailnet MagicDNS name we may serve a
/// cert for. We only ever mint/serve certs for tailnet names — never arbitrary
/// public hostnames — to avoid being turned into a cert oracle for off-tailnet
/// origins.
pub fn is_tailnet_name(name: &str) -> bool {
    // `host.tailnet.ts.net` (public) or `*.ts.net`. Keep this conservative.
    let name = name.trim_end_matches('.');
    !name.is_empty() && name.ends_with(".ts.net") && !name.contains('/')
}

/// Obtain a [`CertifiedKey`] for a node's MagicDNS `name`.
///
/// **Fail-closed.** In this fork the control plane exposes no ACME / DNS-01 cert
/// RPC (see module docs), so this always returns [`CertError::Unimplemented`]
/// once the name passes the tailnet-name check. It NEVER self-signs and NEVER
/// returns a placeholder cert — a caller cannot accidentally serve an untrusted
/// certificate.
///
/// When the control RPC ([`MISSING_CERT_RPC`]) is added, fill in the issuance
/// branch here.
pub async fn get_certificate(name: &str) -> Result<CertifiedKey, CertError> {
    if !is_tailnet_name(name) {
        return Err(CertError::NotTailnetName(name.to_string()));
    }

    // No client-side ACME engine and no set-dns RPC exist in this fork, and the
    // a self-hosted control plane control target 501s on set-dns. Do NOT self-sign.
    Err(CertError::Unimplemented {
        detail: format!(
            "cannot issue a real certificate for {name:?}; requires: {MISSING_CERT_RPC}"
        ),
    })
}

/// Assemble a [`CertifiedKey`] from a PEM chain + PEM private key, using the
/// **ring** crypto provider's signing-key loader (matching the rest of the TLS
/// stack — `ts_tls_util` is `tokio-rustls`/`ring`). This is the assembly helper
/// a future real issuance path (or a test) feeds the control-returned chain into.
///
/// This does NOT fetch or issue anything; it only turns already-trusted material
/// into the rustls representation. Production callers reach it only via a genuine
/// issuance path; tests reach it with a clearly-marked self-signed cert.
pub fn certified_key_from_pem(
    cert_chain_pem: &[u8],
    key_pem: &[u8],
) -> Result<CertifiedKey, CertError> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_chain_pem[..]).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(CertError::Acme(
            "certificate chain PEM contained no certificates".into(),
        ));
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| CertError::Acme("private key PEM contained no key".into()))?;

    certified_key_from_der(certs, key)
}

/// Assemble a [`CertifiedKey`] from DER cert chain + DER private key using the
/// ring signing-key loader. Verifies the key matches the leaf (fail-closed).
pub fn certified_key_from_der(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<CertifiedKey, CertError> {
    // Match the rest of the stack: ring provider's signing-key loader, never
    // auto-detect (which panics under ring+aws-lc feature unification).
    // `any_supported_type` already yields an `Arc<dyn SigningKey>`; don't re-wrap.
    let signing_key = tokio_rustls::rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(CertError::Rustls)?;
    let ck = CertifiedKey::new(cert_chain, signing_key);
    ck.keys_match().map_err(CertError::Rustls)?;
    Ok(ck)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailnet_name_accepts_magicdns() {
        assert!(is_tailnet_name("host.tail1234.ts.net"));
        assert!(is_tailnet_name("host.tail1234.ts.net."));
    }

    #[test]
    fn tailnet_name_rejects_offtailnet() {
        assert!(!is_tailnet_name("example.com"));
        assert!(!is_tailnet_name("evil.ts.net.attacker.com"));
        assert!(!is_tailnet_name(""));
        assert!(!is_tailnet_name("host.ts.net/path"));
    }

    #[tokio::test]
    async fn get_certificate_is_fail_closed_unimplemented() {
        let err = get_certificate("host.tail1234.ts.net")
            .await
            .expect_err("must not mint a cert without an ACME RPC");
        match err {
            CertError::Unimplemented { detail } => {
                assert!(
                    detail.contains("cert"),
                    "detail should name the missing RPC: {detail}"
                );
            }
            other => panic!("expected Unimplemented, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_certificate_rejects_offtailnet_name() {
        let err = get_certificate("example.com").await.unwrap_err();
        assert!(matches!(err, CertError::NotTailnetName(_)));
    }

    #[test]
    fn cert_error_is_std_error_and_displays() {
        let e = CertError::Unimplemented { detail: "x".into() };
        let _: &dyn std::error::Error = &e;
        assert!(format!("{e}").contains("unimplemented"));
    }
}
