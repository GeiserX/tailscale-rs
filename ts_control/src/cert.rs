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
//! **Deployment caveat (why this is currently stubbed, not built):** a
//! self-hosted control plane target may return **HTTP 501
//! NotImplemented** for `/machine/set-dns`. A client-side ACME engine therefore
//! cannot complete a DNS-01 challenge against such a control plane — the issuance path
//! is non-functional until the control plane grows `set-dns` + a real backing DNS zone
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

/// The control-plane seam the ACME DNS-01 engine depends on: publish (and later clear) the
/// `_acme-challenge.<name>` TXT record in the `ts.net` zone control owns, by sending the node's
/// `POST /machine/set-dns` Noise RPC.
///
/// Implemented by the runtime's control-RPC layer (which holds the Noise transport + node keys);
/// the ACME engine ([`crate::acme`], `acme` feature) calls it without depending on the actor types.
/// `name` is the FULL record name (`_acme-challenge.<host>.<tailnet>.ts.net`), `value` the
/// base64url-unpadded DNS-01 digest. Returning `Err` fails the issuance closed (no cert).
#[cfg(feature = "acme")]
pub trait PublishTxt {
    /// Publish the DNS-01 challenge TXT record via `POST /machine/set-dns`. Resolves once control
    /// has accepted the record (HTTP 200 / empty `SetDnsResponse`).
    fn publish_txt(
        &self,
        name: &str,
        value: &str,
    ) -> std::pin::Pin<Box<dyn core::future::Future<Output = Result<(), CertError>> + Send + '_>>;
}

/// Map a [`crate::tokio::SetDnsError`] into [`CertError::Acme`].
///
/// The DNS-01 publish is the one I/O step of issuance the ACME engine reaches through the
/// [`PublishTxt`] seam; fold the set-dns RPC's own error vocabulary into the cert error surface
/// (its `Display` carries the coarse cause, e.g. the self-hosted control plane 501 `Internal(Http)`).
#[cfg(feature = "acme")]
impl From<crate::tokio::SetDnsError> for CertError {
    fn from(error: crate::tokio::SetDnsError) -> Self {
        CertError::Acme(format!("set-dns publish failed: {error}"))
    }
}

/// A [`PublishTxt`] backed by the node's `POST /machine/set-dns` Noise RPC.
///
/// Borrows the node's [`crate::Config`] (control URL + transport) and [`ts_keys::NodeState`] (node
/// keys for the Noise channel) and publishes the `_acme-challenge.<name>` `TXT` record through
/// [`crate::tokio::set_dns`]. SaaS-only: a self-hosted control plane typically 501s on `set-dns`, surfaced as
/// [`CertError::Acme`].
#[cfg(feature = "acme")]
pub struct SetDnsPublisher<'a> {
    /// Control config (server URL + transport) the set-dns RPC dials.
    config: &'a crate::Config,
    /// The node's key state, providing the node/machine keys for the Noise channel.
    node_keystate: &'a ts_keys::NodeState,
}

#[cfg(feature = "acme")]
impl<'a> SetDnsPublisher<'a> {
    /// Build a publisher borrowing the node's control `config` and `node_keystate`.
    pub fn new(config: &'a crate::Config, node_keystate: &'a ts_keys::NodeState) -> Self {
        Self {
            config,
            node_keystate,
        }
    }
}

#[cfg(feature = "acme")]
impl PublishTxt for SetDnsPublisher<'_> {
    fn publish_txt(
        &self,
        name: &str,
        value: &str,
    ) -> std::pin::Pin<Box<dyn core::future::Future<Output = Result<(), CertError>> + Send + '_>>
    {
        let name = name.to_string();
        let value = value.to_string();
        Box::pin(async move {
            crate::tokio::set_dns(self.config, self.node_keystate, &name, "TXT", &value)
                .await
                .map_err(CertError::from)
        })
    }
}

/// Issue a real certificate for `name` via the client-side ACME DNS-01 engine, publishing the
/// challenge TXT through the node's `POST /machine/set-dns` RPC, returning the full
/// [`IssuedCert`](crate::acme::IssuedCert) (the [`CertifiedKey`] **plus** the chain + leaf-key PEMs).
///
/// This is the single issuance entry point: [`issue_certificate_via_setdns`] (which needs only the
/// [`CertifiedKey`] for the `get_certificate` / `ListenTLS` path) delegates here and drops the PEMs,
/// while a caller needing the on-disk `.crt`/`.key` pair (the daemon's `tnet cert`, Go's
/// `LocalClient.CertPair`) keeps them — one ACME order, two consumers.
///
/// `account_key` is the ACME account identity (persist its PKCS#8 DER across renewals — see the
/// runtime caller); `directory_url` selects the ACME CA (production is
/// [`crate::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY`]). Rejects non-tailnet names up front (anti-leak)
/// before any network I/O. SaaS-only: against a self-hosted control plane the set-dns publish typically 501s, surfaced as
/// [`CertError::Acme`]. Fail-closed: returns an [`IssuedCert`](crate::acme::IssuedCert) only when the
/// LE order reached `valid` and the chain assembled. The leaf private key
/// ([`IssuedCert::key_pem`](crate::acme::IssuedCert::key_pem)) is never logged.
#[cfg(feature = "acme")]
pub async fn issue_cert_pair_via_setdns(
    config: &crate::Config,
    node_keystate: &ts_keys::NodeState,
    name: &str,
    account_key: &crate::acme::AcmeAccountKey,
    directory_url: &url::Url,
) -> Result<crate::acme::IssuedCert, CertError> {
    if !is_tailnet_name(name) {
        return Err(CertError::NotTailnetName(name.to_string()));
    }
    let publisher = SetDnsPublisher::new(config, node_keystate);
    crate::acme::issue_certificate(name, directory_url, account_key, &publisher).await
}

/// Issue a real certificate for `name` via the client-side ACME DNS-01 engine, returning just the
/// ready-to-serve [`CertifiedKey`] (the `get_certificate` / `ListenTLS` path).
///
/// Thin wrapper over [`issue_cert_pair_via_setdns`] that discards the raw PEMs — one issuance, the
/// caller here just doesn't need the on-disk pair. See that function for the full contract
/// (anti-leak name check, SaaS-only set-dns, fail-closed).
#[cfg(feature = "acme")]
pub async fn issue_certificate_via_setdns(
    config: &crate::Config,
    node_keystate: &ts_keys::NodeState,
    name: &str,
    account_key: &crate::acme::AcmeAccountKey,
    directory_url: &url::Url,
) -> Result<CertifiedKey, CertError> {
    issue_cert_pair_via_setdns(config, node_keystate, name, account_key, directory_url)
        .await
        .map(|issued| issued.certified)
}

/// Names exactly what this fork is missing to issue a real cert, surfaced
/// verbatim in [`CertError::Unimplemented`] so the gap is self-documenting at
/// runtime. There is no control `cert/<domain>` RPC in real Tailscale — the node
/// is the ACME client and only needs control to publish the DNS-01 TXT via
/// `POST /machine/set-dns` (which a self-hosted control plane typically 501s). See the module docs.
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

    // No client-side ACME engine and no set-dns RPC exist in this fork, and a
    // self-hosted control target typically 501s on set-dns. Do NOT self-sign.
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

    /// `issue_certificate_via_setdns` rejects a non-tailnet name with [`CertError::NotTailnetName`]
    /// BEFORE any network I/O (the `is_tailnet_name` guard fires first). This is the only path
    /// reachable without a live control plane / ACME CA, and it proves the anti-leak guard.
    #[cfg(feature = "acme")]
    #[tokio::test]
    async fn issue_via_setdns_rejects_offtailnet_before_network() {
        let config = crate::Config::default();
        let keystate = ts_keys::NodeState::generate();
        let (account_key, _der) = crate::acme::AcmeAccountKey::generate().expect("generate");
        let directory = url::Url::parse(crate::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY).unwrap();

        let err = issue_certificate_via_setdns(
            &config,
            &keystate,
            "example.com",
            &account_key,
            &directory,
        )
        .await
        .expect_err("must refuse a non-tailnet name without touching the network");
        assert!(matches!(err, CertError::NotTailnetName(_)));
    }

    /// `SetDnsPublisher` implements [`PublishTxt`] (compile-level assertion).
    #[cfg(feature = "acme")]
    #[test]
    fn set_dns_publisher_is_publish_txt() {
        fn assert_publish_txt<T: PublishTxt>() {}
        assert_publish_txt::<SetDnsPublisher<'_>>();
    }

    /// Offline round-trip of the [`crate::acme::IssuedCert`] PEM contract — the data
    /// `Device::cert_pair` surfaces — WITHOUT a network/ACME server. `issue_certificate` ends by
    /// feeding a chain PEM + a leaf-key PEM into [`certified_key_from_pem`] and keeping those same
    /// two PEMs on the `IssuedCert`; this proves that exact assembly with a known cert+key pair
    /// (generated here with `rcgen`, as the live engine does), so the plumbing is covered even when
    /// the Pebble integration test cannot run.
    ///
    /// Asserts: the leaf-key PEM parses as a private key (`rustls_pemfile::private_key` → `Some`),
    /// the cert PEM parses as ≥1 certificate, and the matched pair builds a `CertifiedKey` (which
    /// runs `keys_match()` internally — the key-matches-leaf verification is exercised, NOT skipped).
    #[cfg(feature = "acme")]
    #[test]
    fn issued_cert_pem_pair_round_trips_and_key_matches_leaf() {
        // A self-signed cert + its key — the same `(chain_pem, key_pem)` shape `issue_certificate`
        // holds at its final `certified_key_from_pem` call (there the chain is LE's; here it is a
        // single self-signed leaf — identical for the parse/match contract under test).
        let cert = rcgen::generate_simple_self_signed(vec!["host.tail1234.ts.net".into()])
            .expect("generate self-signed cert");
        let cert_chain_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        // The leaf-key PEM parses as a private key (the "PEM already in hand, no opaque-key export"
        // fact the whole change rests on). Never logged.
        let parsed_key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .expect("key_pem must parse as PEM")
            .expect("key_pem must contain a private key");
        assert!(
            !parsed_key.secret_der().is_empty(),
            "parsed leaf private key DER is empty"
        );

        // The cert PEM parses to ≥1 certificate.
        let chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_chain_pem.as_bytes())
                .collect::<Result<_, _>>()
                .expect("cert_chain_pem must parse as PEM certificates");
        assert!(
            !chain.is_empty(),
            "cert_chain_pem parsed to ZERO certificates"
        );

        // The matched pair assembles — `certified_key_from_pem` runs `keys_match()` internally, so
        // this is the key-matches-leaf check (the production verifier, reused, never weakened).
        let ck = certified_key_from_pem(cert_chain_pem.as_bytes(), key_pem.as_bytes())
            .expect("matched cert_chain_pem + key_pem must build a CertifiedKey");
        assert!(
            !ck.cert.is_empty(),
            "assembled CertifiedKey has an empty chain"
        );
    }

    /// The key-matches-leaf verification is real: a cert paired with a *different* key's PEM must be
    /// REJECTED by [`certified_key_from_pem`]. This guards against any future weakening of the
    /// matched-pair guarantee `IssuedCert` (and `Device::cert_pair`) depend on.
    #[cfg(feature = "acme")]
    #[test]
    fn certified_key_from_pem_rejects_mismatched_key() {
        let cert_a = rcgen::generate_simple_self_signed(vec!["host.tail1234.ts.net".into()])
            .expect("generate cert A");
        let cert_b = rcgen::generate_simple_self_signed(vec!["other.tail1234.ts.net".into()])
            .expect("generate cert B");
        // Cert A's chain with cert B's (non-matching) private key.
        let err = certified_key_from_pem(
            cert_a.cert.pem().as_bytes(),
            cert_b.key_pair.serialize_pem().as_bytes(),
        )
        .expect_err("a cert paired with the wrong key must be rejected (keys_match)");
        assert!(
            matches!(err, CertError::Rustls(_)),
            "mismatch must surface as a rustls error, got {err:?}"
        );
    }
}
