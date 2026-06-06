//! Hand-rolled client-side ACME ([RFC 8555]) DNS-01 engine that mints a *real* Let's Encrypt
//! certificate for a node's `*.ts.net` MagicDNS name, talking **directly** to Let's Encrypt over
//! this crate's existing ring-based HTTPS stack.
//!
//! # Why hand-rolled (ring-only is structural)
//!
//! `instant-acme` would bundle a second `hyper`/`hyper-rustls` TLS stack and defaults to
//! `aws-lc-rs` (a `CryptoProvider`-init race plus the aws-lc supply-chain/musl risk). To keep the
//! crate **ring-only**, this engine is built directly on:
//!
//! - [`ts_http_util`] — ring HTTPS via `ts_tls_util` (the same substrate [`crate::wif`] uses; see
//!   it for the `connect_tls` / `ClientExt::{get,post}` / `ResponseExt::collect_bytes` idiom — we
//!   additionally read response headers via [`http::Response::headers`]),
//! - [`ring`] — ES256 JWS signing (P-256, fixed `r||s`) and SHA-256 digests,
//! - [`rcgen`] (ring backend) — the finalize CSR.
//!
//! No `instant-acme`, no `aws-lc-rs`, no `openssl`, no second TLS stack enter the dependency graph.
//!
//! # DNS-01 flow ([RFC 8555] §7) implemented by [`issue_certificate`]
//!
//! 1. account key (ECDSA P-256), 2. fetch directory + seed a `Replay-Nonce`, 3. `newAccount`
//! (`jwk` header) → account URL (the `kid`), 4. `newOrder` → authorization + finalize URLs,
//! 5. POST-as-GET the authorization → the `dns-01` challenge `token`, 6. compute the key
//! authorization + TXT digest ([RFC 8555] §8.1/§8.4, [RFC 7638] §3) and publish it via the
//! [`crate::cert::PublishTxt`] seam (control's `set-dns`), 7. signal the challenge ready, poll the
//! authorization to `valid`, 8. finalize with a fresh-cert-key CSR, poll the order to `valid`,
//! 9. download the PEM chain and assemble a [`CertifiedKey`] via
//! [`crate::cert::certified_key_from_pem`].
//!
//! Every ACME POST body is a flattened JWS (`{"protected","payload","signature"}`,
//! `application/jose+json`); `base64url` is **always unpadded**.
//!
//! # Deployment caveat (DOA against a self-hosted control plane)
//!
//! The DNS-01 TXT publish goes through [`crate::cert::PublishTxt`], backed by the node's
//! `POST /machine/set-dns` Noise RPC. **A self-hosted control plane returns HTTP 501** for `set-dns`, so this
//! engine cannot complete a challenge there — it is built for full `tsnet` parity and works against
//! real Let's Encrypt / Pebble plus a control plane that implements `set-dns` (and owns the
//! `ts.net` zone). This mirrors the SaaS-only posture of [`crate::wif`].
//!
//! [RFC 8555]: https://www.rfc-editor.org/rfc/rfc8555.txt
//! [RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638.txt

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
};
use serde_json::Value;
use tokio_rustls::rustls::sign::CertifiedKey;
use ts_http_util::{BytesBody, ClientExt as _, HeaderMap, Response, ResponseExt, StatusCode};
use url::Url;

use crate::cert::{CertError, PublishTxt, certified_key_from_pem};

/// The production Let's Encrypt v2 ACME directory URL.
///
/// Pass this as `directory_url` to [`issue_certificate`] for real issuance; tests/staging point at
/// Pebble or the LE staging directory instead.
pub const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
    "https://acme-v02.api.letsencrypt.org/directory";

/// Maximum number of polling iterations for an authorization or order to reach `valid`.
const MAX_POLL_TRIES: usize = 30;

/// Default delay between polls when the server sends no `Retry-After` header.
const DEFAULT_POLL_DELAY: Duration = Duration::from_secs(2);

/// Per-request timeout for a single ACME HTTP round-trip (connect + send + read response).
///
/// Mirrors `set_dns`'s `SET_DNS_TIMEOUT`: each individual call to Let's Encrypt is bounded so a
/// peer that accepts the TCP/TLS connection then stalls cannot hang [`issue_certificate`] forever.
/// This bounds each HTTP call independently; it does not change the [`MAX_POLL_TRIES`] poll loop.
const ACME_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum accepted ACME response body size (256 KiB).
///
/// ACME responses are small JSON objects or a short PEM chain, so this is generous; the cap exists
/// only so a hostile or buggy directory cannot stream unbounded bytes into memory.
const ACME_MAX_RESPONSE: usize = 256 * 1024;

/// Base64url-encode `input` with **no** `=` padding (the only encoding ACME/JWS uses).
///
/// Uses the URL-safe alphabet (`-`/`_`, never `+`/`/`).
fn b64u(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// SHA-256 digest of `input` (ring), returned as raw bytes.
fn sha256(input: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, input)
        .as_ref()
        .to_vec()
}

/// An ACME account key: an ECDSA P-256 key pair used to sign every JWS-protected ACME request
/// (`alg: ES256`). The same account key identifies the ACME account across renewals, so callers
/// persist its PKCS#8 DER (from [`AcmeAccountKey::generate`]) keyed to the node identity.
pub struct AcmeAccountKey {
    /// The ring ECDSA key pair (fixed `r||s` signatures — exactly the 64-byte form ES256 needs).
    key_pair: EcdsaKeyPair,
    /// A random source for ECDSA's per-signature nonce.
    rng: SystemRandom,
}

impl AcmeAccountKey {
    /// Generate a fresh account key, returning it plus its PKCS#8 DER encoding to persist.
    ///
    /// Reload later with [`AcmeAccountKey::from_pkcs8`].
    pub fn generate() -> Result<(Self, Vec<u8>), CertError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| CertError::Acme(format!("generating account key: {e}")))?;
        let der = pkcs8.as_ref().to_vec();
        let key = Self::from_pkcs8(&der)?;
        Ok((key, der))
    }

    /// Load an account key from its PKCS#8 DER (as returned by [`AcmeAccountKey::generate`]).
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, CertError> {
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|e| CertError::Acme(format!("loading account key: {e}")))?;
        Ok(Self { key_pair, rng })
    }

    /// The uncompressed SEC1 public point (`0x04 || X || Y`, 65 bytes), split into the JWK `x`/`y`
    /// base64url-unpadded coordinates.
    fn public_xy(&self) -> (String, String) {
        let pubkey = self.key_pair.public_key().as_ref();
        // SEC1 uncompressed: byte 0 is 0x04, then 32-byte X, then 32-byte Y.
        let x = b64u(&pubkey[1..33]);
        let y = b64u(&pubkey[33..65]);
        (x, y)
    }

    /// The public JWK JSON object used in the `newAccount` `jwk` protected header.
    ///
    /// Members are in canonical (lexical) order so the same value also feeds the thumbprint.
    fn public_jwk(&self) -> Value {
        let (x, y) = self.public_xy();
        serde_json::json!({"crv": "P-256", "kty": "EC", "x": x, "y": y})
    }

    /// The canonical JWK JSON string for RFC 7638 thumbprinting: members in EXACT lexical order
    /// (`crv` < `kty` < `x` < `y`) with **zero** whitespace.
    fn canonical_jwk_json(&self) -> String {
        let (x, y) = self.public_xy();
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
    }

    /// The RFC 7638 JWK thumbprint: `base64url_nopad(SHA256(canonical_jwk_json))`.
    fn jwk_thumbprint(&self) -> String {
        b64u(&sha256(self.canonical_jwk_json().as_bytes()))
    }

    /// ES256-sign `signing_input`, returning the 64-byte fixed `r||s` signature.
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, CertError> {
        self.key_pair
            .sign(&self.rng, signing_input)
            .map(|sig| sig.as_ref().to_vec())
            .map_err(|e| CertError::Acme(format!("signing JWS: {e}")))
    }
}

/// The JWS protected-header key material: either the full public `jwk` (for `newAccount`) or the
/// account `kid` URL (for every other request).
enum JwsKey<'a> {
    /// Embed the public JWK (used only by `newAccount`).
    Jwk,
    /// Reference the existing account by its URL (`kid`).
    Kid(&'a str),
}

/// Build a flattened JWS JSON string for an ACME request ([RFC 8555] §6.2).
///
/// `payload` is the already-serialized request body bytes (empty for POST-as-GET). The signing
/// input is `b64u(protected) + "." + b64u(payload)`, signed with ES256.
fn build_jws(
    account_key: &AcmeAccountKey,
    url: &str,
    nonce: &str,
    key: JwsKey<'_>,
    payload: &[u8],
) -> Result<String, CertError> {
    let mut protected = serde_json::Map::new();
    protected.insert("alg".into(), Value::from("ES256"));
    protected.insert("nonce".into(), Value::from(nonce));
    protected.insert("url".into(), Value::from(url));
    match key {
        JwsKey::Jwk => {
            protected.insert("jwk".into(), account_key.public_jwk());
        }
        JwsKey::Kid(kid) => {
            protected.insert("kid".into(), Value::from(kid));
        }
    }
    let protected_json = Value::Object(protected).to_string();
    let protected_b64 = b64u(protected_json.as_bytes());
    let payload_b64 = b64u(payload);

    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signature = account_key.sign(signing_input.as_bytes())?;
    let signature_b64 = b64u(&signature);

    Ok(serde_json::json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64,
    })
    .to_string())
}

/// The DNS-01 challenge material for one authorization: the full TXT record name and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Dns01Challenge {
    /// The full record name to publish: `_acme-challenge.<name>`.
    record_name: String,
    /// The base64url-unpadded TXT value (always 43 chars): `b64u(SHA256(key_authorization))`.
    txt_value: String,
}

/// Compute the DNS-01 record name + TXT value for `name` from the challenge `token` and the
/// account key's thumbprint ([RFC 8555] §8.1/§8.4).
///
/// Pure (no I/O), so it is unit-testable without a network. The key authorization is
/// `"{token}.{thumbprint}"` and the published TXT value is `b64u_nopad(SHA256(key_authorization))`.
fn prepare_dns01(name: &str, token: &str, account_key: &AcmeAccountKey) -> Dns01Challenge {
    let thumbprint = account_key.jwk_thumbprint();
    let key_authorization = format!("{token}.{thumbprint}");
    let txt_value = b64u(&sha256(key_authorization.as_bytes()));
    Dns01Challenge {
        record_name: format!("_acme-challenge.{name}"),
        txt_value,
    }
}

/// A response reduced to the parts the ACME flow needs: status, headers, and the collected body.
///
/// `ts_http_util` does not re-export its `hyper::body::Incoming` response-body type, so instead of
/// naming it, [`consume`] immediately collects each response into this owned struct (using only the
/// re-exported [`StatusCode`]/[`HeaderMap`] and the [`ResponseExt`] trait). Everything downstream
/// works on `Parts`, keeping `hyper`/`http` out of this crate's direct dependencies.
struct Parts {
    /// The HTTP status line.
    status: StatusCode,
    /// The response headers (read for `Replay-Nonce` / `Location` / `Retry-After`).
    headers: HeaderMap,
    /// The fully collected response body.
    body: bytes::Bytes,
}

impl Parts {
    /// Read a single header as an owned `String`, if present and valid UTF-8.
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }
}

/// Reduce a client response to its status + headers + collected body ([`Parts`]).
///
/// Generic over the response body so this crate never names `ts_http_util`'s `Incoming` type; the
/// bound is exactly what [`ResponseExt::collect_bytes`] requires.
async fn consume<B>(resp: Response<B>) -> Result<Parts, CertError>
where
    Response<B>: ResponseExt,
{
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.collect_bytes().await.map_err(http_err)?;
    check_body_size(body.len())?;
    Ok(Parts {
        status,
        headers,
        body,
    })
}

/// Reject a response body larger than [`ACME_MAX_RESPONSE`].
///
/// Pure (no I/O): factored out of [`consume`] so the cap is unit-testable without a server.
fn check_body_size(len: usize) -> Result<(), CertError> {
    if len > ACME_MAX_RESPONSE {
        return Err(CertError::Acme("ACME response body too large".into()));
    }
    Ok(())
}

/// Run a single ACME HTTP round-trip future, bounded by [`ACME_HTTP_TIMEOUT`].
///
/// Wraps the whole connect + send + read-response future so a peer that accepts the connection
/// then stalls is abandoned instead of hanging forever. Hard to unit-test without a stalling
/// server, so it is exercised only indirectly via the real ACME flow.
async fn with_timeout<F>(round_trip: F) -> Result<Parts, CertError>
where
    F: core::future::Future<Output = Result<Parts, CertError>>,
{
    match tokio::time::timeout(ACME_HTTP_TIMEOUT, round_trip).await {
        Ok(result) => result,
        Err(_elapsed) => Err(CertError::Acme("ACME HTTP request timed out".into())),
    }
}

/// Connect, POST `jws` (Content-Type `application/jose+json`) to `url`, and return its [`Parts`].
///
/// The whole connect + POST + response read is bounded by [`ACME_HTTP_TIMEOUT`].
async fn acme_post(url: &Url, jws: String) -> Result<Parts, CertError> {
    with_timeout(async {
        let client = ts_http_util::http1::connect_tls::<BytesBody>(url)
            .await
            .map_err(http_err)?;
        let headers = [(
            ts_http_util::HeaderName::from_static("content-type"),
            ts_http_util::HeaderValue::from_static("application/jose+json"),
        )];
        let resp = client
            .post(url, headers, bytes::Bytes::from(jws).into())
            .await
            .map_err(http_err)?;
        consume(resp).await
    })
    .await
}

/// Connect and GET `url`, returning its [`Parts`].
///
/// The directory fetch and the `newNonce` seed are plain GETs; the whole connect + GET + response
/// read is bounded by [`ACME_HTTP_TIMEOUT`], same as [`acme_post`].
async fn acme_get(url: &Url) -> Result<Parts, CertError> {
    with_timeout(async {
        let client = ts_http_util::http1::connect_tls::<BytesBody>(url)
            .await
            .map_err(http_err)?;
        let resp = client.get(url, []).await.map_err(http_err)?;
        consume(resp).await
    })
    .await
}

/// Map a `ts_http_util::Error` into [`CertError::Io`].
fn http_err(error: ts_http_util::Error) -> CertError {
    CertError::Io(std::io::Error::other(error.to_string()))
}

/// The directory endpoint URLs we use from `GET <directory>`.
struct Directory {
    /// `newNonce` endpoint (seed/refresh the anti-replay nonce).
    new_nonce: Url,
    /// `newAccount` endpoint.
    new_account: Url,
    /// `newOrder` endpoint.
    new_order: Url,
}

/// Parse the three endpoint URLs we need from a directory JSON body.
fn parse_directory(body: &[u8]) -> Result<Directory, CertError> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|e| CertError::Acme(format!("directory JSON: {e}")))?;
    let field = |k: &str| -> Result<Url, CertError> {
        let s = v
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| CertError::Acme(format!("directory missing {k}")))?;
        Url::parse(s).map_err(|e| CertError::Acme(format!("directory {k} URL: {e}")))
    };
    Ok(Directory {
        new_nonce: field("newNonce")?,
        new_account: field("newAccount")?,
        new_order: field("newOrder")?,
    })
}

/// A live ACME session: the directory, the account `kid`, and the current `Replay-Nonce`.
struct Session {
    /// The directory endpoints.
    directory: Directory,
    /// The account URL returned by `newAccount`, used as the `kid` for every later request.
    kid: String,
    /// The most recent `Replay-Nonce` (each response refreshes it).
    nonce: String,
}

impl Session {
    /// Take the current nonce, leaving an empty placeholder (it must be refreshed per response).
    fn take_nonce(&mut self) -> String {
        std::mem::take(&mut self.nonce)
    }
}

/// POST `payload` to `url` with a `kid`-keyed JWS, refreshing the session nonce from the response.
///
/// `payload` is empty (`&[]`) for POST-as-GET. Returns the collected [`Parts`] (status + headers +
/// body).
async fn signed_post(
    session: &mut Session,
    account_key: &AcmeAccountKey,
    url: &Url,
    payload: &[u8],
) -> Result<Parts, CertError> {
    let nonce = session.take_nonce();
    let jws = build_jws(
        account_key,
        url.as_str(),
        &nonce,
        JwsKey::Kid(&session.kid),
        payload,
    )?;
    let parts = acme_post(url, jws).await?;
    if let Some(n) = parts.header("replay-nonce") {
        session.nonce = n;
    }
    Ok(parts)
}

/// Issue a real certificate for `name` via the full RFC 8555 DNS-01 flow against `directory_url`.
///
/// `account_key` is the persisted ACME account key (see [`AcmeAccountKey::generate`]); `publisher`
/// is the control-plane seam ([`PublishTxt`]) that publishes the `_acme-challenge.<name>` TXT.
/// Returns the assembled [`CertifiedKey`] (leaf+chain from Let's Encrypt plus a freshly generated
/// cert key) ready to serve, or [`CertError`] on any ACME/HTTP failure (fail-closed: no cert is
/// returned unless the order reached `valid` and the chain assembled).
///
/// `directory_url` lets tests point at Pebble/staging; production is
/// [`LETS_ENCRYPT_PRODUCTION_DIRECTORY`].
pub async fn issue_certificate(
    name: &str,
    directory_url: &Url,
    account_key: &AcmeAccountKey,
    publisher: &(impl PublishTxt + Sync),
) -> Result<CertifiedKey, CertError> {
    // 1. Directory.
    let dir = acme_get(directory_url).await?;
    let directory = parse_directory(&dir.body)?;

    // 2. Seed a nonce (HEAD-equivalent GET to newNonce; the body is discarded).
    let nonce = acme_get(&directory.new_nonce)
        .await?
        .header("replay-nonce")
        .ok_or_else(|| CertError::Acme("newNonce response missing Replay-Nonce".into()))?;

    // 3. newAccount (jwk header) → the account URL is the kid for all later requests.
    let account_payload = serde_json::json!({"termsOfServiceAgreed": true}).to_string();
    let account_jws = build_jws(
        account_key,
        directory.new_account.as_str(),
        &nonce,
        JwsKey::Jwk,
        account_payload.as_bytes(),
    )?;
    let account_resp = acme_post(&directory.new_account, account_jws).await?;
    if !account_resp.status.is_success() {
        return Err(status_err("newAccount", &account_resp));
    }
    let kid = account_resp
        .header("location")
        .ok_or_else(|| CertError::Acme("newAccount response missing Location (kid)".into()))?;
    let nonce = account_resp
        .header("replay-nonce")
        .ok_or_else(|| CertError::Acme("newAccount response missing Replay-Nonce".into()))?;

    let mut session = Session {
        directory,
        kid,
        nonce,
    };

    // 4. newOrder.
    let order_payload =
        serde_json::json!({"identifiers": [{"type": "dns", "value": name}]}).to_string();
    let new_order_url = session.directory.new_order.clone();
    let order_resp = signed_post(
        &mut session,
        account_key,
        &new_order_url,
        order_payload.as_bytes(),
    )
    .await?;
    if !order_resp.status.is_success() {
        return Err(status_err("newOrder", &order_resp));
    }
    let order_url = order_resp
        .header("location")
        .ok_or_else(|| CertError::Acme("newOrder response missing Location (order URL)".into()))?;
    let order: Value = serde_json::from_slice(&order_resp.body)
        .map_err(|e| CertError::Acme(format!("newOrder JSON: {e}")))?;
    let authorizations = order
        .get("authorizations")
        .and_then(Value::as_array)
        .ok_or_else(|| CertError::Acme("order missing authorizations".into()))?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let finalize_url = order
        .get("finalize")
        .and_then(Value::as_str)
        .ok_or_else(|| CertError::Acme("order missing finalize URL".into()))?
        .to_string();

    // 5–7. For each authorization: find dns-01, publish TXT, signal ready, poll to valid.
    for authz_url in &authorizations {
        let authz_url = Url::parse(authz_url)
            .map_err(|e| CertError::Acme(format!("authorization URL: {e}")))?;
        let authz_resp = signed_post(&mut session, account_key, &authz_url, &[]).await?;
        if !authz_resp.status.is_success() {
            return Err(status_err("authorization", &authz_resp));
        }
        let authz: Value = serde_json::from_slice(&authz_resp.body)
            .map_err(|e| CertError::Acme(format!("authorization JSON: {e}")))?;
        let challenge = authz
            .get("challenges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|c| c.get("type").and_then(Value::as_str) == Some("dns-01"))
            .ok_or_else(|| CertError::Acme("authorization has no dns-01 challenge".into()))?;
        let token = challenge
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| CertError::Acme("dns-01 challenge missing token".into()))?;
        let challenge_url = challenge
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| CertError::Acme("dns-01 challenge missing url".into()))?
            .to_string();

        // 6. key authorization + TXT digest, published via control's set-dns.
        let dns01 = prepare_dns01(name, token, account_key);
        publisher
            .publish_txt(&dns01.record_name, &dns01.txt_value)
            .await?;

        // 7. Signal ready: POST the challenge URL with payload `{}`.
        let challenge_url = Url::parse(&challenge_url)
            .map_err(|e| CertError::Acme(format!("challenge URL: {e}")))?;
        let ready_resp = signed_post(&mut session, account_key, &challenge_url, b"{}").await?;
        if !ready_resp.status.is_success() {
            return Err(status_err("challenge-ready", &ready_resp));
        }

        // Poll the authorization to valid.
        poll_status(&mut session, account_key, &authz_url, "authorization").await?;
    }

    // 8. Finalize: fresh cert key + CSR for `name`.
    let cert_params = rcgen::CertificateParams::new(vec![name.to_string()])
        .map_err(|e| CertError::Acme(format!("building CSR params: {e}")))?;
    let cert_key = rcgen::KeyPair::generate()
        .map_err(|e| CertError::Acme(format!("generating cert key: {e}")))?;
    let csr = cert_params
        .serialize_request(&cert_key)
        .map_err(|e| CertError::Acme(format!("serializing CSR: {e}")))?;
    let csr_b64 = b64u(csr.der());
    let cert_key_pem = cert_key.serialize_pem();

    // Known simplification: we finalize as soon as the last authorization is `valid` without first
    // polling the order to `ready` (RFC 8555 §7.4 `pending`→`ready`). Most CAs (LE, Pebble) accept
    // this; a strict CA that enforces the `ready` state could 403 here — a future hardening.
    let finalize_url =
        Url::parse(&finalize_url).map_err(|e| CertError::Acme(format!("finalize URL: {e}")))?;
    let finalize_payload = serde_json::json!({"csr": csr_b64}).to_string();
    let finalize_resp = signed_post(
        &mut session,
        account_key,
        &finalize_url,
        finalize_payload.as_bytes(),
    )
    .await?;
    if !finalize_resp.status.is_success() {
        return Err(status_err("finalize", &finalize_resp));
    }

    // 9. Poll the order to valid → it then carries the certificate URL.
    let order_url =
        Url::parse(&order_url).map_err(|e| CertError::Acme(format!("order URL: {e}")))?;
    let final_order = poll_status(&mut session, account_key, &order_url, "order").await?;
    let certificate_url = final_order
        .get("certificate")
        .and_then(Value::as_str)
        .ok_or_else(|| CertError::Acme("valid order missing certificate URL".into()))?
        .to_string();

    // 10. Download the PEM chain (POST-as-GET) and assemble the CertifiedKey.
    let certificate_url = Url::parse(&certificate_url)
        .map_err(|e| CertError::Acme(format!("certificate URL: {e}")))?;
    let cert_resp = signed_post(&mut session, account_key, &certificate_url, &[]).await?;
    if !cert_resp.status.is_success() {
        return Err(status_err("certificate-download", &cert_resp));
    }

    certified_key_from_pem(&cert_resp.body, cert_key_pem.as_bytes())
}

/// Poll `url` (POST-as-GET) until its JSON `status` is `valid`, returning the final JSON.
///
/// Errors on `status: "invalid"`, on exhausting [`MAX_POLL_TRIES`], or on HTTP failure. Honors a
/// `Retry-After` header (seconds) when present, else waits [`DEFAULT_POLL_DELAY`]. `what` names the
/// resource for error messages.
async fn poll_status(
    session: &mut Session,
    account_key: &AcmeAccountKey,
    url: &Url,
    what: &str,
) -> Result<Value, CertError> {
    for _ in 0..MAX_POLL_TRIES {
        let resp = signed_post(session, account_key, url, &[]).await?;
        if !resp.status.is_success() {
            return Err(status_err(what, &resp));
        }
        let retry_after = resp
            .header("retry-after")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        let value: Value = serde_json::from_slice(&resp.body)
            .map_err(|e| CertError::Acme(format!("{what} poll JSON: {e}")))?;
        match value.get("status").and_then(Value::as_str) {
            Some("valid") => return Ok(value),
            Some("invalid") => {
                return Err(CertError::Acme(format!("{what} became invalid: {value}")));
            }
            _ => {
                tokio::time::sleep(retry_after.unwrap_or(DEFAULT_POLL_DELAY)).await;
            }
        }
    }
    Err(CertError::Acme(format!(
        "{what} did not reach valid within {MAX_POLL_TRIES} polls"
    )))
}

/// Wrap a non-2xx response's status + truncated body preview in [`CertError::Acme`].
fn status_err(what: &str, parts: &Parts) -> CertError {
    let mut preview = parts.body.to_vec();
    preview.truncate(512);
    let preview = String::from_utf8_lossy(&preview);
    CertError::Acme(format!(
        "{what} returned status {}: {preview}",
        parts.status
    ))
}

#[cfg(all(test, feature = "acme"))]
mod tests {
    use std::pin::Pin;

    use super::*;

    /// A `PublishTxt` that records the (name, value) pairs it is asked to publish.
    struct MockPublisher {
        records: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl MockPublisher {
        fn new() -> Self {
            Self {
                records: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl PublishTxt for MockPublisher {
        fn publish_txt(
            &self,
            name: &str,
            value: &str,
        ) -> Pin<Box<dyn core::future::Future<Output = Result<(), CertError>> + Send + '_>>
        {
            self.records
                .lock()
                .unwrap()
                .push((name.to_string(), value.to_string()));
            Box::pin(async { Ok(()) })
        }
    }

    /// A freshly generated account key round-trips through PKCS#8 and yields valid JWK coords.
    fn fresh_key() -> AcmeAccountKey {
        let (_key, der) = AcmeAccountKey::generate().expect("generate");
        AcmeAccountKey::from_pkcs8(&der).expect("reload")
    }

    #[test]
    fn base64url_is_unpadded_and_url_safe() {
        // 0xFB 0xFF 0xFE encodes to "+/+ " in standard base64 → "-_-" region in URL-safe.
        let encoded = b64u(&[0xfb, 0xff, 0xbf]);
        assert!(!encoded.contains('='), "must have no padding: {encoded}");
        assert!(!encoded.contains('+'), "must be URL-safe: {encoded}");
        assert!(!encoded.contains('/'), "must be URL-safe: {encoded}");
        // This specific input exercises both URL-safe substitutions.
        assert_eq!(encoded, "-_-_");
    }

    #[test]
    fn canonical_jwk_is_lexical_and_whitespace_free() {
        let key = fresh_key();
        let canonical = key.canonical_jwk_json();
        // Exact member order crv<kty<x<y, no whitespace.
        assert!(canonical.starts_with(r#"{"crv":"P-256","kty":"EC","x":""#));
        assert!(canonical.ends_with(r#""}"#));
        assert!(!canonical.contains(' '));
        assert!(!canonical.contains('\n'));
        // Order check: crv index < kty index < x index < y index.
        let i_crv = canonical.find("crv").unwrap();
        let i_kty = canonical.find("kty").unwrap();
        let i_x = canonical.find(r#""x":"#).unwrap();
        let i_y = canonical.find(r#""y":"#).unwrap();
        assert!(i_crv < i_kty && i_kty < i_x && i_x < i_y);
    }

    #[test]
    fn thumbprint_is_43_char_unpadded_b64url() {
        let key = fresh_key();
        let tp = key.jwk_thumbprint();
        // SHA-256 → 32 bytes → 43 unpadded base64url chars.
        assert_eq!(tp.len(), 43, "thumbprint: {tp}");
        assert!(!tp.contains('='));
        assert!(!tp.contains('+') && !tp.contains('/'));
    }

    #[test]
    fn jwk_x_y_are_32_byte_coords() {
        let key = fresh_key();
        let (x, y) = key.public_xy();
        // 32 raw bytes → base64url-unpadded → 43 chars.
        assert_eq!(x.len(), 43, "x: {x}");
        assert_eq!(y.len(), 43, "y: {y}");
        assert!(!x.contains('=') && !y.contains('='));
    }

    #[test]
    fn prepare_dns01_key_authorization_and_txt_value() {
        let key = fresh_key();
        let dns01 = prepare_dns01("host.tail1234.ts.net", "tok-EN-FACE-123", &key);
        assert_eq!(dns01.record_name, "_acme-challenge.host.tail1234.ts.net");
        // txt_value = b64u(SHA256("tok.thumbprint")); always 43 unpadded base64url chars.
        assert_eq!(dns01.txt_value.len(), 43, "txt: {}", dns01.txt_value);
        assert!(!dns01.txt_value.contains('='));
        // Recompute independently to prove the exact key-authorization formula.
        let key_auth = format!("tok-EN-FACE-123.{}", key.jwk_thumbprint());
        let expected = b64u(&sha256(key_auth.as_bytes()));
        assert_eq!(dns01.txt_value, expected);
    }

    #[test]
    fn jws_has_three_fields_and_verifiable_signature() {
        let key = fresh_key();
        let jws = build_jws(
            &key,
            "https://acme.example/new-order",
            "abc-nonce",
            JwsKey::Kid("https://acme.example/acct/1"),
            b"{}",
        )
        .expect("build jws");
        let v: Value = serde_json::from_str(&jws).unwrap();
        let protected_b64 = v.get("protected").and_then(Value::as_str).unwrap();
        let payload_b64 = v.get("payload").and_then(Value::as_str).unwrap();
        let signature_b64 = v.get("signature").and_then(Value::as_str).unwrap();

        // Protected header decodes to the expected JSON with kid (not jwk).
        let protected_json = URL_SAFE_NO_PAD.decode(protected_b64).unwrap();
        let header: Value = serde_json::from_slice(&protected_json).unwrap();
        assert_eq!(header.get("alg").and_then(Value::as_str), Some("ES256"));
        assert_eq!(
            header.get("nonce").and_then(Value::as_str),
            Some("abc-nonce")
        );
        assert_eq!(
            header.get("url").and_then(Value::as_str),
            Some("https://acme.example/new-order")
        );
        assert_eq!(
            header.get("kid").and_then(Value::as_str),
            Some("https://acme.example/acct/1")
        );
        assert!(header.get("jwk").is_none());

        // Signature is the 64-byte fixed r||s form.
        let sig = URL_SAFE_NO_PAD.decode(signature_b64).unwrap();
        assert_eq!(sig.len(), 64, "ES256 fixed signature is 64 bytes");

        // Round-trip verify with ring to prove the signing input is correct.
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let peer = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            key.key_pair.public_key().as_ref(),
        );
        peer.verify(signing_input.as_bytes(), &sig)
            .expect("signature must verify");
    }

    #[test]
    fn newaccount_jws_uses_jwk_not_kid() {
        let key = fresh_key();
        let jws = build_jws(
            &key,
            "https://acme.example/new-acct",
            "n1",
            JwsKey::Jwk,
            br#"{"termsOfServiceAgreed":true}"#,
        )
        .expect("build jws");
        let v: Value = serde_json::from_str(&jws).unwrap();
        let protected_b64 = v.get("protected").and_then(Value::as_str).unwrap();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected_b64).unwrap()).unwrap();
        let jwk = header.get("jwk").expect("newAccount uses jwk header");
        assert_eq!(jwk.get("crv").and_then(Value::as_str), Some("P-256"));
        assert_eq!(jwk.get("kty").and_then(Value::as_str), Some("EC"));
        assert!(header.get("kid").is_none());
    }

    #[tokio::test]
    async fn mock_publisher_records_the_challenge() {
        let key = fresh_key();
        let publisher = MockPublisher::new();
        let dns01 = prepare_dns01("host.tail1234.ts.net", "the-token", &key);
        publisher
            .publish_txt(&dns01.record_name, &dns01.txt_value)
            .await
            .unwrap();
        let records = publisher.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "_acme-challenge.host.tail1234.ts.net");
        assert_eq!(records[0].1, dns01.txt_value);
    }

    #[test]
    fn check_body_size_caps_at_max() {
        // At or below the cap is accepted; one byte over is rejected.
        check_body_size(0).expect("empty body ok");
        check_body_size(ACME_MAX_RESPONSE).expect("exactly at cap ok");
        let err = check_body_size(ACME_MAX_RESPONSE + 1).expect_err("over cap rejected");
        assert!(matches!(err, CertError::Acme(m) if m.contains("too large")));
    }

    #[test]
    fn generate_then_from_pkcs8_round_trips() {
        // `generate()` returns the key + its PKCS#8 DER to persist; reloading that exact DER must
        // succeed and yield identical JWK coordinates and thumbprint (the persistence contract).
        let (k1, der) = AcmeAccountKey::generate().expect("generate");
        let k2 = AcmeAccountKey::from_pkcs8(&der).expect("reload persisted DER");
        assert_eq!(k1.canonical_jwk_json(), k2.canonical_jwk_json());
        assert_eq!(k1.jwk_thumbprint(), k2.jwk_thumbprint());
        // Reloading the same DER a second time is also stable.
        let k3 = AcmeAccountKey::from_pkcs8(&der).expect("reload again");
        assert_eq!(k2.jwk_thumbprint(), k3.jwk_thumbprint());
    }

    /// A fixed, committed ECDSA P-256 account key (PKCS#8 DER), so the JWK/thumbprint below are
    /// reproducible byte-for-byte. Generated once with `AcmeAccountKey::generate()` and pinned.
    const FIXED_PKCS8_HEX: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420ed5474cb46ef01de295207f9f91ae8a8cca0b9d9a3182c9355328442f2ecc55aa144034200041e9b8e358664e3b6a4bb56c2301efcfdca4120fcef7574ed1bf1287882adb32b5a2f5597fd7eb76e3dd8f3744e7f4c1dde4c7384a27acc78d53fbcd16f4bc062";

    fn fixed_key() -> AcmeAccountKey {
        let der: Vec<u8> = (0..FIXED_PKCS8_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&FIXED_PKCS8_HEX[i..i + 2], 16).unwrap())
            .collect();
        AcmeAccountKey::from_pkcs8(&der).expect("load fixed key")
    }

    /// RFC 7638 known-answer test (self-pinned-literal variant). The existing thumbprint tests use
    /// freshly generated keys, so they only check shape/self-consistency — a member-reorder or a
    /// base64/digest drift in the live `newAccount` JWK would pass them yet break against Let's
    /// Encrypt. This pins the EXACT canonical bytes and an independently computed thumbprint for a
    /// FIXED key, so any reorder / whitespace / base64 / digest change breaks the test.
    ///
    /// (We pin our own canonical literal rather than the RFC's published RSA example, which is not a
    /// P-256 vector; the literal is the engine's `canonical_jwk_json()` output captured once and
    /// hardcoded here. The thumbprint RHS is recomputed via `ring` directly, independent of the
    /// function under test's internal path.)
    #[test]
    fn jwk_thumbprint_known_answer_rfc7638() {
        let key = fixed_key();

        // 1. The canonical JWK string is byte-for-byte the RFC 7638 §3 form: members in lexical
        //    order (crv < kty < x < y) with ZERO whitespace. This is the regression guard the
        //    fresh-key tests lack — a reorder here silently breaks LE.
        const EXPECTED_CANONICAL: &str = r#"{"crv":"P-256","kty":"EC","x":"HpuONYZk47aku1bCMB78_cpBIPzvdXTtG_EoeIKtsys","y":"Wi9Vl_1-t2492PN0Tn9MHd5Mc4Siesx41T-80W9LwGI"}"#;
        assert_eq!(
            key.canonical_jwk_json(),
            EXPECTED_CANONICAL,
            "canonical JWK must be byte-identical (member order + no whitespace)"
        );

        // 2. Independent-path thumbprint: SHA-256 of THAT exact literal, base64url-unpadded, computed
        //    here with `ring::digest` + `URL_SAFE_NO_PAD` directly (not via `jwk_thumbprint`'s code).
        let expected_thumbprint = URL_SAFE_NO_PAD.encode(
            ring::digest::digest(&ring::digest::SHA256, EXPECTED_CANONICAL.as_bytes()).as_ref(),
        );
        assert_eq!(
            key.jwk_thumbprint(),
            expected_thumbprint,
            "thumbprint must equal base64url_nopad(SHA256(canonical JWK))"
        );
        // Also pin the literal known-answer constant (captured once from the fixed key).
        assert_eq!(
            key.jwk_thumbprint(),
            "8NZV0yNd0fBPk--o9T4HK4Koyyb9cv_I9w5TfuDqiqo"
        );
    }

    /// The `jwk` embedded in the `newAccount` JWS header (`public_jwk`) must serialize with the SAME
    /// member order as `canonical_jwk_json` (the thumbprint input). If the header JWK and the
    /// thumbprint input disagree on order, Let's Encrypt computes a different thumbprint than we
    /// publish in the DNS-01 TXT and silently fails — exactly the silent-LE-failure the auditor
    /// flagged. Pinning byte-equality of the header JWK to the canonical string guards it.
    #[test]
    fn public_jwk_header_member_order_matches_canonical() {
        let key = fixed_key();
        // `serde_json::Value` (a `BTreeMap`) serializes object keys in sorted order, which for these
        // members (crv < kty < x < y) is the canonical order — assert it byte-for-byte.
        let header_jwk = serde_json::to_string(&key.public_jwk()).unwrap();
        assert_eq!(
            header_jwk,
            key.canonical_jwk_json(),
            "newAccount header JWK must be byte-identical-ordered to the thumbprint input"
        );
    }

    // ----- Offline ACME state-machine coverage -----
    //
    // SEAM STATUS: the full order→authz→challenge→poll→finalize flow lives in `issue_certificate`,
    // which is HARD-WIRED to `ts_http_util` via the free functions `acme_get` / `acme_post`
    // (`ts_http_util::http1::connect_tls`). There is NO injectable HTTP-client/transport trait — the
    // flow takes only `(name, directory_url, account_key, publisher)`, so a mock transport cannot be
    // substituted without refactoring production code to add a seam. Per the task scope, we do NOT
    // add that seam in this pass. The only network-driving end-to-end coverage remains the env-gated
    // Pebble integration test elsewhere.
    //
    // What IS testable offline without a refactor are the pure helpers the state machine is built
    // from: directory parsing, the nonce-carry of `Session`, header extraction (the `Replay-Nonce` /
    // `Location` / `Retry-After` reads), and error formatting. We cover those below. (The JWS/JWK/
    // DNS-01 builders and the response-size cap are already covered by the tests above.)

    /// `parse_directory` extracts exactly the three endpoint URLs the flow uses, ignoring extras.
    #[test]
    fn parse_directory_extracts_three_endpoints() {
        let body = br#"{
            "newNonce": "https://acme.example/acme/new-nonce",
            "newAccount": "https://acme.example/acme/new-acct",
            "newOrder": "https://acme.example/acme/new-order",
            "revokeCert": "https://acme.example/acme/revoke-cert",
            "meta": {"termsOfService": "https://acme.example/tos"}
        }"#;
        let dir = match parse_directory(body) {
            Ok(d) => d,
            Err(e) => panic!("valid directory must parse: {e:?}"),
        };
        assert_eq!(
            dir.new_nonce.as_str(),
            "https://acme.example/acme/new-nonce"
        );
        assert_eq!(
            dir.new_account.as_str(),
            "https://acme.example/acme/new-acct"
        );
        assert_eq!(
            dir.new_order.as_str(),
            "https://acme.example/acme/new-order"
        );
    }

    /// A directory missing a required endpoint is a fail-closed `CertError::Acme`, naming the field.
    #[test]
    fn parse_directory_missing_field_errors() {
        // No `newOrder`.
        let body = br#"{
            "newNonce": "https://acme.example/acme/new-nonce",
            "newAccount": "https://acme.example/acme/new-acct"
        }"#;
        let err = match parse_directory(body) {
            Err(e) => e,
            Ok(_) => panic!("missing newOrder must error"),
        };
        assert!(
            matches!(err, CertError::Acme(m) if m.contains("newOrder")),
            "error must name the missing field"
        );
    }

    /// A directory whose endpoint is not a valid URL is rejected (fail-closed).
    #[test]
    fn parse_directory_bad_url_errors() {
        let body = br#"{
            "newNonce": "not a url",
            "newAccount": "https://acme.example/acme/new-acct",
            "newOrder": "https://acme.example/acme/new-order"
        }"#;
        let err = match parse_directory(body) {
            Err(e) => e,
            Ok(_) => panic!("invalid URL must error"),
        };
        assert!(matches!(err, CertError::Acme(_)), "got {err:?}");
    }

    /// Non-JSON directory body is rejected.
    #[test]
    fn parse_directory_non_json_errors() {
        let err = match parse_directory(b"<html>not json</html>") {
            Err(e) => e,
            Ok(_) => panic!("non-JSON must error"),
        };
        assert!(
            matches!(err, CertError::Acme(m) if m.contains("directory JSON")),
            "error must indicate a directory JSON parse failure"
        );
    }

    /// `Parts::header` reads a present header case-insensitively (the flow reads `replay-nonce`,
    /// `location`, `retry-after`) and returns `None` for an absent one — the exact nonce/Location
    /// extraction the state machine depends on.
    #[test]
    fn parts_header_read_and_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ts_http_util::HeaderName::from_static("replay-nonce"),
            ts_http_util::HeaderValue::from_static("nonce-abc-123"),
        );
        headers.insert(
            ts_http_util::HeaderName::from_static("location"),
            ts_http_util::HeaderValue::from_static("https://acme.example/acct/42"),
        );
        let parts = Parts {
            status: StatusCode::OK,
            headers,
            body: bytes::Bytes::new(),
        };
        // `http::HeaderMap` lookup is case-insensitive — assert the flow can read these regardless of
        // the case the server used.
        assert_eq!(
            parts.header("Replay-Nonce").as_deref(),
            Some("nonce-abc-123")
        );
        assert_eq!(
            parts.header("replay-nonce").as_deref(),
            Some("nonce-abc-123")
        );
        assert_eq!(
            parts.header("location").as_deref(),
            Some("https://acme.example/acct/42")
        );
        assert_eq!(parts.header("retry-after"), None);
    }

    /// `Session::take_nonce` returns the current nonce and leaves an empty placeholder, so a request
    /// can never silently reuse a spent nonce (anti-replay): each `signed_post` takes then a fresh
    /// response must refill it.
    #[test]
    fn session_take_nonce_consumes_then_empties() {
        let directory = match parse_directory(
            br#"{
                "newNonce": "https://acme.example/n",
                "newAccount": "https://acme.example/a",
                "newOrder": "https://acme.example/o"
            }"#,
        ) {
            Ok(d) => d,
            Err(e) => panic!("directory must parse: {e:?}"),
        };
        let mut session = Session {
            directory,
            kid: "https://acme.example/acct/1".to_string(),
            nonce: "first-nonce".to_string(),
        };
        assert_eq!(session.take_nonce(), "first-nonce");
        // Now spent — a second take yields empty until a response refills `session.nonce`.
        assert_eq!(session.take_nonce(), "");
        session.nonce = "second-nonce".to_string();
        assert_eq!(session.take_nonce(), "second-nonce");
    }

    /// `status_err` (the error path used when the server returns a non-2xx, e.g. an order that goes
    /// `invalid` or any 4xx/5xx) names the failing step, includes the status, and previews the body.
    #[test]
    fn status_err_includes_step_status_and_body_preview() {
        let parts = Parts {
            status: StatusCode::FORBIDDEN,
            headers: HeaderMap::new(),
            body: bytes::Bytes::from_static(
                br#"{"type":"urn:ietf:params:acme:error:unauthorized"}"#,
            ),
        };
        let err = status_err("newOrder", &parts);
        let CertError::Acme(msg) = err else {
            panic!("expected CertError::Acme, got {err:?}");
        };
        assert!(msg.contains("newOrder"), "names the step: {msg}");
        assert!(msg.contains("403"), "includes the status: {msg}");
        assert!(msg.contains("unauthorized"), "previews the body: {msg}");
    }

    /// `status_err` truncates a huge body to the 512-byte preview rather than echoing it whole.
    #[test]
    fn status_err_truncates_long_body() {
        let big = vec![b'x'; 4096];
        let parts = Parts {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            headers: HeaderMap::new(),
            body: bytes::Bytes::from(big),
        };
        let CertError::Acme(msg) = status_err("finalize", &parts) else {
            panic!("expected CertError::Acme");
        };
        // The preview is capped at 512 bytes; the whole message stays bounded well under the body.
        assert!(
            msg.len() < 700,
            "preview must be truncated, got {} chars",
            msg.len()
        );
        assert!(msg.contains("finalize") && msg.contains("500"));
    }
}
