//! Live-CA integration test for the RFC 8555 ACME (DNS-01) engine in
//! [`ts_control::acme`]. It proves the fork's hand-rolled, ring-only ACME engine
//! issues a *real* certificate end-to-end against a real ACME server
//! ([Pebble](https://github.com/letsencrypt/pebble)) — directory fetch,
//! `newAccount`, `newOrder`, dns-01 challenge publish, finalize, and chain
//! download — not just that it compiles.
//!
//! # How to run
//!
//! Bring up Pebble + challtestsrv, export the printed vars, then run the test:
//!
//! ```text
//! ./scripts/pebble-up.sh
//!
//! export TS_RS_TEST_PEBBLE=1
//! export TS_RS_ACME_DIRECTORY="https://localhost:14000/dir"
//! export TS_RS_EXTRA_CA_PEM="$PWD/scripts/.pebble/pebble-root.pem"
//! export TS_RS_CHALLTESTSRV_URL="http://localhost:8055"
//!
//! TS_RS_EXPERIMENT=this_is_unstable_software \
//!   cargo test -p geiserx_ts_control --features acme --test acme_pebble -- --nocapture
//!
//! ./scripts/pebble-down.sh
//! ```
//!
//! Without `TS_RS_TEST_PEBBLE` (and the CA/directory env) the test is a no-op
//! early-return, so it stays green in CI where no ACME server is running.
//!
//! `TS_RS_EXTRA_CA_PEM` MUST be set before the first TLS connection in the
//! process: `ts_tls_util` reads it once into a `LazyLock` root store. The test
//! sets it from env (or programmatically) at the very top, before any
//! `issue_certificate` call.
//!
//! # RFC-compliance gaps this test surfaced (now fixed)
//!
//! Bringing this up against Pebble exposed three RFC bugs that have since been
//! fixed in the shared HTTP stack (`ts_http_util`, used by the engine — not in
//! this test's scope) so the engine now completes issuance end-to-end:
//!
//! 1. **Absolute-form request target.** The h1 client wrote the request line in
//!    absolute-form (`POST https://host/path HTTP/1.1`) instead of origin-form
//!    (`POST /path HTTP/1.1`). A compliant ACME server compares the JWS `url`
//!    header against `scheme + Host + RequestURI`; the doubled URL made every
//!    signed POST fail with `malformed: JWS header parameter 'url' incorrect`.
//!    Fixed: the client now sends origin-form path+query.
//! 2. **Missing `User-Agent`.** RFC 8555 §6.1 requires one; Pebble >= v2.10.0
//!    (and Boulder / Let's Encrypt) 400 requests that omit it. Fixed: the client
//!    now sends a `User-Agent`.
//! 3. **Host header dropped the non-default port.** The `Host` header omitted a
//!    non-443 port, so Pebble advertised unreachable `:443` resource URLs. Fixed
//!    in `ts_http_util::host_header`.
//!
//! # DNS-01 publishing gotcha this test must handle (in this test's scope)
//!
//! challtestsrv keys its TXT challenge store by the RAW host string with NO FQDN
//! normalization (unlike its A/AAAA/CNAME records), while Pebble's DNS query name
//! always arrives fully-qualified WITH a trailing dot. The publisher must POST
//! the record name WITH a trailing dot or the lookup misses and Pebble reports
//! "No TXT records found" despite a 200 from /set-txt. See
//! `ChalltestsrvPublisher::post_set_txt` for the full root-cause note.

#![cfg(feature = "acme")]

use std::{
    io::{Read, Write},
    net::TcpStream,
    pin::Pin,
};

use ts_control::{
    CertError, PublishTxt,
    acme::{AcmeAccountKey, issue_certificate},
    certified_key_from_pem,
};

/// challtestsrv management API URL (its `POST /set-txt` publishes the dns-01 TXT
/// that Pebble then resolves). Overridable via `TS_RS_CHALLTESTSRV_URL`.
const DEFAULT_CHALLTESTSRV_URL: &str = "http://localhost:8055";

/// Default Pebble ACME directory (overridable via `TS_RS_ACME_DIRECTORY`).
const DEFAULT_DIRECTORY_URL: &str = "https://localhost:14000/dir";

/// A [`PublishTxt`] that publishes the dns-01 TXT record into `pebble-challtestsrv`
/// via its management HTTP API (`POST {mgmt}/set-txt`, body `{"host","value"}`),
/// so Pebble's resolver (pointed at challtestsrv) can answer the challenge query.
///
/// Hand-rolled plain-HTTP POST over `std::net::TcpStream` (the mgmt API is HTTP,
/// not HTTPS) to keep the dependency graph clean — this repo is ring-only and
/// avoids pulling a second HTTP/TLS client into the test.
struct ChalltestsrvPublisher {
    /// `host:port` of the challtestsrv management API (parsed from its URL).
    authority: String,
}

impl ChalltestsrvPublisher {
    /// Build from the mgmt base URL (e.g. `http://localhost:8055`), extracting
    /// the `host:port` authority for the raw TCP POST.
    fn new(mgmt_url: &str) -> Self {
        let authority = mgmt_url
            .trim_end_matches('/')
            .strip_prefix("http://")
            .unwrap_or(mgmt_url)
            .to_string();
        Self { authority }
    }

    /// Blocking, zero-dep HTTP/1.1 `POST /set-txt` to challtestsrv. Returns the
    /// status line so the caller can assert a 2xx.
    fn post_set_txt(&self, record_name: &str, value: &str) -> Result<String, String> {
        // CRITICAL host-key normalization (root cause of the historical "No TXT
        // records found" validation failure):
        //
        // Unlike A/AAAA/CNAME records — which challtestsrv FQDN-normalizes on both
        // store AND lookup (`dns.Fqdn(host)` in mockdns.go) — its TXT challenge
        // store does NOT. `AddDNSOneChallenge`/`GetDNSOneChallenge`
        // (challtestsrv@v1.3.2 dnsone.go) key the in-memory `dnsOne` map by the
        // RAW host string, with no normalization on either side.
        //
        // On the DNS *query* side, the question name (`q.Name`) always arrives in
        // fully-qualified form WITH a trailing dot (e.g.
        // `_acme-challenge.host.example.com.`) — that is what `txtAnswers` looks
        // up. So if we POST the record WITHOUT a trailing dot, challtestsrv stores
        // it under `...com` while Pebble queries `...com.`, the map lookup misses,
        // and Pebble reports "No TXT records found" even though /set-txt returned
        // 200 and logged "Added DNS-01 TXT challenge". Appending the trailing dot
        // here makes the stored key match the FQDN-form query name exactly.
        let record_name = if record_name.ends_with('.') {
            record_name.to_string()
        } else {
            format!("{record_name}.")
        };
        // JSON body: challtestsrv decodes `host` + `value` (Go default lowercase
        // keys).
        let body = format!(
            "{{\"host\":\"{}\",\"value\":\"{}\"}}",
            json_escape(&record_name),
            json_escape(value)
        );
        let request = format!(
            "POST /set-txt HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            host = self.authority,
            len = body.len(),
            body = body,
        );

        let mut stream = TcpStream::connect(&self.authority)
            .map_err(|e| format!("connect {} failed: {e}", self.authority))?;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("write set-txt failed: {e}"))?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| format!("read set-txt response failed: {e}"))?;

        let status_line = response.lines().next().unwrap_or("").to_string();
        if !status_line.contains(" 200") {
            return Err(format!(
                "challtestsrv /set-txt did not return 200: status={status_line:?} full={response:?}"
            ));
        }
        Ok(status_line)
    }
}

impl PublishTxt for ChalltestsrvPublisher {
    fn publish_txt(
        &self,
        name: &str,
        value: &str,
    ) -> Pin<Box<dyn core::future::Future<Output = Result<(), CertError>> + Send + '_>> {
        // The mgmt POST is blocking std I/O; run it on the blocking pool so we
        // never stall the tokio reactor that drives the ACME HTTP round-trips.
        let name = name.to_string();
        let value = value.to_string();
        let authority = self.authority.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                ChalltestsrvPublisher { authority }.post_set_txt(&name, &value)
            })
            .await
            .map_err(|e| CertError::Acme(format!("publish_txt join error: {e}")))?
            .map_err(CertError::Acme)?;
            Ok(())
        })
    }
}

/// Minimal JSON string escaping for the two values we emit (dns name + base64url
/// TXT). Neither contains control chars; we only need `"` and `\` escaped.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Truthy env check: set + not `0`/`false`/empty.
fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some(v) if !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pebble_issues_a_real_certificate() {
    // --- Runtime guard: no-op unless explicitly enabled with a CA + directory ---
    if !env_truthy("TS_RS_TEST_PEBBLE") {
        eprintln!(
            "skipping pebble integration test: set TS_RS_TEST_PEBBLE=1 (and run \
             scripts/pebble-up.sh) to enable"
        );
        return;
    }
    let ca_pem = std::env::var("TS_RS_EXTRA_CA_PEM").unwrap_or_default();
    if ca_pem.is_empty() {
        eprintln!(
            "skipping pebble integration test: TS_RS_EXTRA_CA_PEM unset (point it at \
             scripts/.pebble/pebble-root.pem)"
        );
        return;
    }
    // ts_tls_util reads TS_RS_EXTRA_CA_PEM once into a LazyLock root store, so it
    // must already be set before the first TLS connect. It is read from env here
    // and re-asserted so the failure mode (untrusted Pebble CA) is obvious.
    assert!(
        std::path::Path::new(&ca_pem).is_file(),
        "TS_RS_EXTRA_CA_PEM={ca_pem} does not point at a readable file; run \
         scripts/pebble-up.sh first"
    );

    let directory =
        std::env::var("TS_RS_ACME_DIRECTORY").unwrap_or_else(|_| DEFAULT_DIRECTORY_URL.to_string());
    let directory_url = url::Url::parse(&directory)
        .unwrap_or_else(|e| panic!("invalid TS_RS_ACME_DIRECTORY {directory:?}: {e}"));

    let challtestsrv_url = std::env::var("TS_RS_CHALLTESTSRV_URL")
        .unwrap_or_else(|_| DEFAULT_CHALLTESTSRV_URL.to_string());
    let publisher = ChalltestsrvPublisher::new(&challtestsrv_url);

    // Fail fast with a clear message if challtestsrv's mgmt API is unreachable.
    publisher
        .post_set_txt("_acme-challenge.preflight.example.com", "preflight-probe")
        .unwrap_or_else(|e| {
            panic!(
                "challtestsrv mgmt API at {challtestsrv_url} unreachable (run \
                 scripts/pebble-up.sh): {e}"
            )
        });

    // --- Account key (generate + PKCS#8 round-trip, the documented usage) ---
    let (_account_key, der) =
        AcmeAccountKey::generate().expect("generating ACME account key failed");
    let account_key =
        AcmeAccountKey::from_pkcs8(&der).expect("reloading ACME account key from PKCS#8 failed");

    // Pebble issues for any name by default. Use a stable DNS name.
    let name = "test-host.example.com";

    // --- The whole integration: real RFC 8555 issuance against Pebble ---
    // `issue_certificate` returns an `IssuedCert`: the ready-to-serve `CertifiedKey` PLUS the raw
    // chain + leaf-key PEMs (the `Device::cert_pair` / `tnet cert` path) from the SAME issuance.
    let issued = issue_certificate(name, &directory_url, &account_key, &publisher)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "issue_certificate({name}) against Pebble at {directory} FAILED: {e}\n\
                 (directory reachable + CA trusted? account/order/challenge/finalize step?)"
            )
        });
    let certified = &issued.certified;

    // --- Assert we got a usable, non-empty cert chain ---
    assert!(
        !certified.cert.is_empty(),
        "issued CertifiedKey has an EMPTY certificate chain"
    );
    // Pebble returns leaf + at least one intermediate.
    eprintln!(
        "PASS: Pebble issued a certificate for {name}: chain has {} cert(s), \
         leaf DER {} bytes",
        certified.cert.len(),
        certified.cert[0].as_ref().len()
    );
    // The leaf DER must be a plausible X.509 (non-trivial size, SEQUENCE tag).
    assert!(
        certified.cert[0].as_ref().len() > 200,
        "leaf certificate DER suspiciously small: {} bytes",
        certified.cert[0].as_ref().len()
    );
    assert_eq!(
        certified.cert[0].as_ref()[0],
        0x30,
        "leaf certificate DER does not start with an ASN.1 SEQUENCE tag (0x30)"
    );

    // --- Assert the PEM pair (the `Device::cert_pair` surface) is well-formed and matched ---
    // The chain PEM parses to at least one certificate.
    let chain_certs: Vec<_> = rustls_pemfile::certs(&mut issued.cert_chain_pem.as_bytes())
        .collect::<Result<_, _>>()
        .expect("cert_chain_pem must parse as PEM certificates");
    assert!(
        !chain_certs.is_empty(),
        "cert_chain_pem parsed to ZERO certificates"
    );
    // The leaf-key PEM parses as a private key (the no-key-export-needed invariant: the PEM is
    // already in hand). NOTE: never print `issued.key_pem` — it is private key material.
    let parsed_key = rustls_pemfile::private_key(&mut issued.key_pem.as_bytes())
        .expect("key_pem must parse as PEM")
        .expect("key_pem must contain a private key");
    assert!(
        !parsed_key.secret_der().is_empty(),
        "parsed leaf private key DER is empty"
    );
    // The pair MUST match: `certified_key_from_pem` rebuilds a `CertifiedKey` from these exact PEMs
    // and runs `keys_match()` internally, so a mismatch fails here (reuses the production verifier —
    // never weakened). This is the same check `IssuedCert::certified` already passed.
    certified_key_from_pem(issued.cert_chain_pem.as_bytes(), issued.key_pem.as_bytes())
        .expect("the returned cert_chain_pem + key_pem must form a matched CertifiedKey");
    eprintln!("PASS: cert_pair PEMs are well-formed and the key matches the leaf");
}
