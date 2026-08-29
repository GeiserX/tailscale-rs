use alloc::string::String;

use ts_control_serde::{C2NVIPServicesResponse, PingType};
use ts_http_util::{BytesBody, ClientExt, Http2, Request};
use url::Url;

use crate::StateUpdate;

/// Path requested in HTTP GET via a Control-to-Node (C2N) [`ts_control_serde::PingRequest`] to
/// invoke the C2N echo handler.
const C2N_PATH_ECHO: &str = "/echo";
/// Path requested in HTTP GET via a C2N [`ts_control_serde::PingRequest`] to fetch the VIP services
/// this node hosts (Go `c2n` `GET /vip-services`). Answered with a JSON
/// [`C2NVIPServicesResponse`].
const C2N_PATH_VIP_SERVICES: &str = "/vip-services";
/// HTTP 400 Bad Request response sent for all unimplemented C2N methods/paths.
const C2N_PATH_UNKNOWN: &str = "HTTP/1.1 400 Bad Request\r\n\r\nunknown c2n path";
/// The start of an HTTP/1.1 200 response with no headers, just missing the body. Intended for use
/// with C2N echo responses, which can append the request body.
const C2N_RESPONSE_ECHO_PREAMBLE: &str = "HTTP/1.1 200 OK\r\n\r\n";

/// Build the full HTTP/1.1 response to a c2n `GET /vip-services` request from a node's config: a
/// `200 OK` with a JSON [`C2NVIPServicesResponse`] body listing the validated hosted VIP services
/// and their hash (which matches the `HostInfo.ServicesHash` the node advertises). Factored out as a
/// pure function so the response shape is unit-testable without a live control connection.
fn build_vip_services_response(config: &crate::Config) -> String {
    let vip_services = config.advertised_vip_services();
    let services_hash = crate::services_hash(&vip_services);
    let response = C2NVIPServicesResponse {
        vip_services,
        services_hash,
    };
    // Serialization of an owned VIP-service list never fails; fall back to an empty list on the
    // impossible error rather than panicking in the network loop.
    let body = serde_json::to_string(&response).unwrap_or_else(|_| {
        tracing::error!("serializing c2n /vip-services response");
        String::from(r#"{"VIPServices":[],"ServicesHash":""}"#)
    });
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}")
}

/// Route a parsed C2N request to the full HTTP/1.1 response this node sends back to control.
///
/// This mirrors Go's `handleC2N` (`ipn/ipnlocal/c2n.go`): an exact path match selects a handler,
/// and anything with no registered handler falls through to
/// `http.Error(w, "unknown c2n path", http.StatusBadRequest)`. Only the paths listed below are
/// registered here; the fallthrough is the contract for everything else, so it is asserted by test
/// rather than left implicit.
///
/// ## Debug paths this node deliberately does not serve
///
/// Upstream gained three c2n debug endpoints that this tree has no subsystem to answer, so they
/// take the 400 fallthrough like any other unregistered path:
///
/// - `GET|POST /debug/netmap` (Go `handleC2NDebugNetMap`, `ipn/ipnlocal/c2n.go`) marshals the
///   client's whole `netmap.NetworkMap` — returned as an opaque `json.RawMessage` inside
///   `tailcfg.C2NDebugNetmapResponse` precisely because that struct is Go-internal and unstable —
///   and, for a `POST`, re-derives a *candidate* netmap from a supplied `MapResponse` via
///   `controlclient.NetmapFromMapResponseForDebug`. There is no `NetworkMap` aggregate in this
///   tree at all: the netmap arrives as a stream of [`StateUpdate`] deltas and is accumulated by
///   the runtime's peer tracker, which this responder cannot see. Answering with an approximation
///   would be worse than the 400 — control unmarshals the body into Go's `netmap.NetworkMap`, so
///   every field we could not fill would silently read back as a zero value rather than as
///   "unknown".
/// - `/debug/health` (Go `handleC2NDebugHealth`, `ipn/ipnlocal/c2n.go`) marshals
///   `health.Tracker.CurrentState()`. This fork has no health subsystem — see the `LockedOut`
///   discussion in `ts_runtime::control_runner`, which logs where Go would raise a health warning.
/// - `/debug/tka/log` (Go `handleC2NDebugTKALog`, `feature/tailnetlock/tailnetlock.go`) serves the
///   Tailnet Lock AUM chain. The chain exists here (`ts_tka`), but it is held by
///   `ts_runtime::tka_sync`, and `ts_control` deliberately does not depend on `ts_tka` — this crate
///   carries only the wire-level [`crate::TkaStatus`] head/disabled signal.
///
/// The declared [`CapabilityVersion::CURRENT`](ts_capabilityversion::CapabilityVersion::CURRENT) is
/// held below the versions that promise these handlers (127, 128 and 138) so the declaration and
/// the responder agree; see that constant's documentation before raising it.
fn build_c2n_response(request: &Request<String>, config: &crate::Config) -> String {
    let c2n_request_path = request.uri().path();
    match c2n_request_path {
        C2N_PATH_ECHO => {
            tracing::trace!(c2n_request_path, "handling c2n echo");
            format!("{}{}", C2N_RESPONSE_ECHO_PREAMBLE, request.body())
        }
        C2N_PATH_VIP_SERVICES => {
            tracing::trace!(c2n_request_path, "handling c2n vip-services fetch");
            build_vip_services_response(config)
        }
        _ => {
            tracing::debug!(c2n_request_path, "no handler for c2n path");
            C2N_PATH_UNKNOWN.to_string()
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, Eq, PartialEq)]
pub enum PingError {
    #[error("HTTP error")]
    Http,
    #[error("URL parsing error")]
    Url,
    #[error("Ping request with invalid format (missing payload)")]
    MessageFormat,
    #[error("Network error")]
    NetworkError,
}

impl From<ts_http_util::Error> for PingError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "HTTP error handling ping");

        if crate::http_error_is_recoverable(error) {
            PingError::NetworkError
        } else {
            PingError::Http
        }
    }
}

impl From<url::ParseError> for PingError {
    fn from(error: url::ParseError) -> Self {
        tracing::error!(%error, "Error parsing URL");
        PingError::Url
    }
}

/// Parses the payload of a Control-to-Node (C2N) [`ts_control_serde::PingRequest`] as an HTTP/1.1
/// request, or returns an error.
fn parse_c2n_ping(payload: &str) -> Result<Request<String>, PingError> {
    let req = ts_http_util::http1::parse_request(payload.as_bytes())?;
    tracing::trace!(
        payload_len = req.body().len(),
        payload = req.body(),
        "extracted payload from ping request body"
    );
    Ok(req)
}

/// Handles [`ts_control_serde::PingRequest`]s from the control plane to this Tailscale node.
/// Handles Control-to-Node (C2N) `GET /echo` (echo back the body) and `GET /vip-services` (report
/// the VIP services this node hosts, from `config`); non-C2N requests are skipped with a warning,
/// while C2N requests for an unhandled path return a "400 Bad Request" to the control plane.
///
/// ## C2N Mechanism
///
/// The C2N mechanism provides a way for the control plane to query a Tailscale node about their
/// local state, or request changes to the node state. A lot of debugging and metrics-related
/// features are implemented via this mechanism, along with a number of knobs such as changing the
/// netfilter implementation or forcing a logs flush in the Tailscale Go client.
///
/// Ping requests of type [`PingType::C2N`] contain an entire HTTP/1.1 request as their payload.
/// The method and path of this request determine which handler is invoked; for example, in the
/// Tailscale Go client, "GET /echo ..." invokes the C2N echo handler, while
/// "POST /netfilter-kind ..." changes the netfilter implementation the client uses (on Linux only).
/// The handler must return a full HTTP response to the request containing the requested data and/or
/// status - for example, "HTTP/1.1 200 OK <body>" or "HTTP/1.1 400 Bad Request".
///
/// `tailscale-rs` returns an HTTP 400 Bad Request status with an error message to the control
/// plane for any unimplemented C2N methods/paths.
pub async fn handle_ping(
    state: &StateUpdate,
    control_url: &Url,
    http2_client: &Http2<BytesBody>,
    config: &crate::Config,
) -> Result<(), PingError> {
    let Some(ping_request) = &state.ping else {
        return Ok(());
    };

    tracing::trace!(request = ?ping_request, "handling ping request");
    for typ in &ping_request.types {
        if typ != &PingType::C2N {
            tracing::warn!(ping_type = ?typ, "ignoring unsupported ping type");
            continue;
        }

        let ping_request_body = ping_request.payload.as_ref().ok_or_else(|| {
            tracing::error!("message format error in ping request: missing payload");
            PingError::MessageFormat
        })?;
        let c2n_request = match parse_c2n_ping(ping_request_body) {
            Ok(c2n_request) => {
                tracing::trace!(?c2n_request, "parsed c2n ping");
                c2n_request
            }
            Err(_) => {
                tracing::warn!(?ping_request_body, "ignoring malformed c2n ping");
                continue;
            }
        };

        let c2n_response = build_c2n_response(&c2n_request, config);

        let ping_response_url = control_url.join(ping_request.url.path())?;
        tracing::trace!(%ping_response_url, ?c2n_response, "posting c2n response");
        let response = http2_client
            .post(&ping_response_url, None, c2n_response.into())
            .await?;
        if !response.status().is_success() {
            tracing::error!(status = %response.status(), "responding to c2n ping");
        } else {
            tracing::debug!("c2n response sent");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    /// Parse a raw HTTP/1.1 request exactly as it arrives inside a C2N
    /// [`ts_control_serde::PingRequest`] payload, so the routing tests exercise the same parse the
    /// network path uses rather than a hand-built [`Request`].
    fn c2n_request(raw: &str) -> Request<String> {
        parse_c2n_ping(raw).expect("control sends a well-formed HTTP/1.1 c2n request")
    }

    /// The three c2n debug endpoints upstream added above this node's declared capability version
    /// must answer with Go's exact fallthrough: `handleC2N` (`ipn/ipnlocal/c2n.go`) ends with
    /// `http.Error(w, "unknown c2n path", http.StatusBadRequest)` for any path with no registered
    /// handler, and none of these three is registered here.
    ///
    /// - `/debug/netmap` — Go `handleC2NDebugNetMap` (capver 127); needs a `netmap.NetworkMap`
    ///   aggregate this tree does not have.
    /// - `/debug/health` — Go `handleC2NDebugHealth` (capver 128); needs a `health.Tracker`
    ///   this fork does not have.
    /// - `/debug/tka/log` — Go `handleC2NDebugTKALog`
    ///   (`feature/tailnetlock/tailnetlock.go`, capver 138); needs the AUM chain, which lives in
    ///   `ts_runtime`, not in this crate.
    ///
    /// The query-string case pins that the match is on the path alone, so
    /// `/debug/tka/log?limit=60` (the form Go's handler reads its `limit` from) cannot accidentally
    /// route somewhere else.
    #[test]
    fn c2n_debug_endpoints_answer_unknown_path() {
        let config = crate::Config::default();
        for raw in [
            "GET /debug/netmap HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "POST /debug/netmap HTTP/1.1\r\nHost: c2n\r\nContent-Length: 2\r\n\r\n{}",
            "GET /debug/health HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /debug/tka HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /debug/tka/log HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /debug/tka/log?limit=60 HTTP/1.1\r\nHost: c2n\r\n\r\n",
        ] {
            let resp = build_c2n_response(&c2n_request(raw), &config);
            assert_eq!(
                resp, "HTTP/1.1 400 Bad Request\r\n\r\nunknown c2n path",
                "{raw} must take the unknown-c2n-path fallthrough"
            );
        }
    }

    /// The 400 fallthrough is the contract for *every* unregistered path, not just the three debug
    /// endpoints — including other handlers Go registers that this node does not implement. Losing
    /// it (e.g. by routing a prefix) would make control believe an unimplemented feature works.
    #[test]
    fn c2n_unknown_path_still_answers_400() {
        let config = crate::Config::default();
        for raw in [
            "GET /debug/goroutines HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /debug/metrics HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "POST /netfilter-kind HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /not-a-real-path HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: c2n\r\n\r\n",
        ] {
            let resp = build_c2n_response(&c2n_request(raw), &config);
            assert_eq!(
                resp, "HTTP/1.1 400 Bad Request\r\n\r\nunknown c2n path",
                "{raw} must take the unknown-c2n-path fallthrough"
            );
        }
    }

    /// The two paths this node *does* serve still route through the same dispatcher, so the
    /// fallthrough above is proven to be a real routing decision and not a blanket 400.
    /// Go's `handleC2NEcho` writes the request body back verbatim with a bare 200.
    #[test]
    fn c2n_echo_and_vip_services_still_route() {
        let config = crate::Config {
            advertise_services: alloc::vec!["svc:web".to_string()],
            ..Default::default()
        };

        let echo = build_c2n_response(
            &c2n_request("GET /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"),
            &config,
        );
        assert_eq!(echo, "HTTP/1.1 200 OK\r\n\r\nhello");

        let vip = build_c2n_response(
            &c2n_request("GET /vip-services HTTP/1.1\r\nHost: c2n\r\n\r\n"),
            &config,
        );
        let (status, json) = parse_response(&vip);
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(json["VIPServices"][0]["Name"].as_str().unwrap(), "svc:web");
    }

    /// Split the HTTP/1.1 response built by [`build_vip_services_response`] into its status line and
    /// JSON body for assertions.
    fn parse_response(resp: &str) -> (&str, serde_json::Value) {
        let (head, body) = resp.split_once("\r\n\r\n").expect("response has a body");
        let status = head.lines().next().unwrap();
        let json: serde_json::Value = serde_json::from_str(body).expect("body is JSON");
        (status, json)
    }

    #[test]
    fn vip_services_response_lists_configured_services() {
        let config = crate::Config {
            advertise_services: alloc::vec!["svc:samba".to_string(), "svc:web".to_string()],
            ..Default::default()
        };
        let resp = build_vip_services_response(&config);
        let (status, json) = parse_response(&resp);

        assert_eq!(status, "HTTP/1.1 200 OK");
        let names: alloc::vec::Vec<&str> = json["VIPServices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["Name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"svc:samba"));
        assert!(names.contains(&"svc:web"));
        // The response hash must match the standalone hash over the same advertised set.
        let expected = crate::services_hash(&config.advertised_vip_services());
        assert_eq!(json["ServicesHash"].as_str().unwrap(), expected);
        assert!(!expected.is_empty());
    }

    #[test]
    fn vip_services_response_empty_when_none_configured() {
        let config = crate::Config::default();
        let resp = build_vip_services_response(&config);
        let (status, json) = parse_response(&resp);

        assert_eq!(status, "HTTP/1.1 200 OK");
        assert!(json["VIPServices"].as_array().unwrap().is_empty());
        // Empty set -> empty hash sentinel.
        assert_eq!(json["ServicesHash"].as_str().unwrap(), "");
    }

    #[test]
    fn vip_services_response_drops_invalid_names() {
        let config = crate::Config {
            advertise_services: alloc::vec![
                "svc:good".to_string(),
                "not-a-service".to_string(), // missing svc: prefix -> dropped
            ],
            ..Default::default()
        };
        let resp = build_vip_services_response(&config);
        let (_, json) = parse_response(&resp);

        let services = json["VIPServices"].as_array().unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0]["Name"].as_str().unwrap(), "svc:good");
    }
}
