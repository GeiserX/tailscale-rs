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
/// C2N URL path **prefix** under which requests are proxied into this node's LocalAPI, whatever the
/// LocalAPI version (`v0`, `v1`, …). Go `feature/remoteconfig`'s `c2nPrefix`, registered with
/// `ipnlocal.RegisterC2NPrefix`. Unlike every other route here this matches by prefix, so it is
/// tried only after the exact-path handlers above miss (Go `handleC2N` does the same).
const C2N_PREFIX_REMOTE_API: &str = "/remoteapi/localapi/";
/// The portion of [`C2N_PREFIX_REMOTE_API`] stripped from an incoming c2n path to yield the LocalAPI
/// path (Go `feature/remoteconfig`'s `localAPIStrip`).
const C2N_REMOTE_API_STRIP: &str = "/remoteapi";
/// What a stripped [`C2N_PREFIX_REMOTE_API`] path must begin with to be a LocalAPI path. Go
/// re-checks this after the strip so a mis-registered prefix cannot proxy somewhere else.
const C2N_LOCAL_API_PREFIX: &str = "/localapi/";
/// HTTP 400 Bad Request response sent for all unimplemented C2N methods/paths.
const C2N_PATH_UNKNOWN: &str = "HTTP/1.1 400 Bad Request\r\n\r\nunknown c2n path";
/// HTTP 403 Forbidden response sent when control invokes the `/remoteapi/localapi/*` proxy but the
/// local machine has not opted in via [`crate::Config::remote_config`] (Go
/// `handleC2NRemoteAPI`'s `http.Error(w, "remote config not enabled by local machine",
/// http.StatusForbidden)`).
const C2N_REMOTE_CONFIG_DISABLED: &str =
    "HTTP/1.1 403 Forbidden\r\n\r\nremote config not enabled by local machine";
/// HTTP 400 Bad Request response sent when a `/remoteapi/…` path does not survive the
/// `/remoteapi` strip into a `/localapi/` path (Go `handleC2NRemoteAPI`'s three
/// `http.Error(w, "unexpected remote-config path", http.StatusBadRequest)` refusals).
const C2N_REMOTE_API_BAD_PATH: &str =
    "HTTP/1.1 400 Bad Request\r\n\r\nunexpected remote-config path";
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
/// This mirrors Go's `handleC2N` (`ipn/ipnlocal/c2n.go`), including its dispatch *order*: exact
/// path matches are tried first, then the prefix handlers registered with
/// `ipnlocal.RegisterC2NPrefix`, and anything still unmatched falls through to
/// `http.Error(w, "unknown c2n path", http.StatusBadRequest)`. Only the routes listed below are
/// registered here; the fallthrough is the contract for everything else, so it is asserted by test
/// rather than left implicit.
///
/// The one prefix route is [`C2N_PREFIX_REMOTE_API`] — the LocalAPI proxy — and it exists only when
/// a [`LocalApi`](crate::LocalApi) is installed on the config, mirroring upstream's
/// `feature/remoteconfig` build tag: with the feature omitted, `RegisterC2NPrefix` is never called,
/// no prefix matches, and the path takes the same 400 as any other unknown path. Its capability
/// version (142) is not declared either — the declaration is held at 125 for the reasons below — so
/// control does not yet know to send one. The route is here so that raising the declaration is a
/// declaration change and not also a port.
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
async fn build_c2n_response(request: &Request<String>, config: &crate::Config) -> String {
    let c2n_request_path = request.uri().path();
    // Exact-path handlers first.
    match c2n_request_path {
        C2N_PATH_ECHO => {
            tracing::trace!(c2n_request_path, "handling c2n echo");
            return format!("{}{}", C2N_RESPONSE_ECHO_PREAMBLE, request.body());
        }
        C2N_PATH_VIP_SERVICES => {
            tracing::trace!(c2n_request_path, "handling c2n vip-services fetch");
            return build_vip_services_response(config);
        }
        _ => {}
    }
    // Then prefix handlers, exactly as Go walks `c2nPrefixHandlers` after both exact-match lookups
    // miss. Registered only when this node has a LocalAPI to proxy into (see the fn docs).
    if let Some(local_api) = &config.local_api
        && c2n_request_path.starts_with(C2N_PREFIX_REMOTE_API)
    {
        tracing::trace!(
            c2n_request_path,
            "handling c2n remote-config localapi proxy"
        );
        return handle_c2n_remote_api(request, local_api.as_ref(), config.remote_config).await;
    }
    tracing::debug!(c2n_request_path, "no handler for c2n path");
    C2N_PATH_UNKNOWN.to_string()
}

/// Proxy a c2n request under `/remoteapi/localapi/*` into this node's LocalAPI at `/localapi/*`,
/// with full read/write permission, when the local machine has opted in via
/// [`Config::remote_config`](crate::Config::remote_config).
///
/// A faithful port of Go `handleC2NRemoteAPI` (`feature/remoteconfig/remoteconfig.go`), refusals
/// included and in upstream's order:
///
/// 1. The pref gate comes **first**: with `RemoteConfig` off the answer is
///    `403 remote config not enabled by local machine`, and the path is never even parsed. This is
///    the whole of the authorization decision — upstream builds the proxied LocalAPI handler with
///    `Actor: ipnauth.Self`, `PermitRead`/`PermitWrite` set and no `RequiredPassword`, so nothing
///    downstream re-checks it.
/// 2. The prefix is re-checked inside the handler, so a mis-registered prefix refuses with
///    `400 unexpected remote-config path` instead of proxying an unrelated path.
/// 3. `/remoteapi` is stripped; if the strip changed nothing Go refuses "rather than looping".
///    Here that case *is* the failed `strip_prefix`, so the two collapse into one refusal.
/// 4. The stripped path must land under `/localapi/`, else the same 400. Upstream's own comment is
///    that the rewrite must not be able to aim the LocalAPI handler at an arbitrary path.
///
/// Only then is the request handed to the LocalAPI. The query string rides along: Go rewrites
/// `URL.Path` only, leaving `RawQuery` untouched, so a LocalAPI endpoint that reads query
/// parameters still sees them.
async fn handle_c2n_remote_api(
    request: &Request<String>,
    local_api: &dyn crate::LocalApi,
    remote_config: bool,
) -> String {
    if !remote_config {
        tracing::debug!("refusing c2n remote-config request: pref not enabled by local machine");
        return C2N_REMOTE_CONFIG_DISABLED.to_string();
    }
    let path = request.uri().path();
    if !path.starts_with(C2N_PREFIX_REMOTE_API) {
        tracing::debug!(
            c2n_request_path = path,
            "remote-config path outside the c2n prefix"
        );
        return C2N_REMOTE_API_BAD_PATH.to_string();
    }
    let Some(local_api_path) = path
        .strip_prefix(C2N_REMOTE_API_STRIP)
        .filter(|stripped| stripped.starts_with(C2N_LOCAL_API_PREFIX))
    else {
        tracing::debug!(
            c2n_request_path = path,
            "remote-config path is not a LocalAPI path"
        );
        return C2N_REMOTE_API_BAD_PATH.to_string();
    };
    let target = match request.uri().query() {
        Some(query) => format!("{local_api_path}?{query}"),
        None => local_api_path.to_string(),
    };
    local_api
        .serve(request.method().as_str(), &target, request.body())
        .await
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
/// Handles Control-to-Node (C2N) `GET /echo` (echo back the body), `GET /vip-services` (report
/// the VIP services this node hosts, from `config`) and — when a [`LocalApi`](crate::LocalApi) is
/// installed on `config` — the `/remoteapi/localapi/*` prefix that proxies into this node's
/// LocalAPI; non-C2N requests are skipped with a warning, while C2N requests for an unhandled path
/// return a "400 Bad Request" to the control plane.
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

        let c2n_response = build_c2n_response(&c2n_request, config).await;

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
    #[tokio::test]
    async fn c2n_debug_endpoints_answer_unknown_path() {
        let config = crate::Config::default();
        for raw in [
            "GET /debug/netmap HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "POST /debug/netmap HTTP/1.1\r\nHost: c2n\r\nContent-Length: 2\r\n\r\n{}",
            "GET /debug/health HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /debug/tka HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /debug/tka/log HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /debug/tka/log?limit=60 HTTP/1.1\r\nHost: c2n\r\n\r\n",
        ] {
            let resp = build_c2n_response(&c2n_request(raw), &config).await;
            assert_eq!(
                resp, "HTTP/1.1 400 Bad Request\r\n\r\nunknown c2n path",
                "{raw} must take the unknown-c2n-path fallthrough"
            );
        }
    }

    /// The 400 fallthrough is the contract for *every* unregistered path, not just the three debug
    /// endpoints — including other handlers Go registers that this node does not implement. Losing
    /// it (e.g. by routing a prefix) would make control believe an unimplemented feature works.
    #[tokio::test]
    async fn c2n_unknown_path_still_answers_400() {
        let config = crate::Config::default();
        for raw in [
            "GET /debug/goroutines HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /debug/metrics HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "POST /netfilter-kind HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /not-a-real-path HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: c2n\r\n\r\n",
        ] {
            let resp = build_c2n_response(&c2n_request(raw), &config).await;
            assert_eq!(
                resp, "HTTP/1.1 400 Bad Request\r\n\r\nunknown c2n path",
                "{raw} must take the unknown-c2n-path fallthrough"
            );
        }
    }

    /// A stand-in for this node's LocalAPI: records what the proxy handed it and answers with a
    /// fixed `200`, so the rewrite the proxy performs is observable without standing up a live
    /// LocalAPI server. The real implementation is installed by the `tsnet` facade.
    #[derive(Default)]
    struct RecordingLocalApi {
        /// Every `(method, target, body)` triple [`crate::LocalApi::serve`] was called with.
        seen: std::sync::Mutex<alloc::vec::Vec<(String, String, String)>>,
    }

    impl crate::LocalApi for RecordingLocalApi {
        fn serve<'a>(
            &'a self,
            method: &'a str,
            target: &'a str,
            body: &'a str,
        ) -> core::pin::Pin<alloc::boxed::Box<dyn core::future::Future<Output = String> + Send + 'a>>
        {
            alloc::boxed::Box::pin(async move {
                self.seen
                    .lock()
                    .expect("no test panics while holding it")
                    .push((method.to_string(), target.to_string(), body.to_string()));
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{\"Target\":\"{target}\"}}"
                )
            })
        }
    }

    /// A config with a [`RecordingLocalApi`] installed, plus a handle to inspect what it recorded.
    fn config_with_local_api(
        remote_config: bool,
    ) -> (crate::Config, alloc::sync::Arc<RecordingLocalApi>) {
        let local_api = alloc::sync::Arc::new(RecordingLocalApi::default());
        let config = crate::Config {
            remote_config,
            local_api: Some(local_api.clone()),
            ..Default::default()
        };
        (config, local_api)
    }

    /// The one prefix route: `/remoteapi/localapi/*` is proxied into this node's LocalAPI at
    /// `/localapi/*` once the local machine has opted in (Go `handleC2NRemoteAPI`,
    /// `feature/remoteconfig/remoteconfig.go`). The proxy must strip exactly `/remoteapi`, keep the
    /// method and body, and leave the query string on — Go rewrites `URL.Path` only and never
    /// touches `RawQuery`. The version segment is deliberately not matched: the prefix ends at
    /// `/localapi/`, so a future `v1` proxies the same way `v0` does.
    #[tokio::test]
    async fn c2n_remote_api_proxies_into_the_local_api() {
        let (config, local_api) = config_with_local_api(true);

        let status = build_c2n_response(
            &c2n_request("GET /remoteapi/localapi/v0/status HTTP/1.1\r\nHost: c2n\r\n\r\n"),
            &config,
        )
        .await;
        assert_eq!(
            status,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"Target\":\"/localapi/v0/status\"}",
            "the LocalAPI's own response is returned to control verbatim"
        );

        let set = build_c2n_response(
            &c2n_request(
                "POST /remoteapi/localapi/v1/prefs?exit-node=hq HTTP/1.1\r\nHost: c2n\r\nContent-Length: 14\r\n\r\n{\"RouteAll\":1}",
            ),
            &config,
        )
        .await;
        assert!(
            set.starts_with("HTTP/1.1 200 OK"),
            "a LocalAPI version the prefix does not name proxies the same way; got {set}"
        );

        let seen = local_api
            .seen
            .lock()
            .expect("no test panics while holding it")
            .clone();
        assert_eq!(
            seen,
            alloc::vec![
                (
                    "GET".to_string(),
                    "/localapi/v0/status".to_string(),
                    String::new()
                ),
                (
                    "POST".to_string(),
                    "/localapi/v1/prefs?exit-node=hq".to_string(),
                    "{\"RouteAll\":1}".to_string(),
                ),
            ],
            "method, the `/remoteapi`-stripped target (query string kept) and body all cross intact"
        );
    }

    /// The trust gate. Go checks `Prefs.RemoteConfig` *before* it looks at the path at all, and
    /// answers `403 remote config not enabled by local machine` when it is off. This fork's pref
    /// defaults to `false`, so an un-opted-in node refuses control's LocalAPI proxy and the request
    /// never reaches the LocalAPI.
    #[tokio::test]
    async fn c2n_remote_api_refuses_when_pref_disabled() {
        let (config, local_api) = config_with_local_api(false);

        for raw in [
            "GET /remoteapi/localapi/v0/status HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "POST /remoteapi/localapi/v0/prefs HTTP/1.1\r\nHost: c2n\r\n\r\n",
        ] {
            let resp = build_c2n_response(&c2n_request(raw), &config).await;
            assert_eq!(
                resp, "HTTP/1.1 403 Forbidden\r\n\r\nremote config not enabled by local machine",
                "{raw} must be refused while the local machine has not opted in"
            );
        }
        assert!(
            local_api
                .seen
                .lock()
                .expect("no test panics while holding it")
                .is_empty(),
            "a refused request must never reach the LocalAPI"
        );
    }

    /// The prefix must match in full, trailing slash included — everything else keeps taking the
    /// `unknown c2n path` 400, *even with a LocalAPI installed*. Go registers the prefix as
    /// `"/remoteapi/localapi/"` and `handleC2N` prefix-matches on exactly that string, so
    /// `/remoteapi/localapi` (no slash), a sibling path under `/remoteapi/`, and a path that merely
    /// starts with the same bytes all fall through. Losing this would make control believe an
    /// unimplemented endpoint works.
    #[tokio::test]
    async fn c2n_remote_api_near_miss_paths_still_answer_400() {
        let (config, local_api) = config_with_local_api(true);

        for raw in [
            "GET /remoteapi/localapi HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /remoteapi/localapinot/v0/status HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /remoteapi/ HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /remoteapi HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /localapi/v0/status HTTP/1.1\r\nHost: c2n\r\n\r\n",
            "GET /remoteapi/localapi?v0/status HTTP/1.1\r\nHost: c2n\r\n\r\n",
        ] {
            let resp = build_c2n_response(&c2n_request(raw), &config).await;
            assert_eq!(
                resp, "HTTP/1.1 400 Bad Request\r\n\r\nunknown c2n path",
                "{raw} must take the unknown-c2n-path fallthrough"
            );
        }
        assert!(
            local_api
                .seen
                .lock()
                .expect("no test panics while holding it")
                .is_empty(),
            "no near-miss path may reach the LocalAPI"
        );
    }

    /// With no LocalAPI installed the prefix route is not registered at all, so the proxy path
    /// takes the same `unknown c2n path` 400 as any other unregistered path — and does so *before*
    /// the pref is consulted, so it is indistinguishable from a node that never had the feature.
    /// This is upstream's omitted-`remoteconfig`-build behaviour: the `init` that calls
    /// `ipnlocal.RegisterC2NPrefix` never runs, so `handleC2N` finds no prefix to match.
    #[tokio::test]
    async fn c2n_remote_api_unknown_without_a_local_api() {
        for remote_config in [false, true] {
            let config = crate::Config {
                remote_config,
                local_api: None,
                ..Default::default()
            };
            let resp = build_c2n_response(
                &c2n_request("GET /remoteapi/localapi/v0/status HTTP/1.1\r\nHost: c2n\r\n\r\n"),
                &config,
            )
            .await;
            assert_eq!(
                resp, "HTTP/1.1 400 Bad Request\r\n\r\nunknown c2n path",
                "with no LocalAPI to proxy into, the prefix route does not exist \
                 (remote_config = {remote_config})"
            );
        }
    }

    /// Go's handler re-derives the LocalAPI path itself and refuses with
    /// `400 unexpected remote-config path` if the strip does not land under `/localapi/` — a
    /// defensive check against a mis-registered prefix, which is why it is unreachable through the
    /// dispatcher and is exercised on the handler directly.
    #[tokio::test]
    async fn c2n_remote_api_handler_refuses_a_path_it_cannot_rewrite() {
        let local_api = RecordingLocalApi::default();

        for raw in [
            // Strips to `/v0/status`, which is not under `/localapi/`.
            "GET /remoteapi/v0/status HTTP/1.1\r\nHost: c2n\r\n\r\n",
            // Nothing to strip: Go refuses "rather than looping" when the rewrite is a no-op.
            "GET /localapi/v0/status HTTP/1.1\r\nHost: c2n\r\n\r\n",
            // Under the strip prefix but not under the registered c2n prefix.
            "GET /remoteapi/localapi HTTP/1.1\r\nHost: c2n\r\n\r\n",
        ] {
            let resp = handle_c2n_remote_api(&c2n_request(raw), &local_api, true).await;
            assert_eq!(
                resp, "HTTP/1.1 400 Bad Request\r\n\r\nunexpected remote-config path",
                "{raw} is not rewritable into a LocalAPI path"
            );
        }
        assert!(
            local_api
                .seen
                .lock()
                .expect("no test panics while holding it")
                .is_empty(),
            "a path the handler cannot rewrite must never reach the LocalAPI"
        );
    }

    /// The two paths this node *does* serve still route through the same dispatcher, so the
    /// fallthrough above is proven to be a real routing decision and not a blanket 400.
    /// Go's `handleC2NEcho` writes the request body back verbatim with a bare 200.
    #[tokio::test]
    async fn c2n_echo_and_vip_services_still_route() {
        let config = crate::Config {
            advertise_services: alloc::vec!["svc:web".to_string()],
            ..Default::default()
        };

        let echo = build_c2n_response(
            &c2n_request("GET /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"),
            &config,
        )
        .await;
        assert_eq!(echo, "HTTP/1.1 200 OK\r\n\r\nhello");

        let vip = build_c2n_response(
            &c2n_request("GET /vip-services HTTP/1.1\r\nHost: c2n\r\n\r\n"),
            &config,
        )
        .await;
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
