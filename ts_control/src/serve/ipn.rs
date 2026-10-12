//! The stored Serve config in Go's wire shape (`ipn.ServeConfig` and its sub-types).
//!
//! Ported from `ipn/serve.go` (types, `HostPort.Port`) and `ipn/ipnlocal/serve.go`
//! (`validateServeConfigUpdate`, `serveTypeFromPortHandler`, `expandProxyArg`,
//! `parseRedirectWithCode`) at upstream `e2ed432399c9b0fda7aa14e9eb27784d2d893c55`.
//!
//! # Wire shape
//!
//! [`ServeState`] serializes exactly as Go's `encoding/json` encodes an `ipn.ServeConfig`: the
//! same field names, the same `omitempty`/`omitzero` elisions, `uint16` map keys as decimal
//! strings sorted the way Go sorts them (as strings, so `"10000"` precedes `"443"`), and the
//! empty config as `{}`. Decoding accepts what Go's decoder accepts where it matters for a
//! Go-produced document: `null` for any field, unknown fields (ignored), and port keys parsed with
//! Go's `strconv.ParseUint(s, 10, …)` rules (`"0443"` is port 443, `"+443"` is an error).
//!
//! Not mirrored: Go matches JSON field names case-insensitively (`"tcp"` fills `TCP`), and Go
//! HTML-escapes `<`, `>` and `&` inside strings when encoding. Neither changes what a Go encoder's
//! output decodes to; the second only changes the encoded bytes of a string carrying those
//! characters. `ETag` is `json:"-"` upstream and never on the wire, so it is not modelled.
//!
//! # What this runtime serves
//!
//! [`ServeState::serve_plan`] lowers the config onto the per-port [`ServeTarget`]s the serve
//! runtime dispatches. A config the runtime cannot serve the way Go would is **refused**, not
//! approximated: the config that is stored is the config that runs, or the call fails. See
//! [`ServeState::serve_plan`] for the exact list.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
};

use super::{ServeTarget, validate_target};
use crate::cert;

/// Why a serve config was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServeConfigError {
    /// The config is invalid. Go's own refusals (from `validateServeConfigUpdate`) carry Go's
    /// message verbatim; the rest are this fork's fail-closed checks (port 0, a CR/LF in a
    /// redirect target, an unparsable proxy address).
    #[error("{0}")]
    Invalid(String),
    /// Go would serve this config, but this runtime cannot yet serve it the way Go does, so it is
    /// refused rather than served differently. The string names the feature.
    #[error("serve config not supported by this runtime: {0}")]
    Unsupported(String),
    /// A TLS-terminating port names a host that is not a tailnet (`*.ts.net`) name. Anti-leak:
    /// no certificate is ever requested for an off-tailnet name.
    #[error("refusing to terminate TLS for non-tailnet name {0:?}")]
    NotTailnetName(String),
}

/// An SNI name and port joined by a colon (Go `ipn.HostPort`). There is no implicit port 443.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostPort(pub String);

impl HostPort {
    /// Join `host` and `port` the way Go's `net.JoinHostPort` does (an IPv6 literal is
    /// bracketed), which is how every upstream `HostPort` is built.
    pub fn new(host: &str, port: u16) -> Self {
        if host.contains(':') {
            HostPort(alloc::format!("[{host}]:{port}"))
        } else {
            HostPort(alloc::format!("{host}:{port}"))
        }
    }

    /// The host part (Go `net.SplitHostPort`'s first result).
    pub fn host(&self) -> Result<&str, ServeConfigError> {
        split_host_port(&self.0).map(|(host, _)| host)
    }

    /// The port number (Go `HostPort.Port`): an error if there is no port, or it is not a
    /// decimal number that fits in 16 bits.
    pub fn port(&self) -> Result<u16, ServeConfigError> {
        let (_, port) = split_host_port(&self.0)?;
        parse_go_uint16(port).ok_or_else(|| {
            ServeConfigError::Invalid(alloc::format!(
                "strconv.ParseUint: parsing {port:?}: invalid syntax or out of range"
            ))
        })
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Go's `net.SplitHostPort`, with its error cases.
fn split_host_port(hostport: &str) -> Result<(&str, &str), ServeConfigError> {
    let err = |why: &str| ServeConfigError::Invalid(alloc::format!("address {hostport}: {why}"));
    let Some(i) = hostport.rfind(':') else {
        return Err(err("missing port in address"));
    };
    let (host, j, k) = if hostport.starts_with('[') {
        let Some(end) = hostport.find(']') else {
            return Err(err("missing ']' in address"));
        };
        if end + 1 == hostport.len() {
            return Err(err("missing port in address"));
        }
        if end + 1 != i {
            return Err(if hostport.as_bytes()[end + 1] == b':' {
                err("too many colons in address")
            } else {
                err("missing port in address")
            });
        }
        (&hostport[1..end], 1, end + 1)
    } else {
        let host = &hostport[..i];
        if host.contains(':') {
            return Err(err("too many colons in address"));
        }
        (host, 0, 0)
    };
    if hostport[j..].contains('[') {
        return Err(err("unexpected '[' in address"));
    }
    if hostport[k..].contains(']') {
        return Err(err("unexpected ']' in address"));
    }
    Ok((host, &hostport[i + 1..]))
}

/// Go's `strconv.ParseUint(s, 10, 16)`: one or more ASCII digits (no sign, no spaces, leading
/// zeros allowed) whose value fits in a `u16`.
fn parse_go_uint16(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut n: u32 = 0;
    for b in s.bytes() {
        n = n.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
        if n > u32::from(u16::MAX) {
            return None;
        }
    }
    u16::try_from(n).ok()
}

/// What to do with a TCP connection on one port (Go `ipn.TCPPortHandler`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TcpPortHandler {
    /// Handle the connection as HTTPS, per [`ServeState::web`]. Mutually exclusive with
    /// [`tcp_forward`](Self::tcp_forward).
    #[serde(
        rename = "HTTPS",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "is_false"
    )]
    pub https: bool,
    /// Handle the connection as plain HTTP, per [`ServeState::web`]. Mutually exclusive with
    /// [`tcp_forward`](Self::tcp_forward).
    #[serde(
        rename = "HTTP",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "is_false"
    )]
    pub http: bool,
    /// Address to forward the TCP connection to: `host:port`, or `unix:` plus a socket path.
    #[serde(
        rename = "TCPForward",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub tcp_forward: String,
    /// If non-empty, terminate TLS (permitting only this SNI name) before forwarding to
    /// [`tcp_forward`](Self::tcp_forward).
    #[serde(
        rename = "TerminateTLS",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub terminate_tls: String,
    /// PROXY protocol version to send before forwarding to [`tcp_forward`](Self::tcp_forward);
    /// 0 sends none. (Go `int`, which is 64 bits on the platforms Tailscale ships.)
    #[serde(
        rename = "ProxyProtocol",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "is_zero"
    )]
    pub proxy_protocol: i64,
}

/// A web server's handlers, keyed by mount point (Go `ipn.WebServerConfig`).
///
/// `Handlers` has no `omitempty` upstream, so it is always encoded. Go encodes a nil map as
/// `null` and an empty one as `{}`; Rust has no such distinction and encodes `{}`. Both decode to
/// the same empty map here and in Go.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WebServerConfig {
    /// Mount point (`"/"`, `"/foo"`, …) → handler.
    #[serde(rename = "Handlers", default, deserialize_with = "nullable")]
    pub handlers: BTreeMap<String, HttpHandler>,
}

/// One HTTP handler (Go `ipn.HTTPHandler`). Exactly one of `path`, `proxy`, `text` and `redirect`
/// is meant to be set; when several are, Go's `serveWebHandler` uses the first of `text`,
/// `redirect`, `path`, `proxy`, and [`ServeState::serve_plan`] follows the same order.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HttpHandler {
    /// Absolute path to a directory or file to serve.
    #[serde(
        rename = "Path",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub path: String,
    /// Backend to reverse-proxy to: `http://localhost:3000/`, `localhost:3030`, or `3030`.
    #[serde(
        rename = "Proxy",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub proxy: String,
    /// Plain text to serve.
    #[serde(
        rename = "Text",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub text: String,
    /// Peer capabilities to forward to a [`proxy`](Self::proxy) backend in the grant header.
    #[serde(
        rename = "AcceptAppCaps",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub accept_app_caps: Vec<String>,
    /// Redirect target. `302 Found` by default; a `"3xx:"` prefix picks the status. May contain
    /// `${HOST}` and `${REQUEST_URI}`.
    #[serde(
        rename = "Redirect",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub redirect: String,
}

/// One Tailscale Service's serve config (Go `ipn.ServiceConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// TCP port → handler for the service's addresses.
    #[serde(
        rename = "TCP",
        default,
        deserialize_with = "de_port_map",
        serialize_with = "ser_port_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub tcp: BTreeMap<u16, TcpPortHandler>,
    /// `"$SNI_NAME:$PORT"` → web server.
    #[serde(
        rename = "Web",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub web: BTreeMap<HostPort, WebServerConfig>,
    /// L3 forwarding (TUN mode); mutually exclusive with `tcp` and `web`.
    #[serde(
        rename = "Tun",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "is_false"
    )]
    pub tun: bool,
}

/// A node's whole stored Serve config (Go `ipn.ServeConfig`), in Go's wire shape.
///
/// `Device::set_serve_config` replaces the stored config with one of these (Go
/// `SetServeConfig`'s REPLACE semantics) and `Device::get_serve_config` returns it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ServeState {
    /// TCP port → handler, for the node's Tailscale IPs.
    #[serde(
        rename = "TCP",
        default,
        deserialize_with = "de_port_map",
        serialize_with = "ser_port_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub tcp: BTreeMap<u16, TcpPortHandler>,
    /// `"$SNI_NAME:$PORT"` → web server, for ports whose handler is HTTP or HTTPS.
    #[serde(
        rename = "Web",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub web: BTreeMap<HostPort, WebServerConfig>,
    /// Service name (`"svc:dns-label"`) → that service's serve config.
    #[serde(
        rename = "Services",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub services: BTreeMap<String, ServiceConfig>,
    /// `SNI:port` values for which Funnel traffic from trusted ingress peers is allowed.
    #[serde(
        rename = "AllowFunnel",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub allow_funnel: BTreeMap<HostPort, bool>,
    /// IPN-bus session ID → a foreground config that lives as long as that session.
    #[serde(
        rename = "Foreground",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub foreground: BTreeMap<String, ServeState>,
}

/// One port the serve runtime binds, as lowered from a [`ServeState`] by
/// [`ServeState::serve_plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPort {
    /// What the runtime does with each connection on the port.
    pub target: ServeTarget,
    /// The tailnet name whose certificate terminates TLS on the port; `Some` exactly when
    /// `target.terminates_tls()`.
    pub cert_name: Option<String>,
}

impl ServeState {
    /// The ports of this config and of its foreground configs (Go `ServeConfigView.TCPs`).
    fn tcp_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.tcp.keys().copied().chain(
            self.foreground
                .values()
                .flat_map(|fg| fg.tcp.keys().copied()),
        )
    }

    /// The handler for `port`, preferring a foreground one (Go `ServeConfigView.FindTCP`).
    fn find_tcp(&self, port: u16) -> Option<&TcpPortHandler> {
        self.find_foreground_tcp(port)
            .or_else(|| self.tcp.get(&port))
    }

    /// The first foreground handler for `port` (Go `ServeConfigView.FindForegroundTCP`).
    fn find_foreground_tcp(&self, port: u16) -> Option<&TcpPortHandler> {
        self.foreground.values().find_map(|fg| fg.tcp.get(&port))
    }

    /// Lower this config onto the ports the serve runtime binds.
    ///
    /// Each entry of [`tcp`](Self::tcp) becomes at most one bound port, chosen the way Go's
    /// `tcpHandlerForServeTCP` chooses: HTTPS, else HTTP, else `TCPForward`. A handler with none of
    /// them set binds nothing, as Go returns no handler for it.
    ///
    /// * **HTTPS** becomes a [`ServeTarget::Path`] mux over the handlers of the one
    ///   [`web`](Self::web) entry for that port, with that entry's host as the certificate name.
    ///   Each handler is resolved in Go's `serveWebHandler` order: `Text`, `Redirect`, `Path`,
    ///   `Proxy`.
    /// * **`TCPForward`** to a `host:port` becomes [`ServeTarget::TcpForward`].
    ///
    /// Refused as [`ServeConfigError::Unsupported`], because the runtime would serve them
    /// differently from Go: plain-HTTP ports; `TCPForward` with `TerminateTLS`, `ProxyProtocol` or
    /// a `unix:` socket; an HTTPS port with no `web` entry, or with more than one SNI name; a
    /// `Text` handler (Go frames it as an HTTP response, the runtime writes bare bytes); a
    /// `Redirect` using `${HOST}` or `${REQUEST_URI}`; a `Path` (file-serving) handler; a `Proxy`
    /// at any mount but `/` (Go strips the mount prefix), with `AcceptAppCaps`, or to an
    /// `https://`, `https+insecure://` or `unix:` backend or one with a path; an empty handler;
    /// `Services`; `Foreground`; and an `AllowFunnel` entry that is on (Funnel is served by
    /// `listen_funnel`).
    ///
    /// Refused as [`ServeConfigError::Invalid`]: port 0, and a lowered target that fails this
    /// fork's target validation (e.g. a CR or LF in a redirect target). Refused as
    /// [`ServeConfigError::NotTailnetName`]: an HTTPS host that is not a tailnet name.
    pub fn serve_plan(&self) -> Result<BTreeMap<u16, PlannedPort>, ServeConfigError> {
        let unsupported = |what: &str| Err(ServeConfigError::Unsupported(what.to_string()));
        if !self.services.is_empty() {
            return unsupported("Services (Tailscale Service serving)");
        }
        if !self.foreground.is_empty() {
            return unsupported("Foreground (IPN-bus session configs)");
        }
        if self.allow_funnel.values().any(|on| *on) {
            return unsupported("AllowFunnel (Funnel is served by listen_funnel)");
        }

        let mut plan = BTreeMap::new();
        for (&port, handler) in &self.tcp {
            if port == 0 {
                return Err(ServeConfigError::Invalid(
                    "serve port must be non-zero".to_string(),
                ));
            }
            let planned = if handler.https {
                self.plan_https(port)?
            } else if handler.http {
                return unsupported("plain-HTTP ports");
            } else if !handler.tcp_forward.is_empty() {
                plan_tcp_forward(handler)?
            } else {
                continue;
            };
            validate_target(&planned.target, 0).map_err(ServeConfigError::Invalid)?;
            plan.insert(port, planned);
        }
        Ok(plan)
    }

    /// Lower an HTTPS port: the one `web` entry for `port` becomes a path mux, terminated with
    /// its host's certificate.
    fn plan_https(&self, port: u16) -> Result<PlannedPort, ServeConfigError> {
        // Go picks the web config by the TLS SNI name, so it can serve several names on one port;
        // the runtime terminates TLS with a single certificate per port.
        let mut on_port = self
            .web
            .iter()
            .filter(|(hp, _)| hp.port().ok() == Some(port));
        let Some((hp, web)) = on_port.next() else {
            return Err(ServeConfigError::Unsupported(alloc::format!(
                "HTTPS port {port} with no Web config for it"
            )));
        };
        if on_port.next().is_some() {
            return Err(ServeConfigError::Unsupported(alloc::format!(
                "more than one SNI name on HTTPS port {port}"
            )));
        }
        let host = hp.host()?;
        if !cert::is_tailnet_name(host) {
            return Err(ServeConfigError::NotTailnetName(host.to_string()));
        }
        if web.handlers.is_empty() {
            return Err(ServeConfigError::Unsupported(alloc::format!(
                "HTTPS port {port} with no handlers"
            )));
        }
        let mut handlers = BTreeMap::new();
        for (mount, h) in &web.handlers {
            handlers.insert(mount.clone(), plan_http_handler(mount, h)?);
        }
        Ok(PlannedPort {
            target: ServeTarget::Path { handlers },
            cert_name: Some(host.to_string()),
        })
    }
}

/// Lower a `TCPForward` port handler (one with neither HTTPS nor HTTP set).
fn plan_tcp_forward(handler: &TcpPortHandler) -> Result<PlannedPort, ServeConfigError> {
    let unsupported = |what: &str| Err(ServeConfigError::Unsupported(what.to_string()));
    if !handler.terminate_tls.is_empty() {
        return unsupported("TCPForward with TerminateTLS");
    }
    if handler.proxy_protocol != 0 {
        return unsupported("TCPForward with ProxyProtocol");
    }
    if handler.tcp_forward.starts_with("unix:") {
        return unsupported("TCPForward to a unix: socket");
    }
    Ok(PlannedPort {
        target: ServeTarget::TcpForward {
            to: handler.tcp_forward.clone(),
        },
        cert_name: None,
    })
}

/// Lower one web handler mounted at `mount`, in Go `serveWebHandler`'s order.
fn plan_http_handler(mount: &str, h: &HttpHandler) -> Result<ServeTarget, ServeConfigError> {
    let unsupported = |what: &str| Err(ServeConfigError::Unsupported(what.to_string()));
    if !h.text.is_empty() {
        return unsupported("Text handlers");
    }
    if !h.redirect.is_empty() {
        let (status, to) = parse_redirect_with_code(&h.redirect);
        if to.contains("${HOST}") || to.contains("${REQUEST_URI}") {
            return unsupported("Redirect with ${HOST} or ${REQUEST_URI}");
        }
        return Ok(ServeTarget::Redirect {
            to: to.to_string(),
            status,
        });
    }
    if !h.path.is_empty() {
        return unsupported("Path (file-serving) handlers");
    }
    if !h.proxy.is_empty() {
        // Go strips the mount from the request path before proxying, except for a mount that is
        // `/` (or empty) once its one trailing slash is trimmed.
        if !mount.strip_suffix('/').unwrap_or(mount).is_empty() {
            return unsupported("Proxy at a mount other than /");
        }
        if !h.accept_app_caps.is_empty() {
            return unsupported("Proxy with AcceptAppCaps");
        }
        let (target_url, _insecure) = expand_proxy_arg(&h.proxy);
        return Ok(ServeTarget::Proxy {
            to: proxy_backend_addr(&target_url)?,
        });
    }
    unsupported("empty handlers")
}

/// Go's `expandProxyArg`: turn an `HTTPHandler.Proxy` value (a port, `host:port`, or a URL) into
/// a backend URL, and whether TLS verification is to be skipped.
pub fn expand_proxy_arg(s: &str) -> (String, bool) {
    if s.is_empty() {
        return (String::new(), false);
    }
    if s.starts_with("unix:") || s.starts_with("http://") || s.starts_with("https://") {
        return (s.to_string(), false);
    }
    if let Some(rest) = s.strip_prefix("https+insecure://") {
        return (alloc::format!("https://{rest}"), true);
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return (alloc::format!("http://127.0.0.1:{s}"), false);
    }
    (alloc::format!("http://{s}"), false)
}

/// The `host:port` the runtime dials for an expanded proxy URL. Only a plain `http://` backend
/// with no path is spliced verbatim the way Go's reverse proxy would forward it; the port defaults
/// to 80 as Go's transport defaults it.
fn proxy_backend_addr(target_url: &str) -> Result<String, ServeConfigError> {
    let Some(rest) = target_url.strip_prefix("http://") else {
        return Err(ServeConfigError::Unsupported(alloc::format!(
            "Proxy backend {target_url:?} (only http:// backends are supported)"
        )));
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if !(tail.is_empty() || tail == "/") {
        return Err(ServeConfigError::Unsupported(alloc::format!(
            "Proxy backend {target_url:?} with a path, query or fragment"
        )));
    }
    let invalid = || {
        ServeConfigError::Invalid(alloc::format!(
            "invalid Proxy backend address {target_url:?}"
        ))
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid());
    }
    // Split off a port if there is one: after the `]` of an IPv6 literal, else after the only
    // colon.
    let port_at = if authority.starts_with('[') {
        let close = authority.find(']').ok_or_else(invalid)?;
        match &authority[close + 1..] {
            "" => None,
            p if p.starts_with(':') => Some(close + 1),
            _ => return Err(invalid()),
        }
    } else {
        match authority.matches(':').count() {
            0 => None,
            1 => authority.find(':'),
            _ => return Err(invalid()),
        }
    };
    match port_at {
        Some(i) if i + 1 < authority.len() => {
            parse_go_uint16(&authority[i + 1..]).ok_or_else(invalid)?;
            Ok(authority.to_string())
        }
        // `host:` with an empty port dials the scheme's default port, as `host` does.
        Some(i) => Ok(alloc::format!("{}:80", &authority[..i])),
        None => Ok(alloc::format!("{authority}:80")),
    }
}

/// Go's `parseRedirectWithCode`: a `"3xx:"` prefix (300–399) picks the status; anything else is a
/// `302 Found` to the whole string.
pub fn parse_redirect_with_code(redirect: &str) -> (u16, &str) {
    let b = redirect.as_bytes();
    if b.len() >= 4 && b[3] == b':' {
        // Byte 3 is ASCII, so both slices fall on character boundaries. Go's `strconv.Atoi` also
        // takes a sign, but no signed three-byte number is in 300..=399, so digits suffice.
        if let Some(code) = parse_go_uint16(&redirect[..3])
            && (300..=399).contains(&code)
        {
            return (code, &redirect[4..]);
        }
    }
    (302, redirect)
}

/// The kind of serve a port handler performs (Go `serveType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServeType {
    Https,
    Http,
    Tcp,
    TlsTerminatedTcp,
    /// Go's `-1`, for a handler with nothing set.
    Unknown,
}

impl fmt::Display for ServeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ServeType::Https => "https",
            ServeType::Http => "http",
            ServeType::Tcp => "tcp",
            ServeType::TlsTerminatedTcp => "tls-terminated-tcp",
            ServeType::Unknown => "unknownServeType",
        })
    }
}

/// Go's `serveTypeFromPortHandler`. Note HTTP is tested before HTTPS here, as upstream does.
fn serve_type(h: &TcpPortHandler) -> ServeType {
    if h.http {
        ServeType::Http
    } else if h.https {
        ServeType::Https
    } else if !h.terminate_tls.is_empty() {
        ServeType::TlsTerminatedTcp
    } else if !h.tcp_forward.is_empty() {
        ServeType::Tcp
    } else {
        ServeType::Unknown
    }
}

/// Go's `validateServeConfigUpdate`: the refusals Go applies when `incoming` replaces `existing`.
///
/// TUN mode is exclusive with TCP and web handlers on a Service; a new foreground session may not
/// claim a port already in use; a background port may not take over a foreground one; and a port
/// that stays configured may not change its serve type (`https`, `http`, `tcp`,
/// `tls-terminated-tcp`) — clear it in one update and reconfigure it in the next. The messages are
/// Go's. A never-set config is the empty one, against which only the first check can fail, as in
/// Go.
pub fn validate_serve_config_update(
    existing: &ServeState,
    incoming: &ServeState,
) -> Result<(), ServeConfigError> {
    let invalid = |msg: String| Err(ServeConfigError::Invalid(msg));

    for (name, svc) in &incoming.services {
        if svc.tun && (!svc.tcp.is_empty() || !svc.web.is_empty()) {
            return invalid(alloc::format!(
                "cannot configure TUN mode in combination with TCP or web handlers for {name}"
            ));
        }
    }

    for (session, fg) in &incoming.foreground {
        if !existing.foreground.contains_key(session) {
            for port in fg.tcp_ports() {
                if existing.find_tcp(port).is_some() {
                    return invalid(alloc::format!("listener already exists for port {port}"));
                }
            }
        }
    }

    for &port in incoming.tcp.keys() {
        if existing.find_foreground_tcp(port).is_some() {
            return invalid(alloc::format!(
                "foreground listener already exists for port {port}"
            ));
        }
    }

    for (&port, handler) in &incoming.tcp {
        let Some(existing_handler) = existing.find_tcp(port) else {
            continue;
        };
        let (was, want) = (serve_type(existing_handler), serve_type(handler));
        if want != was {
            return invalid(alloc::format!(
                "want to serve {:?}, but port {port} is already serving {:?}",
                want.to_string(),
                was.to_string()
            ));
        }
    }

    for (name, svc) in &incoming.services {
        let Some(existing_svc) = existing.services.get(name) else {
            continue;
        };
        for (port, handler) in &svc.tcp {
            let Some(existing_handler) = existing_svc.tcp.get(port) else {
                continue;
            };
            let (was, want) = (serve_type(existing_handler), serve_type(handler));
            if want != was {
                return invalid(alloc::format!(
                    "want to serve {:?}, but port {port} is already serving {:?} for {name}",
                    want.to_string(),
                    was.to_string()
                ));
            }
        }
        let existing_has_handlers = !existing_svc.tcp.is_empty() || !existing_svc.web.is_empty();
        if svc.tun && existing_has_handlers {
            return invalid(alloc::format!(
                "cannot turn on TUN mode with existing TCP or web handlers for {name}"
            ));
        }
        if (!svc.tcp.is_empty() || !svc.web.is_empty()) && existing_svc.tun {
            return invalid(alloc::format!(
                "cannot add TCP or web handlers as TUN mode is enabled for {name}"
            ));
        }
    }

    Ok(())
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// Decode a field Go may encode as `null` (a nil map or slice): `null` reads as the default.
fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Encode a `map[uint16]…` as Go does: decimal-string keys, sorted as strings.
fn ser_port_map<S, V>(m: &BTreeMap<u16, V>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    V: Serialize,
{
    let mut entries: Vec<(String, &V)> = m.iter().map(|(k, v)| (k.to_string(), v)).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    s.collect_map(entries)
}

/// Decode a `map[uint16]…` as Go does: `null` is empty, each key goes through Go's
/// `strconv.ParseUint(key, 10, …)` with a 16-bit range check, and a repeated port (`"443"` and
/// `"0443"`) keeps the later value.
fn de_port_map<'de, D, V>(d: D) -> Result<BTreeMap<u16, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct PortMap<V>(BTreeMap<u16, V>);

    struct PortMapVisitor<V>(PhantomData<V>);

    impl<'de, V: Deserialize<'de>> Visitor<'de> for PortMapVisitor<V> {
        type Value = PortMap<V>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object keyed by decimal port numbers")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, V>()? {
                let port = parse_go_uint16(&key).ok_or_else(|| {
                    de::Error::custom(alloc::format!("invalid port number {key:?} as a map key"))
                })?;
                out.insert(port, value);
            }
            Ok(PortMap(out))
        }
    }

    impl<'de, V: Deserialize<'de>> Deserialize<'de> for PortMap<V> {
        fn deserialize<D2: Deserializer<'de>>(d: D2) -> Result<Self, D2::Error> {
            d.deserialize_map(PortMapVisitor(PhantomData))
        }
    }

    Ok(Option::<PortMap<V>>::deserialize(d)?
        .map(|m| m.0)
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "host.tail1.ts.net";

    fn hp(port: u16) -> HostPort {
        HostPort::new(NAME, port)
    }

    fn handlers(entries: &[(&str, HttpHandler)]) -> WebServerConfig {
        WebServerConfig {
            handlers: entries
                .iter()
                .map(|(m, h)| (m.to_string(), h.clone()))
                .collect(),
        }
    }

    fn proxy(to: &str) -> HttpHandler {
        HttpHandler {
            proxy: to.into(),
            ..Default::default()
        }
    }

    fn redirect(to: &str) -> HttpHandler {
        HttpHandler {
            redirect: to.into(),
            ..Default::default()
        }
    }

    fn https_on(port: u16, web: WebServerConfig) -> ServeState {
        ServeState {
            tcp: [(
                port,
                TcpPortHandler {
                    https: true,
                    ..Default::default()
                },
            )]
            .into(),
            web: [(hp(port), web)].into(),
            ..Default::default()
        }
    }

    fn tcp(entries: &[(u16, TcpPortHandler)]) -> ServeState {
        ServeState {
            tcp: entries.iter().cloned().collect(),
            ..Default::default()
        }
    }

    fn forward(to: &str) -> TcpPortHandler {
        TcpPortHandler {
            tcp_forward: to.into(),
            ..Default::default()
        }
    }

    fn http() -> TcpPortHandler {
        TcpPortHandler {
            http: true,
            ..Default::default()
        }
    }

    fn https() -> TcpPortHandler {
        TcpPortHandler {
            https: true,
            ..Default::default()
        }
    }

    fn unsupported(st: &ServeState) -> bool {
        matches!(st.serve_plan(), Err(ServeConfigError::Unsupported(_)))
    }

    // ---- wire shape ----

    #[test]
    fn empty_object_decodes_to_the_empty_config_and_back() {
        // Go encodes a zero `ipn.ServeConfig` as `{}` (every field is omitempty) and that is what
        // a fresh node's LocalAPI hands out. It has to decode, and the empty config has to encode
        // to exactly it.
        let st: ServeState = serde_json::from_str("{}").unwrap();
        assert_eq!(st, ServeState::default());
        assert_eq!(serde_json::to_string(&ServeState::default()).unwrap(), "{}");
    }

    /// `json.Marshal` of a Go `ipn.ServeConfig` built with every handler shape, derived from Go's
    /// `encoding/json` rules: struct-order fields, omitempty/omitzero elided, map keys sorted as
    /// strings (`"10000"` before `"443"` before `"5432"`).
    const GO_JSON: &str = concat!(
        r#"{"TCP":{"#,
        r#""10000":{"TCPForward":"localhost:3000","TerminateTLS":"host.tail1.ts.net","ProxyProtocol":2},"#,
        r#""443":{"HTTPS":true},"#,
        r#""5432":{"TCPForward":"127.0.0.1:5432"}},"#,
        r#""Web":{"host.tail1.ts.net:443":{"Handlers":{"#,
        r#""/":{"Proxy":"http://127.0.0.1:3000"},"#,
        r#""/caps":{"Proxy":"3001","AcceptAppCaps":["example.com/cap/mon"]},"#,
        r#""/old":{"Redirect":"301:https://host.tail1.ts.net/new"}}}},"#,
        r#""AllowFunnel":{"host.tail1.ts.net:443":true}}"#,
    );

    fn go_json_config() -> ServeState {
        ServeState {
            tcp: [
                (
                    10000,
                    TcpPortHandler {
                        tcp_forward: "localhost:3000".into(),
                        terminate_tls: NAME.into(),
                        proxy_protocol: 2,
                        ..Default::default()
                    },
                ),
                (443, https()),
                (5432, forward("127.0.0.1:5432")),
            ]
            .into(),
            web: [(
                hp(443),
                handlers(&[
                    ("/", proxy("http://127.0.0.1:3000")),
                    (
                        "/caps",
                        HttpHandler {
                            proxy: "3001".into(),
                            accept_app_caps: vec!["example.com/cap/mon".into()],
                            ..Default::default()
                        },
                    ),
                    ("/old", redirect("301:https://host.tail1.ts.net/new")),
                ]),
            )]
            .into(),
            allow_funnel: [(hp(443), true)].into(),
            ..Default::default()
        }
    }

    #[test]
    fn decodes_a_go_encoded_config() {
        let st: ServeState = serde_json::from_str(GO_JSON).unwrap();
        assert_eq!(st, go_json_config());
    }

    #[test]
    fn encodes_byte_for_byte_as_go_does() {
        assert_eq!(serde_json::to_string(&go_json_config()).unwrap(), GO_JSON);
    }

    #[test]
    fn services_and_foreground_round_trip_in_go_shape() {
        let json = concat!(
            r#"{"Services":{"svc:db":{"TCP":{"5432":{"TCPForward":"127.0.0.1:5432"}}},"#,
            r#""svc:vpn":{"Tun":true}},"#,
            r#""Foreground":{"12345":{"TCP":{"8080":{"HTTP":true}},"#,
            r#""Web":{"host.tail1.ts.net:8080":{"Handlers":{"/":{"Text":"hi"}}}}}}}"#,
        );
        let st: ServeState = serde_json::from_str(json).unwrap();
        assert!(st.services["svc:vpn"].tun);
        assert_eq!(
            st.services["svc:db"].tcp[&5432].tcp_forward,
            "127.0.0.1:5432"
        );
        assert!(st.foreground["12345"].tcp[&8080].http);
        assert_eq!(serde_json::to_string(&st).unwrap(), json);
    }

    #[test]
    fn decode_accepts_nulls_and_ignores_unknown_fields_as_go_does() {
        // Go encodes a nil `Handlers` map as `null`; any field may be null; and a newer Go adds
        // fields this tree does not know.
        let json = concat!(
            r#"{"TCP":null,"Services":null,"FutureField":{"x":1},"#,
            r#""Web":{"host.tail1.ts.net:443":{"Handlers":null}},"#,
            r#""AllowFunnel":{"host.tail1.ts.net:443":false}}"#,
        );
        let st: ServeState = serde_json::from_str(json).unwrap();
        assert!(st.tcp.is_empty());
        assert!(st.web[&hp(443)].handlers.is_empty());
        assert!(!st.allow_funnel[&hp(443)]);

        let h: TcpPortHandler =
            serde_json::from_str(r#"{"HTTPS":null,"TCPForward":null,"ProxyProtocol":null}"#)
                .unwrap();
        assert_eq!(h, TcpPortHandler::default());
    }

    #[test]
    fn port_keys_parse_with_go_parseuint_rules() {
        let st: ServeState = serde_json::from_str(r#"{"TCP":{"0443":{"HTTPS":true}}}"#).unwrap();
        assert!(st.tcp[&443].https);
        for bad in ["+443", " 443", "-1", "65536", "", "0x1bb", "443 "] {
            let json = alloc::format!(r#"{{"TCP":{{"{bad}":{{}}}}}}"#);
            assert!(
                serde_json::from_str::<ServeState>(&json).is_err(),
                "port key {bad:?} must not decode"
            );
        }
        // A repeated port keeps the later entry, as Go's map decode does.
        let st: ServeState =
            serde_json::from_str(r#"{"TCP":{"443":{"HTTP":true},"0443":{"HTTPS":true}}}"#).unwrap();
        assert_eq!(st.tcp[&443], https());
    }

    // ---- HostPort ----

    #[test]
    fn host_port_splits_like_go_net_splithostport() {
        assert_eq!(hp(443).0, "host.tail1.ts.net:443");
        assert_eq!(HostPort::new("::1", 8443).0, "[::1]:8443");
        assert_eq!(hp(443).port().unwrap(), 443);
        assert_eq!(hp(443).host().unwrap(), NAME);
        assert_eq!(HostPort("[::1]:8443".into()).host().unwrap(), "::1");
        assert_eq!(HostPort("h:0080".into()).port().unwrap(), 80);
        for bad in [
            "host.tail1.ts.net",
            "a:b:443",
            "[::1]",
            "[::1]x:443",
            "[::1:443",
            "x]:443",
            "h:",
            "h:+1",
            "h:65536",
        ] {
            assert!(
                HostPort(bad.into()).port().is_err(),
                "{bad:?} must not yield a port"
            );
        }
    }

    // ---- Go helper ports ----

    #[test]
    fn expand_proxy_arg_matches_go() {
        // Go's TestExpandProxyArg table.
        for (input, want, insecure) in [
            ("", "", false),
            ("3030", "http://127.0.0.1:3030", false),
            ("localhost:3030", "http://localhost:3030", false),
            ("10.2.3.5:3030", "http://10.2.3.5:3030", false),
            ("http://foo.com", "http://foo.com", false),
            ("https://foo.com", "https://foo.com", false),
            ("https+insecure://10.2.3.4", "https://10.2.3.4", true),
        ] {
            assert_eq!(
                expand_proxy_arg(input),
                (want.to_string(), insecure),
                "{input:?}"
            );
        }
    }

    #[test]
    fn parse_redirect_with_code_matches_go() {
        // Go's TestParseRedirectWithRedirectCode table.
        for (input, code, url) in [
            ("301:https://example.com", 301, "https://example.com"),
            ("302:https://example.com", 302, "https://example.com"),
            ("303:/path", 303, "/path"),
            (
                "307:https://example.com/path?query=1",
                307,
                "https://example.com/path?query=1",
            ),
            ("308:https://example.com", 308, "https://example.com"),
            ("https://example.com", 302, "https://example.com"),
            ("/path", 302, "/path"),
            ("http://example.com", 302, "http://example.com"),
            ("git://example.com", 302, "git://example.com"),
            ("200:https://example.com", 302, "200:https://example.com"),
            ("404:https://example.com", 302, "404:https://example.com"),
            ("500:https://example.com", 302, "500:https://example.com"),
            ("30:https://example.com", 302, "30:https://example.com"),
            ("3:https://example.com", 302, "3:https://example.com"),
            ("3012:https://example.com", 302, "3012:https://example.com"),
            ("abc:https://example.com", 302, "abc:https://example.com"),
            ("301", 302, "301"),
        ] {
            assert_eq!(parse_redirect_with_code(input), (code, url), "{input:?}");
        }
    }

    // ---- validateServeConfigUpdate (Go's TestValidateServeConfigUpdate table) ----

    fn svc(tcp_ports: &[(u16, TcpPortHandler)], web: bool, tun: bool) -> ServiceConfig {
        ServiceConfig {
            tcp: tcp_ports.iter().cloned().collect(),
            web: if web {
                [(HostPort("127.0.0.1:443".into()), WebServerConfig::default())].into()
            } else {
                BTreeMap::new()
            },
            tun,
        }
    }

    fn with_services(services: &[(&str, ServiceConfig)]) -> ServeState {
        ServeState {
            services: services
                .iter()
                .map(|(n, s)| (n.to_string(), s.clone()))
                .collect(),
            ..Default::default()
        }
    }

    fn with_foreground(session: &str, fg: ServeState) -> ServeState {
        ServeState {
            foreground: [(session.to_string(), fg)].into(),
            ..Default::default()
        }
    }

    #[test]
    fn validate_serve_config_update_matches_go() {
        let empty = ServeState::default();
        let mut broken = tcp(&[
            (
                9000,
                TcpPortHandler {
                    https: true,
                    tcp_forward: "127.0.0.1:9000".into(),
                    ..Default::default()
                },
            ),
            (443, TcpPortHandler::default()),
        ]);
        broken.foreground = [(
            "12345".to_string(),
            tcp(&[(443, TcpPortHandler::default())]),
        )]
        .into();
        broken.services = [(
            "svc:foo".to_string(),
            svc(&[(6060, TcpPortHandler::default())], false, true),
        )]
        .into();

        let cases: &[(&str, ServeState, ServeState, Option<&str>)] = &[
            (
                "empty-existing-config",
                empty.clone(),
                tcp(&[(8080, TcpPortHandler::default())]),
                None,
            ),
            (
                "empty-incoming-config",
                tcp(&[(80, TcpPortHandler::default())]),
                empty.clone(),
                None,
            ),
            (
                "non-overlapping-update",
                tcp(&[(80, TcpPortHandler::default())]),
                tcp(&[(8080, TcpPortHandler::default())]),
                None,
            ),
            (
                "overwriting-background-port",
                tcp(&[(80, forward("localhost:8080"))]),
                tcp(&[(80, forward("localhost:9999"))]),
                None,
            ),
            (
                "broken-existing-config",
                broken,
                tcp(&[(80, TcpPortHandler::default())]),
                None,
            ),
            (
                "services-same-port-as-background",
                tcp(&[(80, TcpPortHandler::default())]),
                with_services(&[(
                    "svc:foo",
                    svc(&[(80, TcpPortHandler::default())], false, false),
                )]),
                None,
            ),
            (
                "services-tun-mode",
                empty.clone(),
                with_services(&[(
                    "svc:foo",
                    svc(&[(6060, TcpPortHandler::default())], false, true),
                )]),
                Some(
                    "cannot configure TUN mode in combination with TCP or web handlers for svc:foo",
                ),
            ),
            (
                "new-foreground-listener",
                tcp(&[(80, TcpPortHandler::default())]),
                with_foreground("12345", tcp(&[(80, TcpPortHandler::default())])),
                Some("listener already exists for port 80"),
            ),
            (
                "new-background-listener",
                with_foreground("12345", tcp(&[(80, TcpPortHandler::default())])),
                tcp(&[(80, TcpPortHandler::default())]),
                Some("foreground listener already exists for port 80"),
            ),
            (
                "serve-type-overwrite",
                tcp(&[(80, http())]),
                tcp(&[(80, forward("localhost:8080"))]),
                Some(r#"want to serve "tcp", but port 80 is already serving "http""#),
            ),
            (
                "serve-type-overwrite-services",
                with_services(&[("svc:foo", svc(&[(80, http())], false, false))]),
                with_services(&[(
                    "svc:foo",
                    svc(&[(80, forward("localhost:8080"))], false, false),
                )]),
                Some(r#"want to serve "tcp", but port 80 is already serving "http" for svc:foo"#),
            ),
            (
                "tun-mode-with-handlers",
                with_services(&[("svc:foo", svc(&[(443, https())], true, false))]),
                with_services(&[("svc:foo", svc(&[], false, true))]),
                Some("cannot turn on TUN mode with existing TCP or web handlers for svc:foo"),
            ),
            (
                "handlers-with-tun-mode",
                with_services(&[("svc:foo", svc(&[], false, true))]),
                with_services(&[("svc:foo", svc(&[(443, https())], true, false))]),
                Some("cannot add TCP or web handlers as TUN mode is enabled for svc:foo"),
            ),
        ];
        for (name, existing, incoming, want) in cases {
            let got = validate_serve_config_update(existing, incoming);
            match want {
                None => assert_eq!(got, Ok(()), "{name}"),
                Some(msg) => assert_eq!(
                    got,
                    Err(ServeConfigError::Invalid(msg.to_string())),
                    "{name}"
                ),
            }
        }
    }

    #[test]
    fn serve_type_names_match_go_including_unknown() {
        // A port that was configured with nothing set is "unknownServeType" (Go's -1), so even
        // giving it a real handler is a type change Go refuses.
        let got = validate_serve_config_update(
            &tcp(&[(80, TcpPortHandler::default())]),
            &tcp(&[(80, https())]),
        );
        assert_eq!(
            got,
            Err(ServeConfigError::Invalid(
                r#"want to serve "https", but port 80 is already serving "unknownServeType""#
                    .to_string()
            ))
        );
        let tls_tcp = TcpPortHandler {
            tcp_forward: "127.0.0.1:5432".into(),
            terminate_tls: NAME.into(),
            ..Default::default()
        };
        assert_eq!(serve_type(&tls_tcp), ServeType::TlsTerminatedTcp);
        assert_eq!(serve_type(&tls_tcp).to_string(), "tls-terminated-tcp");
        // Both HTTP and HTTPS set: Go names it "http" (it tests HTTP first) ...
        let both = TcpPortHandler {
            http: true,
            https: true,
            ..Default::default()
        };
        assert_eq!(serve_type(&both), ServeType::Http);
    }

    // ---- serve_plan ----

    #[test]
    fn empty_config_plans_nothing() {
        assert_eq!(ServeState::default().serve_plan(), Ok(BTreeMap::new()));
    }

    #[test]
    fn https_port_lowers_to_a_path_mux_with_its_hosts_cert() {
        let st = https_on(
            443,
            handlers(&[
                ("/", proxy("3000")),
                ("/old", redirect("308:https://host.tail1.ts.net/new")),
                ("/moved", redirect("/elsewhere")),
            ]),
        );
        let plan = st.serve_plan().unwrap();
        let mut want = BTreeMap::new();
        want.insert(
            "/".to_string(),
            ServeTarget::Proxy {
                to: "127.0.0.1:3000".into(),
            },
        );
        want.insert(
            "/old".to_string(),
            ServeTarget::Redirect {
                to: "https://host.tail1.ts.net/new".into(),
                status: 308,
            },
        );
        want.insert(
            "/moved".to_string(),
            ServeTarget::Redirect {
                to: "/elsewhere".into(),
                status: 302,
            },
        );
        assert_eq!(
            plan,
            [(
                443,
                PlannedPort {
                    target: ServeTarget::Path { handlers: want },
                    cert_name: Some(NAME.to_string()),
                }
            )]
            .into()
        );
        assert!(plan[&443].target.terminates_tls());
    }

    #[test]
    fn tcp_forward_lowers_to_a_raw_forward_without_a_cert() {
        let plan = tcp(&[(5432, forward("127.0.0.1:5432"))])
            .serve_plan()
            .unwrap();
        assert_eq!(
            plan[&5432],
            PlannedPort {
                target: ServeTarget::TcpForward {
                    to: "127.0.0.1:5432".into()
                },
                cert_name: None,
            }
        );
    }

    #[test]
    fn https_wins_over_tcp_forward_and_an_empty_handler_binds_nothing() {
        // Go's tcpHandlerForServeTCP checks HTTPS/HTTP before TCPForward, and returns no handler
        // at all for a port with nothing set.
        let mut st = https_on(443, handlers(&[("/", proxy("3000"))]));
        st.tcp.get_mut(&443).unwrap().tcp_forward = "127.0.0.1:9".into();
        st.tcp.insert(80, TcpPortHandler::default());
        let plan = st.serve_plan().unwrap();
        assert_eq!(plan.keys().copied().collect::<Vec<_>>(), vec![443]);
        assert!(matches!(plan[&443].target, ServeTarget::Path { .. }));
    }

    #[test]
    fn handler_precedence_follows_go_serve_web_handler() {
        // Redirect is consulted before Path and Proxy.
        let h = HttpHandler {
            redirect: "/r".into(),
            path: "/srv".into(),
            proxy: "3000".into(),
            ..Default::default()
        };
        assert_eq!(
            plan_http_handler("/", &h),
            Ok(ServeTarget::Redirect {
                to: "/r".into(),
                status: 302
            })
        );
        // AcceptAppCaps only matters to a Proxy; with a Redirect winning it is ignored, as in Go.
        let h = HttpHandler {
            redirect: "/r".into(),
            accept_app_caps: vec!["example.com/cap/mon".into()],
            ..Default::default()
        };
        assert!(plan_http_handler("/", &h).is_ok());
    }

    #[test]
    fn proxy_backend_addresses() {
        for (proxy_arg, want) in [
            ("3000", "127.0.0.1:3000"),
            ("localhost:3000", "localhost:3000"),
            ("http://127.0.0.1:3000/", "127.0.0.1:3000"),
            ("http://[::1]:3000", "[::1]:3000"),
            ("http://localhost", "localhost:80"),
            ("http://[::1]", "[::1]:80"),
            ("localhost:", "localhost:80"),
        ] {
            let st = https_on(443, handlers(&[("/", proxy(proxy_arg))]));
            let plan = st.serve_plan().unwrap();
            let ServeTarget::Path { handlers } = &plan[&443].target else {
                panic!("not a path mux");
            };
            assert_eq!(
                handlers["/"],
                ServeTarget::Proxy { to: want.into() },
                "{proxy_arg:?}"
            );
        }
        for (proxy_arg, unsupported) in [
            ("https://localhost:3000", true),
            ("https+insecure://localhost:3000", true),
            ("unix:/run/app.sock", true),
            ("http://localhost:3000/app", true),
            ("http://localhost:3000?x=1", true),
            ("http://user@localhost:3000", false),
            ("http://localhost:99999", false),
            ("http://a:b:c", false),
            ("http://", false),
        ] {
            let st = https_on(443, handlers(&[("/", proxy(proxy_arg))]));
            let err = st.serve_plan().unwrap_err();
            assert_eq!(
                matches!(err, ServeConfigError::Unsupported(_)),
                unsupported,
                "{proxy_arg:?}: {err}"
            );
            assert!(
                unsupported || matches!(err, ServeConfigError::Invalid(_)),
                "{proxy_arg:?}: {err}"
            );
        }
    }

    #[test]
    fn refuses_what_the_runtime_would_serve_differently_from_go() {
        let refused = [
            ("plain HTTP", tcp(&[(80, http())])),
            (
                "TerminateTLS",
                tcp(&[(
                    5432,
                    TcpPortHandler {
                        tcp_forward: "127.0.0.1:5432".into(),
                        terminate_tls: NAME.into(),
                        ..Default::default()
                    },
                )]),
            ),
            (
                "ProxyProtocol",
                tcp(&[(
                    5432,
                    TcpPortHandler {
                        tcp_forward: "127.0.0.1:5432".into(),
                        proxy_protocol: 1,
                        ..Default::default()
                    },
                )]),
            ),
            ("unix forward", tcp(&[(5432, forward("unix:/run/pg.sock"))])),
            ("HTTPS without Web", tcp(&[(443, https())])),
            ("HTTPS with no handlers", https_on(443, handlers(&[]))),
            (
                "Text",
                https_on(
                    443,
                    handlers(&[(
                        "/",
                        HttpHandler {
                            text: "hi".into(),
                            ..Default::default()
                        },
                    )]),
                ),
            ),
            (
                "templated Redirect",
                https_on(
                    443,
                    handlers(&[("/", redirect("https://${HOST}/new${REQUEST_URI}"))]),
                ),
            ),
            (
                "Path",
                https_on(
                    443,
                    handlers(&[(
                        "/",
                        HttpHandler {
                            path: "/srv/www".into(),
                            ..Default::default()
                        },
                    )]),
                ),
            ),
            (
                "Proxy below /",
                https_on(443, handlers(&[("/api", proxy("3000"))])),
            ),
            (
                "Proxy with AcceptAppCaps",
                https_on(
                    443,
                    handlers(&[(
                        "/",
                        HttpHandler {
                            proxy: "3000".into(),
                            accept_app_caps: vec!["example.com/cap/mon".into()],
                            ..Default::default()
                        },
                    )]),
                ),
            ),
            (
                "empty handler",
                https_on(443, handlers(&[("/", HttpHandler::default())])),
            ),
            (
                "Services",
                with_services(&[(
                    "svc:db",
                    svc(&[(5432, forward("127.0.0.1:5432"))], false, false),
                )]),
            ),
            (
                "Foreground",
                with_foreground("12345", tcp(&[(5432, forward("127.0.0.1:5432"))])),
            ),
            ("AllowFunnel", {
                let mut st = https_on(443, handlers(&[("/", proxy("3000"))]));
                st.allow_funnel.insert(hp(443), true);
                st
            }),
        ];
        for (what, st) in refused {
            assert!(
                unsupported(&st),
                "{what} must be refused: {:?}",
                st.serve_plan()
            );
        }

        // Two SNI names on one HTTPS port.
        let mut st = https_on(443, handlers(&[("/", proxy("3000"))]));
        st.web.insert(
            HostPort::new("other.tail1.ts.net", 443),
            handlers(&[("/", proxy("3001"))]),
        );
        assert!(unsupported(&st));

        // An AllowFunnel entry that is off is not Funnel being on.
        let mut st = https_on(443, handlers(&[("/", proxy("3000"))]));
        st.allow_funnel.insert(hp(443), false);
        assert!(st.serve_plan().is_ok());
    }

    #[test]
    fn web_entries_for_other_ports_are_ignored() {
        // Go only consults a Web entry when its port's TCP handler is HTTP/HTTPS.
        let mut st = tcp(&[(5432, forward("127.0.0.1:5432"))]);
        st.web
            .insert(hp(8443), handlers(&[("/", HttpHandler::default())]));
        st.web.insert(
            HostPort("not-a-hostport".into()),
            handlers(&[("/", HttpHandler::default())]),
        );
        assert_eq!(st.serve_plan().unwrap().len(), 1);
    }

    #[test]
    fn refuses_invalid_ports_names_and_redirects() {
        assert!(matches!(
            tcp(&[(0, forward("127.0.0.1:1"))]).serve_plan(),
            Err(ServeConfigError::Invalid(_))
        ));

        let mut st = https_on(443, handlers(&[("/", proxy("3000"))]));
        let web = st.web.remove(&hp(443)).unwrap();
        st.web.insert(HostPort::new("example.com", 443), web);
        assert_eq!(
            st.serve_plan(),
            Err(ServeConfigError::NotTailnetName("example.com".into()))
        );

        // A CR/LF in a redirect target would split the `Location:` response header.
        for bad in [
            "https://host.tail1.ts.net/\r\nSet-Cookie: evil=1",
            "301:/x\ny",
            "/\r",
        ] {
            let st = https_on(443, handlers(&[("/", redirect(bad))]));
            assert!(
                matches!(st.serve_plan(), Err(ServeConfigError::Invalid(_))),
                "{bad:?}"
            );
        }
        // `301:` with nothing after it is a redirect to the empty string.
        let st = https_on(443, handlers(&[("/", redirect("301:"))]));
        assert!(matches!(st.serve_plan(), Err(ServeConfigError::Invalid(_))));
    }
}
