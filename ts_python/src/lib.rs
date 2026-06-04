#![doc = include_str!("../README.md")]

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Once},
    time::Duration,
};

use pyo3::{exceptions::PyValueError, prelude::*};
use pyo3_async_runtimes::tokio::future_into_py;
use tracing_subscriber::filter::LevelFilter;

use crate::ip_or_str::IpRepr;

extern crate tailscale as ts;

type PyFut<'p> = PyResult<Bound<'p, PyAny>>;

mod ip_or_str;
mod key_state;
mod node_info;
mod serve;
mod status;
mod tcp;
mod udp;

use key_state::Keystate;
use node_info::NodeInfo;
use serve::ServeConfigArg;
use status::{Status, WhoIs};

/// Tailscale API.
#[pymodule]
pub mod _internal {
    use super::*;
    #[pymodule_export]
    use crate::{
        Device, Keystate,
        tcp::{TcpListener, TcpStream},
        udp::UdpSocket,
    };

    /// Connect to tailscale using the specified parameters.
    ///
    /// The forwarding/routing keyword arguments mirror `tailscale.Config`:
    ///
    /// - `accept_routes` (bool): accept and route to subnet routes peers advertise.
    /// - `exit_node` (str): route internet-bound traffic through this peer (IP or MagicDNS name).
    /// - `advertise_routes` (list[str]): CIDRs to advertise as a subnet router.
    /// - `advertise_exit_node` (bool): advertise this node as an exit node.
    /// - `forward_tcp_ports` / `forward_udp_ports` (list[int]): ports the inbound forwarder splices.
    /// - `forward_all_ports` (bool): forward every TCP/UDP port on advertised routes.
    /// - `forward_exit_egress` (bool): actually egress exit-node flows via this host's real IP.
    #[pyfunction]
    #[pyo3(signature = (
        key_file_path=None, /, auth_key=None, *, control_server_url=None, hostname=None, tags=None, keys=None,
        accept_routes=None, exit_node=None, advertise_routes=None, advertise_exit_node=None,
        forward_tcp_ports=None, forward_udp_ports=None, forward_all_ports=None, forward_exit_egress=None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        py: Python<'_>,
        key_file_path: Option<String>,
        auth_key: Option<String>,
        control_server_url: Option<String>,
        hostname: Option<String>,
        tags: Option<Vec<String>>,
        keys: Option<Keystate>,
        accept_routes: Option<bool>,
        exit_node: Option<String>,
        advertise_routes: Option<Vec<String>>,
        advertise_exit_node: Option<bool>,
        forward_tcp_ports: Option<Vec<u16>>,
        forward_udp_ports: Option<Vec<u16>>,
        forward_all_ports: Option<bool>,
        forward_exit_egress: Option<bool>,
    ) -> PyFut<'_> {
        static TRACING_ONCE: Once = Once::new();
        TRACING_ONCE.call_once(|| {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                )
                .init();
        });

        future_into_py(py, async move {
            let mut config = if let Some(key_file_path) = key_file_path {
                ts::Config::default_with_key_file(key_file_path)
                    .await
                    .map_err(py_value_err)?
            } else {
                ts::Config::default()
            };

            config.client_name = Some("ts_python".to_owned());
            if let Some(control_server_url) = control_server_url {
                config.control_server_url = control_server_url.parse().map_err(py_value_err)?;
            }

            if let Some(hostname) = hostname {
                config.requested_hostname = Some(hostname);
            }

            if let Some(tags) = tags {
                config.requested_tags = tags;
            }

            if let Some(keys) = &keys {
                config.key_state = keys.try_into().map_err(|_| py_value_err("invalid keys"))?;
            }

            if let Some(accept_routes) = accept_routes {
                config.accept_routes = accept_routes;
            }

            if let Some(exit_node) = exit_node {
                // `ExitNodeSelector::from_str` is infallible (non-IP strings become MagicDNS
                // names), matching the Go CLI's `--exit-node`.
                config.exit_node = Some(exit_node.parse().map_err(py_value_err)?);
            }

            if let Some(advertise_routes) = advertise_routes {
                config.advertise_routes = advertise_routes
                    .iter()
                    .map(|cidr| cidr.parse())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(py_value_err)?;
            }

            if let Some(advertise_exit_node) = advertise_exit_node {
                config.advertise_exit_node = advertise_exit_node;
            }

            if let Some(forward_tcp_ports) = forward_tcp_ports {
                config.forward_tcp_ports = forward_tcp_ports;
            }

            if let Some(forward_udp_ports) = forward_udp_ports {
                config.forward_udp_ports = forward_udp_ports;
            }

            if let Some(forward_all_ports) = forward_all_ports {
                config.forward_all_ports = forward_all_ports;
            }

            if let Some(forward_exit_egress) = forward_exit_egress {
                config.forward_exit_egress = forward_exit_egress;
            }

            let dev = ts::Device::new(&config, auth_key)
                .await
                .map_err(py_value_err)?;

            Ok(Device { dev: Arc::new(dev) })
        })
    }
}

/// Tailscale client.
#[pyclass(frozen, module = "tailscale")]
pub struct Device {
    dev: Arc<ts::Device>,
}

#[pymethods]
impl Device {
    /// Bind a new UDP socket on the given `addr`.
    ///
    /// `addr` must be given as (host, port). Presently, `host` must be an IP.
    pub fn udp_bind<'p>(&self, py: Python<'p>, addr: (IpRepr, u16)) -> PyFut<'p> {
        let dev = self.dev.clone();
        let ip: Result<IpAddr, _> = addr.0.try_into();

        future_into_py(py, async move {
            let ip = ip?;

            let sock = dev
                .udp_bind((ip, addr.1).into())
                .await
                .map_err(py_value_err)?;

            Ok(udp::UdpSocket {
                sock: Arc::new(sock),
            })
        })
    }

    /// Bind a new TCP listen socket on the given `addr` and `port`.
    ///
    /// `addr` must be given as (host, port). Presently, `host` must be an IP.
    pub fn tcp_listen<'p>(&self, py: Python<'p>, addr: (IpRepr, u16)) -> PyFut<'p> {
        let dev = self.dev.clone();
        let ip: Result<IpAddr, _> = addr.0.try_into();

        future_into_py(py, async move {
            let ip = ip?;

            let listener = dev
                .tcp_listen((ip, addr.1).into())
                .await
                .map_err(py_value_err)?;

            Ok(tcp::TcpListener {
                listener: Arc::new(listener),
            })
        })
    }

    /// Create a new TCP connection to the given `addr`.
    ///
    /// `addr` must be given as (host, port). Presently, `host` must be an IP.
    pub fn tcp_connect<'p>(&self, py: Python<'p>, addr: (IpRepr, u16)) -> PyFut<'p> {
        let dev = self.dev.clone();
        let ip: Result<IpAddr, _> = addr.0.try_into();

        future_into_py(py, async move {
            let ip = ip?;

            let sock = dev
                .tcp_connect((ip, addr.1).into())
                .await
                .map_err(|e| PyValueError::new_err(e.to_string()))?;

            Ok(tcp::TcpStream {
                sock: Arc::new(sock),
            })
        })
    }

    /// Get the device's IPv4 tailnet address.
    pub fn ipv4_addr<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = dev.ipv4_addr().await.map_err(py_value_err)?;
            Ok(ip)
        })
    }

    /// Get the device's IPv6 tailnet address.
    pub fn ipv6_addr<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = dev.ipv6_addr().await.map_err(py_value_err)?;
            Ok(ip)
        })
    }

    /// Look up info about a peer by its name.
    ///
    /// `name` may be an unqualified hostname or a fully-qualified name.
    pub fn peer_by_name<'p>(&self, py: Python<'p>, name: String) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let node = dev.peer_by_name(&name).await.map_err(py_value_err)?;

            Ok(node.map(|node| NodeInfo::from(&node)))
        })
    }

    /// Get this device's node info.
    pub fn self_node<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let node = dev.self_node().await.map_err(py_value_err)?;
            Ok(NodeInfo::from(&node))
        })
    }

    /// Look up a peer by its tailnet IP address.
    pub fn peer_by_tailnet_ip<'p>(&self, py: Python<'p>, ip: IpRepr) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = ip.try_into().map_err(py_value_err)?;
            let node = dev.peer_by_tailnet_ip(ip).await.map_err(py_value_err)?;

            Ok(node.map(|node| NodeInfo::from(&node)))
        })
    }

    /// Look up peer(s) with the most specific route match for the given address.
    ///
    /// If more than one peer has the same route covering the same address, more than one
    /// result may be returned.
    pub fn peers_with_route<'p>(&self, py: Python<'p>, ip: IpRepr) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = ip.try_into().map_err(py_value_err)?;
            let nodes = dev.peers_with_route(ip).await.map_err(py_value_err)?;

            Ok(nodes
                .into_iter()
                .map(|node| NodeInfo::from(&node))
                .collect::<Vec<_>>())
        })
    }

    // --- Lane 1: Status / WhoIs / netmap snapshot ---

    /// Snapshot of this device and its tailnet peers (like `tailscale status`).
    ///
    /// Returns a dict `{"self_node": <node>|None, "peers": [<node>, ...]}` where each node carries
    /// `stable_id`, `display_name`, `ipv4`, `ipv6`, `online`, `allowed_routes`, and `is_exit_node`.
    pub fn status<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let status = dev.status().await.map_err(py_value_err)?;
            Ok(Status::from(&status))
        })
    }

    /// Map a tailnet source `addr` to the node that owns its IP (like `tsnet`'s `WhoIs`).
    ///
    /// `addr` may be an `ip` or `host:port` string; only the IP is used. Returns `None` if no
    /// tailnet node owns that address.
    pub fn whois<'p>(&self, py: Python<'p>, addr: String) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let socket_addr = parse_whois_addr(&addr)?;
            let whois = dev.whois(socket_addr).await.map_err(py_value_err)?;
            Ok(whois.as_ref().map(WhoIs::from))
        })
    }

    /// One-shot snapshot of the current netmap peers (the current value of the netmap watch).
    ///
    /// Returns the list of peer nodes as of now, in the same shape as `status()["peers"]`. Mirrors
    /// reading the current value off `tsnet`'s `WatchIPNBus` subscription.
    pub fn netmap<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let rx = dev.watch_netmap().await.map_err(py_value_err)?;
            let nodes = rx.borrow();
            Ok(nodes
                .iter()
                .map(status::StatusNode::from)
                .collect::<Vec<_>>())
        })
    }

    // --- Lane 2: MagicDNS ---

    /// Resolve a tailnet peer (or this node) by MagicDNS `name` to its tailnet IPv4 address.
    ///
    /// Returns the IPv4 address as a string, or `None` if no tailnet node has that name. This is an
    /// in-process netmap lookup — it does not query any DNS server. IPv6 is not resolved (this fork
    /// is IPv4-only on the tailnet).
    pub fn resolve<'p>(&self, py: Python<'p>, name: String) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = dev.resolve(&name).await.map_err(py_value_err)?;
            Ok(ip.map(|ip| ip.to_string()))
        })
    }

    /// Connect to a tailnet peer by MagicDNS `name` and `port` over TCP.
    ///
    /// Resolves `name` via [`Device::resolve`] (an in-process netmap lookup, no DNS server), then
    /// dials the resulting tailnet IPv4 address. Raises if the name does not resolve to a tailnet
    /// node. Returns the same `TcpStream` as `tcp_connect`.
    pub fn connect_by_name<'p>(&self, py: Python<'p>, name: String, port: u16) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let sock = dev
                .connect_by_name(&name, port)
                .await
                .map_err(py_value_err)?;

            Ok(tcp::TcpStream {
                sock: Arc::new(sock),
            })
        })
    }

    // --- Lane 4: Ping ---

    /// Ping a tailnet peer over the overlay with an ICMPv4 echo (like `tailscale ping`).
    ///
    /// `addr` is the peer's tailnet IP; `timeout_ms` is the timeout in milliseconds. Returns the
    /// round-trip time in milliseconds (a float), or raises on timeout / unsupported IPv6
    /// destination. The echo is sent from this device's own tailnet IPv4 over the overlay netstack
    /// — never a host socket.
    pub fn ping<'p>(&self, py: Python<'p>, addr: IpRepr, timeout_ms: u64) -> PyFut<'p> {
        let dev = self.dev.clone();
        let ip: Result<IpAddr, _> = addr.try_into();

        future_into_py(py, async move {
            let ip = ip?;
            let rtt = dev
                .ping(ip, Duration::from_millis(timeout_ms))
                .await
                .map_err(py_value_err)?;
            Ok(rtt.as_secs_f64() * 1000.0)
        })
    }

    // --- Lane 5: TLS / Serve ---

    /// Obtain a TLS certificate for a node's MagicDNS `name` (like `tsnet`'s `GetCertificate`).
    ///
    /// **Fail-closed.** This fork has no client-side ACME engine and no `set-dns` RPC, so this
    /// ALWAYS raises a Python exception carrying the underlying `CertError` (issuance is
    /// unimplemented). It NEVER self-signs and NEVER returns a placeholder certificate. When ACME
    /// issuance lands upstream, this starts succeeding with no API change.
    pub fn get_certificate<'p>(&self, py: Python<'p>, name: String) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            // Always Err(CertError::Unimplemented) today; propagate it faithfully, never swallow.
            dev.get_certificate(&name).await.map_err(py_value_err)?;
            Ok(())
        })
    }

    /// Build a TLS listener config for `serve_config` on the overlay (like `tsnet`'s `ListenTLS`).
    ///
    /// `serve_config` is a mapping `{"name": str, "port": int, "target": <target>}` where `target`
    /// is `"accept"` or `{"proxy": "host:port"}`.
    ///
    /// **Fail-closed.** Delegates to [`Device::get_certificate`]; because no real certificate can be
    /// issued in this fork, this ALWAYS raises the same `CertError` rather than ever serving a
    /// self-signed cert or downgrading to plaintext. The serve config is validated first, so an
    /// off-tailnet name / zero port / empty proxy target raises a distinct error.
    pub fn listen_tls<'p>(&self, py: Python<'p>, serve_config: ServeConfigArg) -> PyFut<'p> {
        let dev = self.dev.clone();
        let cfg = serve_config.0;

        future_into_py(py, async move {
            // Always Err(CertError) today; propagate it faithfully, never swallow.
            dev.listen_tls(&cfg).await.map_err(py_value_err)?;
            Ok(())
        })
    }
}

/// Parse a WhoIs `addr` argument: a bare IP or an `ip:port`/`[ip6]:port` string. Only the IP
/// matters to `whois`; a bare IP is given port 0.
fn parse_whois_addr(addr: &str) -> PyResult<SocketAddr> {
    if let Ok(sock) = addr.parse::<SocketAddr>() {
        return Ok(sock);
    }
    let ip: IpAddr = addr.parse().map_err(py_value_err)?;
    Ok(SocketAddr::new(ip, 0))
}

fn sockaddr_as_tuple(s: SocketAddr) -> (IpAddr, u16) {
    (s.ip(), s.port())
}

fn py_value_err(e: impl ToString) -> PyErr {
    PyValueError::new_err(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whois_addr_accepts_bare_ip() {
        let sock = parse_whois_addr("100.64.0.7").unwrap();
        assert_eq!(sock.ip(), "100.64.0.7".parse::<IpAddr>().unwrap());
        assert_eq!(sock.port(), 0);
    }

    #[test]
    fn whois_addr_accepts_ip_port() {
        let sock = parse_whois_addr("100.64.0.7:443").unwrap();
        assert_eq!(sock.ip(), "100.64.0.7".parse::<IpAddr>().unwrap());
        assert_eq!(sock.port(), 443);
    }

    #[test]
    fn whois_addr_rejects_garbage() {
        assert!(parse_whois_addr("not-an-ip").is_err());
    }
}
