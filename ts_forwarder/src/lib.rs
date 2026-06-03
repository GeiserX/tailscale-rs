//! Inbound subnet-router / exit-node forwarding dataplane.
//!
//! This crate implements the tsnet-style inbound forwarder: it accepts flows arriving over the
//! Tailscale overlay that are addressed to destinations this node advertised (subnet prefixes,
//! or `0.0.0.0/0` for an exit node) and splices them to real OS sockets — mirroring gVisor's
//! TCP/UDP forwarders in Go `tsnet`. Like `tsnet`, it does not perform IP routing; it accepts
//! netstack flows and dials corresponding real sockets.
//!
//! # Anti-leak posture
//!
//! Every overlay flow becomes a real OS socket in exactly one place — the [`RealDialer`] trait.
//! The default [`DirectDialer`] dials real sockets bound to `0.0.0.0:0` (never `::`; IPv6 is
//! disabled everywhere) for subnet routes and **structurally refuses** exit-node egress. There
//! is no flag that turns exit egress on in `DirectDialer`; egressing a peer's traffic via our
//! real IP requires substituting a different, explicitly-wired dialer. This makes "the real
//! origin IP never silently leaks" a type-level fact.
//!
//! # All-port forwarding and the smoltcp-0.13.1 constraint
//!
//! smoltcp 0.13.1 has **no single-socket all-port accept**. Concretely (verified against the
//! vendored smoltcp source):
//! - `socket/tcp.rs:931` — `Socket::listen` returns `Unaddressable` for `port == 0`, so a TCP
//!   listener cannot bind a wildcard port.
//! - `socket/tcp.rs:1549-1553` — `Socket::accepts` (the iface's per-socket dispatch test)
//!   wildcards only the destination *address* when `listen_endpoint.addr == None` (this is the
//!   any-IP path); it still requires `dst_port == listen_endpoint.port` exactly. No wildcard port.
//! - `iface/interface/tcp.rs:36-56` — `process_tcp` walks the existing sockets and, if none
//!   `accepts()` the SYN, synchronously emits a TCP RST inside the ingress poll loop. There is
//!   no callback to dynamically create a listener for an unmatched port before the RST goes out,
//!   so an "on-demand listener driven by the SYN's port" cannot observe the port in time.
//! - UDP `bind` likewise rejects port 0.
//!
//! Eagerly opening one listener per port across the full `1..=65535` range would be correct but
//! unusable: smoltcp scans every socket in `accepts()` per inbound packet, so 65535 listeners
//! make every packet `O(65535)`. Instead, [`Forwarder::all_ports`] (and [`PortSpec::All`]) use
//! an **on-demand** listener manager (see [`all_port`]): a raw `(Ipv4, Tcp)` socket both
//! suppresses smoltcp's unmatched-SYN RST (a raw socket that `accepts()` a packet sets
//! `handled_by_raw_socket`, and `process_tcp` then returns `None` instead of `rst_reply`) and
//! reveals each new destination port; a per-port any-IP listener is started the first time a
//! port is seen, and the peer's SYN retransmit is then accepted and spliced through the
//! unchanged accept → classify → dial loop. UDP is handled analogously via a raw `(Ipv4, Udp)`
//! observer. Steady-state socket count is the number of *active* ports, not the full range.
//! This achieves all-port coverage; the residual costs are the raw observer copying inbound
//! packets and the one-RTT setup latency on a port's first flow.
//!
//! All-port mode does **not** change the anti-leak posture: [`PortSpec::All`] routes every
//! accepted flow through the *same* [`RouteTable`] classification and the *same* [`RealDialer`]
//! chokepoint as the per-port path. An all-port exit-node (`0.0.0.0/0`) flow under the default
//! [`DirectDialer`] is still structurally refused at dial time — opening every port does not
//! open a leak.

#![forbid(unsafe_code)]

pub mod all_port;
mod class;
mod dialer;
mod forwarder;
mod tcp;
mod udp;

pub use class::{FlowClass, RouteTable};
pub use dialer::{DialError, DialedUdp, DirectDialer, HostExitDialer, RealDialer};
pub use forwarder::{Forwarder, PortSpec, RouteUpdater};
