//! [`GatewayCap`]: the validated gateway capability, and the only module in this crate that
//! creates sockets or sends.
//!
//! A `GatewayCap` is built once per network generation from a [`Gateway`] and re-checks it:
//! private gateway and self address, an on-link prefix of length 8 to 31, and a usable interface
//! (up, not loopback, not point-to-point) that holds `self_ip/prefix`. Every exchange uses a fresh
//! UDP socket with `SO_DONTROUTE` (the kernel refuses a destination that is not directly
//! connected), bound to `self_ip:0` and to the interface (`IP_BOUND_IF` on macOS,
//! `SO_BINDTODEVICE` on Linux), sends only to `gateway:5351` ([`LanDest::Pxp`]; no API takes an
//! address), checks the [`PolicyHandle`] and the cap's own validity before **every** send, and
//! accepts only datagrams whose source is exactly `gateway:5351`.
//!
//! Without interface binding ([`BindMode::SourceIp`]: Linux without permission for
//! `SO_BINDTODEVICE`, other platforms) the egress interface is whatever the kernel's full policy
//! routing picks, which can be a tunnel (a VPN, or a Tailscale subnet route covering the LAN). So
//! that mode needs a gateway lookup, and the cap requires, at build time and before every send,
//! that the lookup still reports the same gateway **and** that the kernel's own source selection
//! for the gateway is `self_ip`.
//!
//! Residual risk, by design: NAT-PMP is unauthenticated, so an on-LAN spoofer can fake service
//! availability, force failures and churn, or report a false external address. PCP nonces stop
//! off-path spoofing only. Mitigations here: bounded parse work (at most [`MAX_EXAMINED`]
//! datagrams per exchange), an absolute deadline that junk cannot extend, and a request target
//! that is always our own `self_ip` and port, never chosen by a reply.

use std::{
    fmt,
    future::Future,
    io,
    net::{SocketAddr, SocketAddrV4},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::time::Instant;

use crate::{
    PXP_PORT,
    gateway::{
        Gateway, GatewayLookup, IfInfo, LAN_PREFIX_LENS, interfaces, is_private, kernel_source,
        prefix_contains,
    },
};

/// The kernel's preferred source address for a destination (see [`kernel_source`]).
type KernelSource = Arc<dyn Fn(std::net::Ipv4Addr) -> Option<std::net::Ipv4Addr> + Send + Sync>;

/// Go's per-exchange budget (`portMapServiceTimeout`): an absolute deadline, never extended.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_millis(250);
/// Most datagrams examined in one exchange, whatever their source or content.
pub const MAX_EXAMINED: usize = 64;
/// Receive buffer: the PCP maximum of 1100 bytes plus one, so a datagram that fills it is known
/// to be oversize (truncated) and is dropped.
pub const RECV_BUF: usize = crate::pcp::MAX_LEN + 1;

/// Where a LAN packet may go. Phases 0–1 allow exactly one destination.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanDest {
    /// The gateway's NAT-PMP/PCP port, `gateway:5351`.
    Pxp,
}

#[derive(Debug)]
struct PolicyInner {
    /// Serializes final gate checks + one nonblocking send against disable/invalidation.
    /// Never held across readiness, route lookup, socket construction or any await.
    send: Mutex<()>,
    lan_sends: AtomicBool,
}

/// Whether LAN sends are allowed right now. Shared between the owner (which flips it, for example
/// on `only-tcp-443`) and every cap, which checks it before each send.
#[derive(Debug, Clone)]
pub struct PolicyHandle(Arc<PolicyInner>);

impl PolicyHandle {
    /// A policy that starts with LAN sends allowed or not.
    pub fn new(lan_sends_allowed: bool) -> Self {
        Self(Arc::new(PolicyInner {
            send: Mutex::new(()),
            lan_sends: AtomicBool::new(lan_sends_allowed),
        }))
    }

    /// Whether LAN sends are allowed.
    pub fn lan_sends_allowed(&self) -> bool {
        self.0.lan_sends.load(Ordering::SeqCst)
    }

    /// Allow or forbid LAN sends; takes effect at the next send of every cap sharing this handle.
    pub fn set_lan_sends_allowed(&self, allowed: bool) {
        let _permit = self.send_permit();
        self.0.lan_sends.store(allowed, Ordering::SeqCst);
    }

    fn send_permit(&self) -> MutexGuard<'_, ()> {
        self.0
            .send
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A network generation: bumped whenever the gateway identity changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NetGen(pub u64);

/// How a cap's sockets are tied to the gateway's interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindMode {
    /// macOS `IP_BOUND_IF`, plus the source address.
    IfScope,
    /// Linux `SO_BINDTODEVICE`, plus the source address.
    Device,
    /// Source address only (Linux without permission for `SO_BINDTODEVICE`, other platforms),
    /// with the gateway revalidated before each send when a lookup is available.
    SourceIp,
    /// The loopback test transport.
    LoopbackTest,
}

impl fmt::Display for BindMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::IfScope => "ifscope",
            Self::Device => "device",
            Self::SourceIp => "source-ip",
            Self::LoopbackTest => "loopback-test",
        })
    }
}

/// Why a send was refused before touching a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The policy forbids LAN sends.
    Policy,
    /// The cap was invalidated (network change, close).
    Invalidated,
    /// The owner is closing.
    Closing,
    /// The gateway no longer revalidates (source-IP bind mode).
    NetworkChanged,
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Policy => "policy forbids LAN sends",
            Self::Invalidated => "capability invalidated",
            Self::Closing => "closing",
            Self::NetworkChanged => "gateway no longer validates",
        })
    }
}

/// A capability error. I/O errors are kept verbatim (errno name, number and message), so that,
/// for example, macOS Local Network privacy (`EHOSTUNREACH`/`EPERM`) is diagnosable.
#[derive(Debug, thiserror::Error)]
pub enum CapError {
    /// The send was refused before any socket was touched.
    #[error("LAN send denied: {0}")]
    Denied(DenyReason),
    /// The gateway failed validation.
    #[error("gateway rejected: {0}")]
    InvalidGateway(&'static str),
    /// A refused probe-listener port.
    #[error("port {0} is reserved for the node; pick another test port")]
    ReservedPort(u16),
    /// No tokio runtime to register the socket with.
    #[error("no tokio runtime")]
    NoRuntime,
    /// An OS error, verbatim.
    #[error("{op}: {}{detail}", errno_label(*.raw_os_error))]
    Io {
        /// What was being done: `socket`, `bind`, `bind-interface`, `send`, `recv`.
        op: &'static str,
        /// The error kind.
        kind: io::ErrorKind,
        /// The raw OS error number, if any.
        raw_os_error: Option<i32>,
        /// The OS error message.
        detail: String,
    },
}

impl CapError {
    /// Wrap an I/O error from `op`, keeping it verbatim.
    pub fn io(op: &'static str, e: &io::Error) -> Self {
        Self::Io {
            op,
            kind: e.kind(),
            raw_os_error: e.raw_os_error(),
            detail: e.to_string(),
        }
    }
}

/// `"EHOSTUNREACH: "` for well-known errno values, else empty.
fn errno_label(raw: Option<i32>) -> String {
    raw.and_then(errno_name)
        .map(|n| format!("{n}: "))
        .unwrap_or_default()
}

/// Symbolic names for the errno values a LAN send can plausibly hit.
pub fn errno_name(code: i32) -> Option<&'static str> {
    #[cfg(unix)]
    {
        let names = [
            (libc::EPERM, "EPERM"),
            (libc::EACCES, "EACCES"),
            (libc::EHOSTUNREACH, "EHOSTUNREACH"),
            (libc::ENETUNREACH, "ENETUNREACH"),
            (libc::EHOSTDOWN, "EHOSTDOWN"),
            (libc::ENETDOWN, "ENETDOWN"),
            (libc::EADDRNOTAVAIL, "EADDRNOTAVAIL"),
            (libc::EADDRINUSE, "EADDRINUSE"),
            (libc::ECONNREFUSED, "ECONNREFUSED"),
            (libc::ENOBUFS, "ENOBUFS"),
            (libc::ENXIO, "ENXIO"),
            (libc::ENODEV, "ENODEV"),
        ];
        names.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
    }
    #[cfg(not(unix))]
    {
        let _ = code;
        None
    }
}

/// Tells an exchange whether to keep receiving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep receiving until the deadline.
    Continue,
    /// Stop: the reply (or replies) this exchange waited for arrived.
    Done,
}

/// What happened during one exchange.
#[derive(Debug)]
pub struct ExchangeStats {
    /// Datagrams received and looked at (all sources).
    pub examined: usize,
    /// Datagrams dropped because their source was not exactly `gateway:5351`.
    pub wrong_source: usize,
    /// Datagrams dropped because they filled the receive buffer (truncated).
    pub oversize: usize,
    /// The reply handler returned [`Flow::Done`].
    pub done: bool,
    /// The exchange stopped at [`MAX_EXAMINED`].
    pub hit_cap: bool,
    /// The absolute deadline the exchange ran against.
    pub deadline: Instant,
    /// A receive error that ended the exchange, verbatim.
    pub recv_error: Option<CapError>,
}

/// Per-MAP evidence shared with the lifecycle reservation, including after cancellation.
/// Constructed internally; only the sealed transports can record a syscall attempt. The
/// NAT-PMP public-address request does not count as a MAP. Socket/route/permit failures do not
/// record evidence. Once recorded, evidence is never cleared, even when the syscall fails.
#[derive(Debug)]
pub struct SendEvidence {
    map_index: usize,
    logical_origin: Instant,
    runtime_origin: Instant,
    attempted_ns: AtomicU64,
}

impl SendEvidence {
    pub(crate) fn new(map_index: usize, now: Instant) -> Self {
        Self {
            map_index,
            logical_origin: now,
            runtime_origin: Instant::now(),
            attempted_ns: AtomicU64::new(0),
        }
    }

    pub(crate) fn enter(&self, index: usize) {
        if index == self.map_index {
            let elapsed = Instant::now().saturating_duration_since(self.runtime_origin);
            // Zero means never attempted. Retrying a WouldBlock must advance the possible
            // grant from the latest attempt, even when an earlier attempt already marked it.
            let ns = elapsed.as_nanos().min(u128::from(u64::MAX - 1)) as u64;
            self.attempted_ns.fetch_max(ns + 1, Ordering::SeqCst);
        }
    }

    pub(crate) fn possible_until(&self) -> Option<Instant> {
        let ns = self.attempted_ns.load(Ordering::SeqCst).checked_sub(1)?;
        let elapsed = Duration::from_nanos(ns);
        let logical = self
            .logical_origin
            .checked_add(elapsed)
            .unwrap_or(self.logical_origin);
        let runtime = self
            .runtime_origin
            .checked_add(elapsed)
            .unwrap_or(self.runtime_origin);
        // An unanswered MAP's possible grant is bounded by the requested lifetime: a NAT-PMP
        // gateway SHOULD NOT grant longer than requested (RFC 6886 §3.3). Go trusts no
        // unanswered MAP at all (net/portmapper/portmapper.go:394-411), so this is already
        // stricter than Go, and a tombstone for a network we left cannot hold its slot for ever.
        Some(crate::oneshot::lease_deadline(
            logical.max(runtime),
            crate::schedule::REQUESTED_LIFETIME,
        ))
    }
}

/// The checks every send passes first.
pub(crate) struct SendGate {
    policy: PolicyHandle,
    valid: AtomicBool,
    closing: AtomicBool,
    revalidate: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}

impl SendGate {
    pub(crate) fn new(
        policy: PolicyHandle,
        revalidate: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    ) -> Self {
        Self {
            policy,
            valid: AtomicBool::new(true),
            closing: AtomicBool::new(false),
            revalidate,
        }
    }

    pub(crate) fn check(&self) -> Result<(), CapError> {
        if !self.policy.lan_sends_allowed() {
            return Err(CapError::Denied(DenyReason::Policy));
        }
        if !self.valid.load(Ordering::SeqCst) {
            return Err(CapError::Denied(DenyReason::Invalidated));
        }
        if self.closing.load(Ordering::SeqCst) {
            return Err(CapError::Denied(DenyReason::Closing));
        }
        Ok(())
    }

    /// OS route checks run off the async worker. Cancellation leaves bounded OS work behind,
    /// and the atomic policy/generation gate is rechecked after the result arrives.
    pub(crate) async fn check_async(&self, deadline: Instant) -> Result<(), CapError> {
        self.check()?;
        if let Some(revalidate) = self.revalidate.clone() {
            let valid =
                tokio::time::timeout_at(deadline, crate::blocking::run(move || revalidate()))
                    .await
                    .map_err(|_| CapError::InvalidGateway("route validation timed out"))?;
            if valid != Some(true) {
                self.invalidate();
                return Err(CapError::Denied(DenyReason::NetworkChanged));
            }
        }
        self.check()
    }

    pub(crate) fn invalidate(&self) {
        let _permit = self.policy.send_permit();
        self.valid.store(false, Ordering::SeqCst);
    }

    pub(crate) fn set_closing(&self) {
        let _permit = self.policy.send_permit();
        self.closing.store(true, Ordering::SeqCst);
    }

    /// The only admitted send. Callers supply a nonblocking syscall; no await or socket/route
    /// setup is allowed under this permit. Invalidation/disable cannot return during the
    /// final check-to-syscall window.
    pub(crate) fn send(&self, send: impl FnOnce() -> io::Result<usize>) -> Result<usize, CapError> {
        #[cfg(test)]
        send_tests::before_send();
        let _permit = self.policy.send_permit();
        self.check()?;
        send().map_err(|e| CapError::io("send", &e))
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.valid.load(Ordering::SeqCst)
    }
}

/// Send `reqs` to `to` (each send gated), then receive until `on_reply` says [`Flow::Done`], the
/// absolute `deadline` passes, or [`MAX_EXAMINED`] datagrams were seen. Only datagrams whose
/// source, as presented by `present`, is exactly `expected` reach `on_reply`.
///
/// Shared by [`GatewayCap`] and the test transport, so the acceptance logic under test is the
/// production logic.
pub(crate) async fn exchange_on(
    sock: &tokio::net::UdpSocket,
    gate: &SendGate,
    to: SocketAddr,
    expected: SocketAddrV4,
    present: &(dyn Fn(SocketAddr) -> Option<SocketAddrV4> + Sync),
    reqs: &[&[u8]],
    deadline: Instant,
    on_reply: &mut (dyn FnMut(&[u8]) -> Flow + Send),
    evidence: Option<&SendEvidence>,
) -> Result<ExchangeStats, CapError> {
    for (index, req) in reqs.iter().enumerate() {
        loop {
            gate.check()?;
            tokio::time::timeout_at(deadline, sock.writable())
                .await
                .map_err(|_| CapError::io("send-ready", &io::Error::from(io::ErrorKind::TimedOut)))?
                .map_err(|e| CapError::io("send-ready", &e))?;
            // Source-IP revalidation follows readiness. Neither wait owns the send permit.
            gate.check_async(deadline).await?;
            let sent = gate.send(|| {
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                if let Some(evidence) = evidence {
                    evidence.enter(index);
                }
                sock.try_send_to(req, to)
            });
            match sent {
                Ok(_) => break,
                Err(CapError::Io {
                    kind: io::ErrorKind::WouldBlock,
                    ..
                }) => continue,
                Err(e) => return Err(e),
            }
        }
    }
    let mut stats = ExchangeStats {
        examined: 0,
        wrong_source: 0,
        oversize: 0,
        done: false,
        hit_cap: false,
        deadline,
        recv_error: None,
    };
    let mut buf = [0u8; RECV_BUF];
    loop {
        if stats.examined >= MAX_EXAMINED {
            stats.hit_cap = true;
            break;
        }
        let (n, src) = match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
            Err(_elapsed) => break,
            Ok(Err(e)) => {
                stats.recv_error = Some(CapError::io("recv", &e));
                break;
            }
            Ok(Ok(got)) => got,
        };
        stats.examined += 1;
        if n >= RECV_BUF {
            stats.oversize += 1;
            continue;
        }
        if present(src) != Some(expected) {
            stats.wrong_source += 1;
            continue;
        }
        if on_reply(&buf[..n]) == Flow::Done {
            stats.done = true;
            break;
        }
    }
    Ok(stats)
}

/// A receive-only UDP socket for the probe's hold window. It reports each datagram's length and
/// source; the payload is never exposed and nothing is ever sent from it.
#[derive(Debug)]
pub struct ProbeListener {
    sock: tokio::net::UdpSocket,
    port: u16,
    buf: Vec<u8>,
}

impl ProbeListener {
    pub(crate) fn new(sock: tokio::net::UdpSocket) -> Result<Self, CapError> {
        let port = sock
            .local_addr()
            .map_err(|e| CapError::io("bind", &e))?
            .port();
        Ok(Self {
            sock,
            port,
            buf: vec![0u8; 65536],
        })
    }

    /// The bound (nonzero) port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Wait for one datagram; returns its length and source.
    pub async fn recv(&mut self) -> Result<(usize, SocketAddr), CapError> {
        self.sock
            .recv_from(&mut self.buf)
            .await
            .map_err(|e| CapError::io("recv", &e))
    }
}

pub(crate) mod sealed {
    /// Only this crate's transports implement [`super::PxpTransport`].
    pub trait Sealed {}
}

/// The transport the one-shot client and probe run on: [`GatewayCap`] in production, `TestCap`
/// (feature `test-harness`) in tests. Sealed: no other implementation can exist.
pub trait PxpTransport: sealed::Sealed + Send + Sync {
    /// The gateway this transport talks to.
    fn gateway(&self) -> &Gateway;

    /// How sockets are bound.
    fn bind_mode(&self) -> BindMode;

    /// Send `reqs` to `dest` from one fresh socket, then receive replies (see [`Flow`]) until the
    /// absolute `deadline`.
    fn exchange(
        &self,
        dest: LanDest,
        reqs: &[&[u8]],
        deadline: Instant,
        on_reply: &mut (dyn FnMut(&[u8]) -> Flow + Send),
    ) -> impl Future<Output = Result<ExchangeStats, CapError>> + Send {
        self.exchange_with_evidence(dest, reqs, deadline, on_reply, None)
    }

    /// The exchange implementation, optionally recording the MAP syscall boundary. Evidence
    /// is operation-scoped and must be recorded after all gates, immediately before the syscall.
    fn exchange_with_evidence(
        &self,
        dest: LanDest,
        reqs: &[&[u8]],
        deadline: Instant,
        on_reply: &mut (dyn FnMut(&[u8]) -> Flow + Send),
        evidence: Option<&SendEvidence>,
    ) -> impl Future<Output = Result<ExchangeStats, CapError>> + Send;

    /// One unacknowledged, non-blocking send (best-effort release from `Drop`; no runtime
    /// needed).
    fn send_nowait(&self, dest: LanDest, req: &[u8]) -> Result<(), CapError>;

    /// Bind the probe's dedicated receive-only test socket on `self_ip:port` (0 = ephemeral).
    /// Must be called within a tokio runtime.
    fn bind_probe_listener(&self, port: u16) -> Result<ProbeListener, CapError>;

    /// Refuse every later send.
    fn invalidate(&self);

    /// Whether sends are still possible (not invalidated).
    fn is_valid(&self) -> bool;
}

/// The validated gateway capability. See the module docs.
pub struct GatewayCap {
    gateway: Gateway,
    generation: NetGen,
    bind_mode: BindMode,
    gate: SendGate,
    /// Always [`PXP_PORT`] in production; a test may point the real cap at a loopback router.
    pxp_port: u16,
}

impl fmt::Debug for GatewayCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayCap")
            .field("gateway", &self.gateway)
            .field("generation", &self.generation)
            .field("bind_mode", &self.bind_mode)
            .field("valid", &self.gate.is_valid())
            .finish_non_exhaustive()
    }
}

/// Re-check the properties a [`Gateway`] promises, whatever produced it.
fn check_gateway(g: &Gateway) -> Result<(), CapError> {
    if !is_private(g.gw) {
        return Err(CapError::InvalidGateway(
            "gateway is not private (RFC 1918)",
        ));
    }
    if !is_private(g.self_ip) {
        return Err(CapError::InvalidGateway(
            "self address is not private (RFC 1918)",
        ));
    }
    if !LAN_PREFIX_LENS.contains(&g.prefix_len) {
        return Err(CapError::InvalidGateway(
            "self prefix length is not 8 to 31",
        ));
    }
    if g.gw == g.self_ip || !prefix_contains(g.self_ip, g.prefix_len, g.gw) {
        return Err(CapError::InvalidGateway("gateway is not on-link"));
    }
    if g.if_index == 0 || g.if_name.is_empty() {
        return Err(CapError::InvalidGateway("no interface"));
    }
    Ok(())
}

/// Re-check the gateway's interface against the host's interface list: it exists under the same
/// index and name, is usable, and holds `self_ip/prefix_len`.
fn check_interface(g: &Gateway, ifs: &[IfInfo]) -> Result<(), CapError> {
    let iface = ifs
        .iter()
        .find(|i| i.index == g.if_index && i.name == g.if_name)
        .ok_or(CapError::InvalidGateway("interface not found"))?;
    if !iface.usable() {
        return Err(CapError::InvalidGateway(
            "interface is down, loopback or point-to-point",
        ));
    }
    if !iface.v4.contains(&(g.self_ip, g.prefix_len)) {
        return Err(CapError::InvalidGateway(
            "self address is not on the interface",
        ));
    }
    Ok(())
}

fn new_socket() -> Result<Socket, CapError> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| CapError::io("socket", &e))?;
    s.set_nonblocking(true)
        .map_err(|e| CapError::io("socket", &e))?;
    set_dontroute(&s)?;
    Ok(s)
}

/// `SO_DONTROUTE`: send only to directly connected destinations, so an off-link "gateway" fails
/// with `ENETUNREACH` instead of following a route. It makes "on-link" a kernel-enforced property.
#[cfg(unix)]
fn set_dontroute(s: &Socket) -> Result<(), CapError> {
    use std::os::fd::AsRawFd;
    let on: libc::c_int = 1;
    // SAFETY: `s` is an open socket for the duration of the call, and `on` is a live `c_int`
    // whose size is passed as the option length.
    let r = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_DONTROUTE,
            std::ptr::from_ref(&on).cast(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap_or(4),
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(CapError::io("socket", &io::Error::last_os_error()))
    }
}

#[cfg(not(unix))]
fn set_dontroute(_: &Socket) -> Result<(), CapError> {
    Ok(())
}

/// Whether `SO_DONTROUTE` is set on `s`.
#[cfg(all(test, unix))]
fn dontroute_is_set(s: &Socket) -> bool {
    use std::os::fd::AsRawFd;
    let mut v: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap_or(4);
    // SAFETY: `s` is open; `v` and `len` are live and `len` holds `v`'s size.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_DONTROUTE,
            std::ptr::from_mut(&mut v).cast(),
            &raw mut len,
        )
    };
    r == 0 && v != 0
}

/// Decide the bind mode with a trial socket (bound to nothing, sends nothing).
fn probe_bind_mode(g: &Gateway) -> Result<BindMode, CapError> {
    let s = new_socket()?;
    #[cfg(target_os = "macos")]
    {
        s.bind_device_by_index_v4(std::num::NonZeroU32::new(g.if_index))
            .map_err(|e| CapError::io("bind-interface", &e))?;
        Ok(BindMode::IfScope)
    }
    #[cfg(target_os = "linux")]
    {
        match s.bind_device(Some(g.if_name.as_bytes())) {
            Ok(()) => Ok(BindMode::Device),
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => Ok(BindMode::SourceIp),
            Err(e) => Err(CapError::io("bind-interface", &e)),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        drop((s, g));
        Ok(BindMode::SourceIp)
    }
}

/// Tie `s` to the gateway's interface per `mode`.
fn apply_bind_mode(s: &Socket, g: &Gateway, mode: BindMode) -> Result<(), CapError> {
    match mode {
        #[cfg(target_os = "macos")]
        BindMode::IfScope => s
            .bind_device_by_index_v4(std::num::NonZeroU32::new(g.if_index))
            .map_err(|e| CapError::io("bind-interface", &e)),
        #[cfg(target_os = "linux")]
        BindMode::Device => s
            .bind_device(Some(g.if_name.as_bytes()))
            .map_err(|e| CapError::io("bind-interface", &e)),
        BindMode::SourceIp => Ok(()),
        _ => {
            let _ = (s, g);
            Err(CapError::InvalidGateway(
                "bind mode unavailable on this platform",
            ))
        }
    }
}

impl GatewayCap {
    /// Validate `gateway` and build the capability for network generation `generation`.
    ///
    /// In [`BindMode::SourceIp`] (the socket is not interface-bound) `lookup` is required: the
    /// cap is refused without one, and before each send the lookup must still report the same
    /// gateway and the kernel must still pick `self_ip` as the source for the gateway.
    pub fn validate(
        gateway: Gateway,
        generation: NetGen,
        policy: PolicyHandle,
        lookup: Option<Arc<dyn GatewayLookup>>,
    ) -> Result<Arc<Self>, CapError> {
        check_gateway(&gateway)?;
        let ifs =
            interfaces().map_err(|_| CapError::InvalidGateway("interface list unavailable"))?;
        let bind_mode = probe_bind_mode(&gateway)?;
        Self::validate_with(
            gateway,
            generation,
            policy,
            lookup,
            bind_mode,
            &ifs,
            Arc::new(kernel_source),
        )
    }

    /// [`GatewayCap::validate`] with the bind mode, interface list and kernel source selection
    /// supplied (tests inject them; no socket is created here).
    fn validate_with(
        gateway: Gateway,
        generation: NetGen,
        policy: PolicyHandle,
        lookup: Option<Arc<dyn GatewayLookup>>,
        bind_mode: BindMode,
        ifs: &[IfInfo],
        kernel_source: KernelSource,
    ) -> Result<Arc<Self>, CapError> {
        check_gateway(&gateway)?;
        check_interface(&gateway, ifs)?;
        let revalidate: Option<Arc<dyn Fn() -> bool + Send + Sync>> = match bind_mode {
            BindMode::SourceIp => {
                let Some(lookup) = lookup else {
                    return Err(CapError::InvalidGateway(
                        "source-ip bind mode needs a gateway lookup",
                    ));
                };
                let (gw, me) = (gateway.gw, gateway.self_ip);
                if kernel_source(gw) != Some(me) {
                    return Err(CapError::InvalidGateway(
                        "the kernel routes to the gateway from another address",
                    ));
                }
                let expect = gateway.clone();
                Some(Arc::new(move || {
                    matches!(lookup.lookup(), Ok(Some(g)) if g.same_network(&expect))
                        && kernel_source(gw) == Some(me)
                }))
            }
            BindMode::IfScope | BindMode::Device | BindMode::LoopbackTest => None,
        };
        Ok(Arc::new(Self {
            gateway,
            generation,
            bind_mode,
            gate: SendGate::new(policy, revalidate),
            pxp_port: PXP_PORT,
        }))
    }

    /// The network generation this cap belongs to.
    pub fn generation(&self) -> NetGen {
        self.generation
    }

    /// Whether `lookup` still reports the same gateway, self address and interface.
    pub fn revalidate(&self, lookup: &dyn GatewayLookup) -> bool {
        matches!(lookup.lookup(), Ok(Some(g)) if g.same_network(&self.gateway))
    }

    /// Refuse new work: later sends fail with [`DenyReason::Closing`].
    pub fn set_closing(&self) {
        self.gate.set_closing();
    }

    fn dest(&self, dest: LanDest) -> SocketAddr {
        match dest {
            LanDest::Pxp => SocketAddr::from((self.gateway.gw, self.pxp_port)),
        }
    }

    /// A fresh socket on `self_ip:port`, interface-bound per the bind mode. Fails closed if the
    /// address or interface is gone.
    fn socket(&self, port: u16) -> Result<Socket, CapError> {
        let s = new_socket()?;
        apply_bind_mode(&s, &self.gateway, self.bind_mode)?;
        s.bind(&SocketAddrV4::new(self.gateway.self_ip, port).into())
            .map_err(|e| CapError::io("bind", &e))?;
        Ok(s)
    }

    fn tokio_socket(&self, port: u16) -> Result<tokio::net::UdpSocket, CapError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(CapError::NoRuntime);
        }
        let std_sock: std::net::UdpSocket = self.socket(port)?.into();
        tokio::net::UdpSocket::from_std(std_sock).map_err(|e| CapError::io("socket", &e))
    }
}

impl sealed::Sealed for GatewayCap {}

impl PxpTransport for GatewayCap {
    fn gateway(&self) -> &Gateway {
        &self.gateway
    }

    fn bind_mode(&self) -> BindMode {
        self.bind_mode
    }

    async fn exchange_with_evidence(
        &self,
        dest: LanDest,
        reqs: &[&[u8]],
        deadline: Instant,
        on_reply: &mut (dyn FnMut(&[u8]) -> Flow + Send),
        evidence: Option<&SendEvidence>,
    ) -> Result<ExchangeStats, CapError> {
        // Refuse before creating a socket at all.
        self.gate.check()?;
        let sock = self.tokio_socket(0)?;
        let to = self.dest(dest);
        let expected = SocketAddrV4::new(self.gateway.gw, self.pxp_port);
        let present = |src: SocketAddr| match src {
            SocketAddr::V4(a) => Some(a),
            SocketAddr::V6(a) => a
                .ip()
                .to_ipv4_mapped()
                .map(|ip| SocketAddrV4::new(ip, a.port())),
        };
        exchange_on(
            &sock, &self.gate, to, expected, &present, reqs, deadline, on_reply, evidence,
        )
        .await
    }

    fn send_nowait(&self, dest: LanDest, req: &[u8]) -> Result<(), CapError> {
        self.gate.check()?;
        #[cfg(test)]
        send_tests::pause_nowait_after_check();
        // Without interface binding a safe send needs an asynchronous route recheck. The
        // no-runtime release path fails closed rather than running OS discovery here.
        if self.bind_mode == BindMode::SourceIp {
            return Err(CapError::Denied(DenyReason::NetworkChanged));
        }
        let s = self.socket(0)?;
        self.gate
            .send(|| s.send_to(req, &self.dest(dest).into()))
            .map(drop)
    }

    fn bind_probe_listener(&self, port: u16) -> Result<ProbeListener, CapError> {
        ProbeListener::new(self.tokio_socket(port)?)
    }

    fn invalidate(&self) {
        self.gate.invalidate();
    }

    fn is_valid(&self) -> bool {
        self.gate.is_valid()
    }
}

/// The loopback interface's index, for tests that run the real cap against loopback.
#[cfg(test)]
pub(crate) fn loopback_gateway() -> Option<Gateway> {
    use std::net::Ipv4Addr;
    let ifs = crate::gateway::interfaces().ok()?;
    let lo = ifs
        .into_iter()
        .find(|i| i.loopback && i.v4.iter().any(|(a, _)| *a == Ipv4Addr::LOCALHOST))?;
    Some(Gateway {
        gw: Ipv4Addr::LOCALHOST,
        self_ip: Ipv4Addr::LOCALHOST,
        prefix_len: 8,
        if_index: lo.index,
        if_name: lo.name,
    })
}

#[cfg(test)]
impl GatewayCap {
    /// The real cap, skipping the private-address checks, pointed at a loopback "router" on
    /// `127.0.0.1:pxp_port`, so the production socket, bind and gate code runs without any
    /// packet leaving the host.
    pub(crate) fn loopback_for_test(pxp_port: u16, policy: PolicyHandle) -> Option<Arc<Self>> {
        let gateway = loopback_gateway()?;
        let bind_mode = probe_bind_mode(&gateway).ok()?;
        Some(Arc::new(Self {
            gateway,
            generation: NetGen(1),
            bind_mode,
            gate: SendGate::new(policy, None),
            pxp_port,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn gw(gw: &str, me: &str, prefix: u8) -> Gateway {
        Gateway {
            gw: gw.parse().unwrap(),
            self_ip: me.parse().unwrap(),
            prefix_len: prefix,
            if_index: 4,
            if_name: "en0".to_owned(),
        }
    }

    /// The cap re-validates whatever `Gateway` it is handed.
    #[test]
    fn validation_rejects_bad_gateways() {
        let p = PolicyHandle::new(true);
        for (g, why) in [
            (gw("203.0.113.1", "192.168.1.20", 24), "not private"),
            (gw("192.168.1.1", "100.64.0.2", 8), "self not private"),
            (gw("192.168.2.1", "192.168.1.20", 24), "not on-link"),
            (gw("192.168.1.20", "192.168.1.20", 24), "gateway is self"),
            (gw("127.0.0.1", "127.0.0.1", 8), "loopback"),
        ] {
            assert!(
                matches!(
                    GatewayCap::validate(g, NetGen(1), p.clone(), None),
                    Err(CapError::InvalidGateway(_))
                ),
                "{why}"
            );
        }
        let mut no_if = gw("192.168.1.1", "192.168.1.20", 24);
        no_if.if_index = 0;
        assert!(GatewayCap::validate(no_if, NetGen(1), p.clone(), None).is_err());
        // A /0 (or /1../7) prefix would make any private gateway "on-link"; /32 has no
        // neighbours.
        for (g, why) in [
            (gw("10.0.0.1", "192.168.1.20", 0), "/0"),
            (gw("10.0.0.1", "10.1.2.3", 7), "/7"),
            (gw("192.168.1.1", "192.168.1.20", 32), "/32"),
        ] {
            assert!(
                matches!(
                    GatewayCap::validate(g, NetGen(1), p.clone(), None),
                    Err(CapError::InvalidGateway(_))
                ),
                "{why}"
            );
        }
    }

    fn en0() -> IfInfo {
        IfInfo {
            name: "en0".to_owned(),
            index: 4,
            up: true,
            loopback: false,
            point_to_point: false,
            v4: vec![("192.168.1.20".parse().unwrap(), 24)],
        }
    }

    struct FixedLookup(Gateway);

    impl GatewayLookup for FixedLookup {
        fn lookup(&self) -> Result<Option<Gateway>, crate::LookupError> {
            Ok(Some(self.0.clone()))
        }
    }

    fn build(
        mode: BindMode,
        ifs: &[IfInfo],
        lookup: bool,
        ks: KernelSource,
    ) -> Result<Arc<GatewayCap>, CapError> {
        let g = gw("192.168.1.1", "192.168.1.20", 24);
        let lookup: Option<Arc<dyn GatewayLookup>> =
            lookup.then(|| Arc::new(FixedLookup(g.clone())) as _);
        GatewayCap::validate_with(g, NetGen(1), PolicyHandle::new(true), lookup, mode, ifs, ks)
    }

    fn ks_is(ip: &'static str) -> KernelSource {
        Arc::new(move |_| Some(ip.parse().unwrap()))
    }

    /// The interface is re-checked: present under the same index and name, usable, and holding
    /// `self_ip/prefix`.
    #[test]
    fn validation_rechecks_the_interface() {
        let ks = || ks_is("192.168.1.20");
        assert!(build(BindMode::IfScope, &[en0()], false, ks()).is_ok());
        let mut down = en0();
        down.up = false;
        let mut lo = en0();
        lo.loopback = true;
        let mut p2p = en0();
        p2p.point_to_point = true;
        let mut other_addr = en0();
        other_addr.v4 = vec![("192.168.1.21".parse().unwrap(), 24)];
        let mut other_prefix = en0();
        other_prefix.v4 = vec![("192.168.1.20".parse().unwrap(), 16)];
        let mut renamed = en0();
        renamed.name = "en1".to_owned();
        for (i, ifs) in [
            vec![],
            vec![down],
            vec![lo],
            vec![p2p],
            vec![other_addr],
            vec![other_prefix],
            vec![renamed],
        ]
        .iter()
        .enumerate()
        {
            assert!(
                matches!(
                    build(BindMode::IfScope, ifs, false, ks()),
                    Err(CapError::InvalidGateway(_))
                ),
                "case {i}"
            );
        }
    }

    /// Source-IP mode: no lookup, or a kernel that would send to the gateway from another
    /// address (policy routing into a tunnel), is refused.
    #[test]
    fn source_ip_mode_needs_lookup_and_kernel_agreement() {
        assert!(build(BindMode::SourceIp, &[en0()], true, ks_is("192.168.1.20")).is_ok());
        assert!(matches!(
            build(BindMode::SourceIp, &[en0()], false, ks_is("192.168.1.20")),
            Err(CapError::InvalidGateway(_))
        ));
        // A Tailscale subnet route covering the LAN: the kernel picks the tailnet address.
        assert!(matches!(
            build(BindMode::SourceIp, &[en0()], true, ks_is("100.64.0.5")),
            Err(CapError::InvalidGateway(_))
        ));
        assert!(matches!(
            build(BindMode::SourceIp, &[en0()], true, Arc::new(|_| None)),
            Err(CapError::InvalidGateway(_))
        ));
        // Interface-bound modes do not consult the kernel's source selection.
        assert!(build(BindMode::IfScope, &[en0()], false, Arc::new(|_| None)).is_ok());
    }

    /// Source-IP mode re-checks the kernel's source selection before every send.
    #[tokio::test]
    async fn source_ip_mode_revalidates_before_each_send() {
        let via_lan = Arc::new(AtomicBool::new(true));
        let flag = via_lan.clone();
        let ks: KernelSource = Arc::new(move |_| {
            Some(if flag.load(Ordering::SeqCst) {
                "192.168.1.20".parse().unwrap()
            } else {
                "100.64.0.5".parse().unwrap()
            })
        });
        let cap = build(BindMode::SourceIp, &[en0()], true, ks).unwrap();
        assert!(
            cap.gate
                .check_async(Instant::now() + EXCHANGE_TIMEOUT)
                .await
                .is_ok()
        );
        via_lan.store(false, Ordering::SeqCst);
        assert!(matches!(
            cap.gate
                .check_async(Instant::now() + EXCHANGE_TIMEOUT)
                .await,
            Err(CapError::Denied(DenyReason::NetworkChanged))
        ));
        // Once invalidated, it stays invalid.
        via_lan.store(true, Ordering::SeqCst);
        assert!(
            cap.gate
                .check_async(Instant::now() + EXCHANGE_TIMEOUT)
                .await
                .is_err()
        );
    }

    /// Every cap socket carries `SO_DONTROUTE`; the loopback cap still works with it (the other
    /// loopback tests send through such sockets).
    #[cfg(unix)]
    #[test]
    fn cap_sockets_are_dontroute() {
        assert!(dontroute_is_set(&new_socket().unwrap()));
        let cap = GatewayCap::loopback_for_test(9, PolicyHandle::new(true))
            .expect("loopback capability construction must succeed");
        assert!(dontroute_is_set(&cap.socket(0).unwrap()));
    }

    /// A loopback "router" that counts what it receives (a raw socket in this module, the only
    /// one allowed to create sockets).
    async fn counting_listener() -> (Arc<tokio::net::UdpSocket>, u16) {
        let s = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = s.local_addr().unwrap().port();
        (Arc::new(s), port)
    }

    async fn received(s: &tokio::net::UdpSocket) -> usize {
        let mut buf = [0u8; 64];
        let mut n = 0;
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(50), s.recv_from(&mut buf)).await
        {
            n += 1;
        }
        n
    }

    /// A send with the policy off, after `invalidate()`, or while closing is refused
    /// without a socket write.
    #[tokio::test]
    async fn denied_sends_write_nothing() {
        let (router, port) = counting_listener().await;
        let policy = PolicyHandle::new(true);
        let cap = GatewayCap::loopback_for_test(port, policy.clone())
            .expect("loopback capability construction must succeed");
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        let mut ignore = |_: &[u8]| Flow::Continue;

        policy.set_lan_sends_allowed(false);
        let r = cap
            .exchange(LanDest::Pxp, &[b"x"], deadline, &mut ignore)
            .await;
        assert!(matches!(r, Err(CapError::Denied(DenyReason::Policy))));
        assert!(matches!(
            cap.send_nowait(LanDest::Pxp, b"x"),
            Err(CapError::Denied(DenyReason::Policy))
        ));
        policy.set_lan_sends_allowed(true);

        cap.set_closing();
        let r = cap
            .exchange(LanDest::Pxp, &[b"x"], deadline, &mut ignore)
            .await;
        assert!(matches!(r, Err(CapError::Denied(DenyReason::Closing))));
        assert_eq!(received(&router).await, 0);

        let cap = GatewayCap::loopback_for_test(port, policy.clone()).unwrap();
        cap.invalidate();
        assert!(!cap.is_valid());
        let r = cap
            .exchange(LanDest::Pxp, &[b"x"], deadline, &mut ignore)
            .await;
        assert!(matches!(r, Err(CapError::Denied(DenyReason::Invalidated))));
        assert!(cap.send_nowait(LanDest::Pxp, b"x").is_err());
        assert_eq!(received(&router).await, 0);

        // The same cap, allowed, does reach the loopback router: the denials above were real.
        let cap = GatewayCap::loopback_for_test(port, policy).unwrap();
        cap.send_nowait(LanDest::Pxp, b"x").unwrap();
        let mut ignore = |_: &[u8]| Flow::Continue;
        let deadline = Instant::now() + Duration::from_millis(20);
        cap.exchange(LanDest::Pxp, &[b"y"], deadline, &mut ignore)
            .await
            .unwrap();
        assert_eq!(received(&router).await, 2);
    }

    /// Binding to an address this host does not have fails closed, before any send.
    #[tokio::test]
    async fn bind_to_missing_self_ip_fails_closed() {
        let mut g = loopback_gateway().expect("loopback interface must exist");
        // 192.0.2.0/24 is TEST-NET-1: never configured on a host.
        g.self_ip = Ipv4Addr::new(192, 0, 2, 77);
        let cap = GatewayCap {
            bind_mode: probe_bind_mode(&g).unwrap(),
            gateway: g,
            generation: NetGen(1),
            gate: SendGate::new(PolicyHandle::new(true), None),
            pxp_port: 9,
        };
        let err = cap.socket(0).unwrap_err();
        assert!(matches!(err, CapError::Io { op: "bind", .. }), "{err}");
    }

    /// The real cap's sockets carry `self_ip` as their source and are interface-bound.
    #[tokio::test]
    async fn real_cap_source_is_self_ip() {
        let (router, port) = counting_listener().await;
        let cap = GatewayCap::loopback_for_test(port, PolicyHandle::new(true))
            .expect("loopback capability construction must succeed");
        if cfg!(target_os = "macos") {
            assert_eq!(cap.bind_mode(), BindMode::IfScope);
        }
        cap.send_nowait(LanDest::Pxp, b"hello").unwrap();
        let mut buf = [0u8; 16];
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), router.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((n, src.ip()), (5, Ipv4Addr::LOCALHOST.into()));
    }

    #[test]
    fn errors_are_verbatim() {
        #[cfg(unix)]
        {
            let e = CapError::io("send", &io::Error::from_raw_os_error(libc::EHOSTUNREACH));
            let s = e.to_string();
            assert!(s.starts_with("send: EHOSTUNREACH: "), "{s}");
            assert!(
                s.contains(&format!("os error {}", libc::EHOSTUNREACH)),
                "{s}"
            );
            let e = CapError::io("send", &io::Error::from_raw_os_error(libc::EPERM));
            assert!(e.to_string().starts_with("send: EPERM: "));
        }
        let e = CapError::io("recv", &io::Error::other("boom"));
        assert_eq!(e.to_string(), "recv: boom");
    }

    #[test]
    fn policy_handle_is_shared() {
        let a = PolicyHandle::new(true);
        let b = a.clone();
        b.set_lan_sends_allowed(false);
        assert!(!a.lan_sends_allowed());
    }
}

#[cfg(test)]
pub(crate) mod send_tests {
    use super::*;
    use std::{
        future::{Future, poll_fn},
        net::Ipv4Addr,
        task::Poll,
        time::Duration,
    };

    #[tokio::test]
    async fn fenced_during_source_route_validation() {
        for disable in [false, true] {
            let recv = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            recv.set_nonblocking(true).unwrap();
            let to = recv.local_addr().unwrap();
            let sock = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            sock.writable().await.unwrap();
            let entered = Arc::new(tokio::sync::Notify::new());
            let open = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
            let (hit, barrier) = (entered.clone(), open.clone());
            let evidence = SendEvidence::new(0, Instant::now());
            let policy = PolicyHandle::new(true);
            let gate = SendGate::new(
                policy.clone(),
                Some(Arc::new(move || {
                    hit.notify_one();
                    let (lock, cv) = &*barrier;
                    let mut ready = lock.lock().unwrap();
                    while !*ready {
                        ready = cv.wait(ready).unwrap();
                    }
                    true
                })),
            );
            let expected = match to {
                SocketAddr::V4(a) => a,
                _ => unreachable!(),
            };
            let present = |a| match a {
                SocketAddr::V4(a) => Some(a),
                _ => None,
            };
            let mut on_reply = |_: &[u8]| Flow::Done;
            let reqs = [&b"route-cut"[..]];
            let mut exchange = Box::pin(exchange_on(
                &sock,
                &gate,
                to,
                expected,
                &present,
                &reqs,
                Instant::now() + Duration::from_secs(2),
                &mut on_reply,
                Some(&evidence),
            ));
            tokio::select! {
                _ = entered.notified() => {},
                _ = &mut exchange => panic!("route check did not pause"),
            }
            if disable {
                policy.set_lan_sends_allowed(false);
            } else {
                gate.invalidate();
            }
            *open.0.lock().unwrap() = true;
            open.1.notify_one();
            assert!(matches!(exchange.await, Err(CapError::Denied(_))));
            assert!(
                evidence.possible_until().is_none(),
                "route denial is not send evidence"
            );
            assert_eq!(
                recv.recv(&mut [0u8; 32]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    #[tokio::test]
    async fn map_syscall_error_still_records_possible_ownership() {
        let _frozen = crate::test_time::FrozenTime::new();
        let sock = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let gate = SendGate::new(PolicyHandle::new(true), None);
        let evidence = SendEvidence::new(0, Instant::now());
        // A native IPv6 destination on an IPv4 socket fails in the syscall; no LAN traffic.
        let to = SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            9,
            0,
            0,
        ));
        let expected = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
        let present = |a| match a {
            SocketAddr::V4(a) => Some(a),
            _ => None,
        };
        let mut ignore = |_: &[u8]| Flow::Continue;
        let result = exchange_on(
            &sock,
            &gate,
            to,
            expected,
            &present,
            &[b"map"],
            Instant::now() + Duration::from_secs(1),
            &mut ignore,
            Some(&evidence),
        )
        .await;
        assert!(
            matches!(result, Err(CapError::Io { op: "send", .. })),
            "{result:?}"
        );
        assert!(
            evidence.possible_until().is_some(),
            "syscall errors cannot prove absence"
        );
        let first = evidence.possible_until().unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        let retry = exchange_on(
            &sock,
            &gate,
            to,
            expected,
            &present,
            &[b"map"],
            Instant::now() + Duration::from_secs(1),
            &mut ignore,
            Some(&evidence),
        )
        .await;
        assert!(matches!(retry, Err(CapError::Io { op: "send", .. })));
        assert!(
            evidence.possible_until().unwrap() >= first + Duration::from_secs(2),
            "latest attempt must advance the possible grant"
        );
    }

    type Hook = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);
    std::thread_local! {
        static NOWAIT_HOOK: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) };
    }
    pub(super) fn pause_nowait_after_check() {
        let hook = NOWAIT_HOOK.with(|hook| hook.borrow_mut().take());
        if let Some((reached, resume)) = hook {
            reached.send(()).unwrap();
            resume.recv().unwrap();
        }
    }

    fn nowait_fence(disable: bool) {
        let recv = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        recv.set_nonblocking(true).unwrap();
        let policy = PolicyHandle::new(true);
        let cap = std::sync::Arc::new(
            GatewayCap::loopback_for_test(recv.local_addr().unwrap().port(), policy.clone())
                .unwrap(),
        );
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let sender = cap.clone();
        let job = std::thread::spawn(move || {
            NOWAIT_HOOK.with(|hook| *hook.borrow_mut() = Some((reached_tx, resume_rx)));
            assert!(tokio::runtime::Handle::try_current().is_err());
            let request = crate::pmp::delete_request(std::num::NonZeroU16::new(41641).unwrap());
            sender.send_nowait(LanDest::Pxp, &request)
        });
        reached_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        if disable {
            policy.set_lan_sends_allowed(false);
        } else {
            cap.invalidate();
        }
        resume_tx.send(()).unwrap();
        let result = job.join().unwrap();
        let mut buf = [0u8; 32];
        assert!(
            result.is_err(),
            "final delete admitted after fence: {result:?}"
        );
        assert_eq!(
            recv.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "must receive zero datagrams after the fence"
        );
    }

    async fn waiting_send_fence(disable: bool) {
        let recv = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        recv.set_nonblocking(true).unwrap();
        let dest = recv.local_addr().unwrap();
        let send = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let evidence = SendEvidence::new(0, Instant::now());
        let policy = PolicyHandle::new(true);
        let gate = SendGate::new(policy.clone(), None);
        let expected = match dest {
            SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let present = |a| match a {
            SocketAddr::V4(a) => Some(a),
            _ => None,
        };
        let mut on_reply = |_: &[u8]| Flow::Done;
        let request = crate::pmp::delete_request(std::num::NonZeroU16::new(41641).unwrap());
        let requests = [&request[..]];
        let mut exchange = Box::pin(exchange_on(
            &send,
            &gate,
            dest,
            expected,
            &present,
            &requests,
            Instant::now() + Duration::from_millis(20),
            &mut on_reply,
            Some(&evidence),
        ));
        poll_fn(|cx| {
            assert!(exchange.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let mut buf = [0u8; 32];
        assert_eq!(
            recv.recv(&mut buf).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "test cut must precede the actual send"
        );
        if disable {
            policy.set_lan_sends_allowed(false);
        } else {
            gate.invalidate();
        }
        drop(exchange.await);
        assert!(
            evidence.possible_until().is_none(),
            "no MAP syscall crossed the fence"
        );
        assert_eq!(
            recv.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "must receive zero datagrams after the fence"
        );
    }

    #[test]
    fn nowait_invalidation_before_socket_send() {
        nowait_fence(false);
    }
    #[test]
    fn nowait_policy_disable_before_socket_send() {
        nowait_fence(true);
    }
    #[tokio::test]
    async fn invalidated_while_waiting_for_first_udp_send() {
        waiting_send_fence(false).await;
    }
    #[tokio::test]
    async fn policy_disabled_while_waiting_for_first_udp_send() {
        waiting_send_fence(true).await;
    }

    std::thread_local! {
        static BEFORE_SEND: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
    }
    pub(crate) fn before_send() {
        BEFORE_SEND.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
    }
    pub(crate) struct ClearHook;
    pub(crate) fn set_send_hook(hook: impl FnMut() + 'static) -> ClearHook {
        BEFORE_SEND.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        ClearHook
    }
    impl Drop for ClearHook {
        fn drop(&mut self) {
            BEFORE_SEND.with(|hook| drop(hook.borrow_mut().take()));
        }
    }

    async fn ready_send_fence(disable: bool, between: bool) {
        let recv = Arc::new(std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap());
        recv.set_nonblocking(!between).unwrap();
        recv.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let dest = recv.local_addr().unwrap();
        let send = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        send.writable().await.unwrap();
        let evidence = SendEvidence::new(usize::from(between), Instant::now());
        let policy = PolicyHandle::new(true);
        let gate = Arc::new(SendGate::new(policy.clone(), None));
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (g, r, done) = (gate.clone(), recv.clone(), entered.clone());
        let mut calls = 0;
        BEFORE_SEND.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                calls += 1;
                if calls != if between { 2 } else { 1 } {
                    return;
                }
                if between {
                    let mut before = [0u8; 32];
                    let n = r.recv(&mut before).unwrap();
                    assert_eq!(&before[..n], &crate::pmp::public_address_request());
                    r.set_nonblocking(true).unwrap();
                }
                if disable {
                    policy.set_lan_sends_allowed(false);
                } else {
                    g.invalidate();
                }
                done.store(true, Ordering::SeqCst);
            }))
        });
        let _clear = ClearHook;
        let addr = crate::pmp::public_address_request();
        let map = crate::pmp::map_request(
            std::num::NonZeroU16::new(41641).unwrap(),
            0,
            std::num::NonZeroU32::new(7200).unwrap(),
        );
        let both = [&addr[..], &map[..]];
        let reqs = if between { &both[..] } else { &both[1..] };
        let expected = match dest {
            SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let present = |a| match a {
            SocketAddr::V4(a) => Some(a),
            _ => None,
        };
        let mut on_reply = |_: &[u8]| Flow::Done;
        let result = exchange_on(
            &send,
            &gate,
            dest,
            expected,
            &present,
            reqs,
            Instant::now() + Duration::from_millis(20),
            &mut on_reply,
            Some(&evidence),
        )
        .await;
        assert!(
            entered.load(Ordering::SeqCst),
            "scheduling cut was not reached"
        );
        let mut buf = [0u8; 32];
        assert_eq!(
            recv.recv(&mut buf).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "must receive zero datagrams after the fence returns"
        );
        assert!(matches!(result, Err(CapError::Denied(_))));
        assert!(
            evidence.possible_until().is_none(),
            "a PMP address request is not MAP evidence"
        );
    }

    #[tokio::test]
    async fn fence_after_ready_gate_check() {
        for disable in [false, true] {
            ready_send_fence(disable, false).await;
        }
    }
    #[tokio::test]
    async fn fence_between_pmp_sends() {
        for disable in [false, true] {
            ready_send_fence(disable, true).await;
        }
    }
    #[test]
    fn send_permit_serializes_fences() {
        for disable in [false, true] {
            let recv = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            recv.set_nonblocking(true).unwrap();
            let dest = recv.local_addr().unwrap();
            let send = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            send.set_nonblocking(true).unwrap();
            let policy = PolicyHandle::new(true);
            let gate = Arc::new(SendGate::new(policy.clone(), None));
            let (entered, at_send) = std::sync::mpsc::channel();
            let (resume, blocked) = std::sync::mpsc::channel();
            let g = gate.clone();
            let sender = std::thread::spawn(move || {
                g.send(|| {
                    // Controlled preemption of a sender inside its final check/syscall window.
                    // This wait is test instrumentation; real send closures are nonblocking.
                    entered.send(()).unwrap();
                    blocked.recv().unwrap();
                    send.send_to(b"one", dest)
                })
            });
            at_send.recv_timeout(Duration::from_secs(1)).unwrap();
            let (started, at_fence) = std::sync::mpsc::channel();
            let (done, returned) = std::sync::mpsc::channel();
            let g = gate.clone();
            let fence = std::thread::spawn(move || {
                started.send(()).unwrap();
                if disable {
                    policy.set_lan_sends_allowed(false);
                } else {
                    g.invalidate();
                }
                done.send(()).unwrap();
            });
            at_fence.recv_timeout(Duration::from_secs(1)).unwrap();
            let early = returned.recv_timeout(Duration::from_millis(50)).is_ok();
            resume.send(()).unwrap();
            sender.join().unwrap().unwrap();
            fence.join().unwrap();
            assert!(
                !early,
                "fence returned while a sender still held the check/syscall window"
            );
            let mut buf = [0u8; 32];
            // The first send linearized before the fence; no send may follow it.
            recv.set_nonblocking(false).unwrap();
            recv.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            assert_eq!(recv.recv(&mut buf).unwrap(), 3);
            recv.set_nonblocking(true).unwrap();
            let other = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            other.set_nonblocking(true).unwrap();
            assert!(gate.send(|| other.send_to(b"two", dest)).is_err());
            assert_eq!(
                recv.recv(&mut buf).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }
}
