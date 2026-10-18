//! `TestCap`: the loopback test transport.
//!
//! It runs the same exchange loop as [`crate::GatewayCap`] (same send gate, same source check,
//! same receive caps), but sends to a [`FakeRouter`] on loopback and presents the router's
//! replies as coming from the logical `gateway:5351`. Two routers can stand in for two gateways
//! that both listen on port 5351.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
};

use tokio::time::Instant;

use super::{FakeRouter, RouterEndpoint};
use crate::{
    Gateway, PXP_PORT,
    cap::{
        BindMode, CapError, ExchangeStats, Flow, LanDest, PolicyHandle, ProbeListener,
        PxpTransport, SendEvidence, SendGate, exchange_on, sealed,
    },
};

/// The address a reply "from the wrong address" is presented as (TEST-NET-1).
pub const WRONG_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 66);

/// A loopback transport for one logical gateway. See the module docs.
pub struct TestCap {
    gateway: Gateway,
    to: SocketAddr,
    bind_ip: Ipv4Addr,
    aliases: Vec<(SocketAddr, SocketAddrV4)>,
    gate: SendGate,
    inject_send_error: Mutex<Option<i32>>,
    inject_bind_error: Mutex<Option<i32>>,
    panic_next: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for TestCap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCap")
            .field("gateway", &self.gateway)
            .field("to", &self.to)
            .finish_non_exhaustive()
    }
}

impl TestCap {
    /// A transport for the logical `gateway` backed by `router`. The PCP client IP the client
    /// sends is `gateway.self_ip`; the packets' real source is the router's loopback address, so
    /// `self_ip = 127.0.0.1` is the source-consistent mode.
    ///
    /// # Panics
    ///
    /// If the router is not on loopback (it never is: [`FakeRouter::start`] refuses).
    pub fn new(gateway: Gateway, router: &FakeRouter, policy: PolicyHandle) -> Arc<Self> {
        Self::with_endpoint(gateway, &router.endpoint(), policy)
    }

    /// [`TestCap::new`] from a router's detached [`RouterEndpoint`].
    ///
    /// # Panics
    ///
    /// If the endpoint is not on loopback.
    pub fn with_endpoint(
        gateway: Gateway,
        router: &RouterEndpoint,
        policy: PolicyHandle,
    ) -> Arc<Self> {
        assert!(
            router.addr.ip().is_loopback(),
            "TestCap only talks to a loopback router"
        );
        let gw = gateway.gw;
        let bind_ip = match router.addr {
            SocketAddr::V4(a) => *a.ip(),
            SocketAddr::V6(_) => Ipv4Addr::LOCALHOST,
        };
        Arc::new(Self {
            aliases: vec![
                (router.addr, SocketAddrV4::new(gw, PXP_PORT)),
                (
                    router.wrong_port_addr,
                    SocketAddrV4::new(gw, PXP_PORT.wrapping_add(1)),
                ),
                (router.wrong_ip_addr, SocketAddrV4::new(WRONG_IP, PXP_PORT)),
            ],
            to: router.addr,
            bind_ip,
            gateway,
            gate: SendGate::new(policy, None),
            inject_send_error: Mutex::new(None),
            inject_bind_error: Mutex::new(None),
            panic_next: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Make the next exchange panic (to show that single-flight survives a panicking attempt).
    pub fn panic_next_exchange(&self) {
        self.panic_next
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Make every later send fail with this OS error (`None` to stop).
    pub fn inject_send_error(&self, raw_os_error: Option<i32>) {
        *self
            .inject_send_error
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = raw_os_error;
    }

    /// Fail socket setup before any send attempt, without touching a real interface.
    pub fn inject_bind_error(&self, raw_os_error: Option<i32>) {
        *self
            .inject_bind_error
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = raw_os_error;
    }

    /// Refuse new work, like [`crate::GatewayCap::set_closing`].
    pub fn set_closing(&self) {
        self.gate.set_closing();
    }

    fn injected(&self) -> Result<(), CapError> {
        let code = *self
            .inject_send_error
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match code {
            Some(c) => Err(CapError::io("send", &io::Error::from_raw_os_error(c))),
            None => Ok(()),
        }
    }

    fn present(&self, src: SocketAddr) -> Option<SocketAddrV4> {
        self.aliases
            .iter()
            .find(|(real, _)| *real == src)
            .map(|(_, shown)| *shown)
    }
}

impl sealed::Sealed for TestCap {}

impl PxpTransport for TestCap {
    fn gateway(&self) -> &Gateway {
        &self.gateway
    }

    fn bind_mode(&self) -> BindMode {
        BindMode::LoopbackTest
    }

    async fn exchange_with_evidence(
        &self,
        dest: LanDest,
        reqs: &[&[u8]],
        deadline: Instant,
        on_reply: &mut (dyn FnMut(&[u8]) -> Flow + Send),
        evidence: Option<&SendEvidence>,
    ) -> Result<ExchangeStats, CapError> {
        let LanDest::Pxp = dest;
        self.gate.check()?;
        if let Some(code) = *self
            .inject_bind_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
        {
            return Err(CapError::io("bind", &io::Error::from_raw_os_error(code)));
        }
        assert!(
            !self
                .panic_next
                .swap(false, std::sync::atomic::Ordering::SeqCst),
            "TestCap: injected panic"
        );
        let sock = tokio::net::UdpSocket::bind((self.bind_ip, 0))
            .await
            .map_err(|e| CapError::io("bind", &e))?;
        if let Err(err) = self.injected() {
            // Simulate an OS failure of the first send, after setup and the final permit.
            self.gate.send(|| {
                if let Some(evidence) = evidence {
                    evidence.enter(0);
                }
                Ok(0)
            })?;
            return Err(err);
        }
        let expected = SocketAddrV4::new(self.gateway.gw, PXP_PORT);
        let present = |src| self.present(src);
        exchange_on(
            &sock, &self.gate, self.to, expected, &present, reqs, deadline, on_reply, evidence,
        )
        .await
    }

    fn send_nowait(&self, dest: LanDest, req: &[u8]) -> Result<(), CapError> {
        let LanDest::Pxp = dest;
        self.gate.check()?;
        if let Some(code) = *self
            .inject_bind_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
        {
            return Err(CapError::io("bind", &io::Error::from_raw_os_error(code)));
        }
        self.injected()?;
        let s =
            std::net::UdpSocket::bind((self.bind_ip, 0)).map_err(|e| CapError::io("bind", &e))?;
        s.set_nonblocking(true)
            .map_err(|e| CapError::io("bind", &e))?;
        self.gate.send(|| s.send_to(req, self.to)).map(drop)
    }

    fn bind_probe_listener(&self, port: u16) -> Result<ProbeListener, CapError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(CapError::NoRuntime);
        }
        let s = std::net::UdpSocket::bind((self.bind_ip, port))
            .map_err(|e| CapError::io("bind", &e))?;
        s.set_nonblocking(true)
            .map_err(|e| CapError::io("bind", &e))?;
        let s = tokio::net::UdpSocket::from_std(s).map_err(|e| CapError::io("bind", &e))?;
        ProbeListener::new(s)
    }

    fn invalidate(&self) {
        self.gate.invalidate();
    }

    fn is_valid(&self) -> bool {
        self.gate.is_valid()
    }
}
