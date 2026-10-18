//! Harness pieces for the lifecycle client: a [`TestCaps`] factory that builds [`TestCap`]s for
//! logical gateways backed by fake routers, a [`ScriptedLookup`] whose answer a test changes, a
//! [`PanicLookup`] for configurations that must never look a gateway up, and a [`ManualClock`].

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use tokio::time::Instant;

use super::{RouterEndpoint, TestCap};
use crate::{
    CapError, Gateway, GatewayLookup, LookupError, PolicyHandle, PxpTransport, cap::NetGen,
    client::CapFactory, clock::Clock,
};

fn lock<S>(m: &Mutex<S>) -> MutexGuard<'_, S> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Builds [`TestCap`]s: each logical gateway address maps to a fake router's endpoint. A gateway
/// that is not [present](TestCaps::set_present) fails to build, which is how a test says "the old
/// network no longer validates".
#[derive(Debug, Default)]
pub struct TestCaps {
    routers: Mutex<HashMap<Ipv4Addr, RouterEndpoint>>,
    absent: Mutex<HashSet<Ipv4Addr>>,
    built: Mutex<Vec<Arc<TestCap>>>,
    builds: AtomicUsize,
}

impl TestCaps {
    /// An empty factory.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Route the logical gateway `gw` to `router`.
    pub fn add(&self, gw: Ipv4Addr, router: RouterEndpoint) {
        lock(&self.routers).insert(gw, router);
    }

    /// Whether `gw`'s network still validates.
    pub fn set_present(&self, gw: Ipv4Addr, present: bool) {
        let mut absent = lock(&self.absent);
        if present {
            absent.remove(&gw);
        } else {
            absent.insert(gw);
        }
    }

    /// How many caps were built.
    pub fn builds(&self) -> usize {
        self.builds.load(Ordering::SeqCst)
    }

    /// Every cap built so far (to inject errors into them).
    pub fn built(&self) -> Vec<Arc<TestCap>> {
        lock(&self.built).clone()
    }
}

impl CapFactory<TestCap> for TestCaps {
    fn build(
        &self,
        gateway: &Gateway,
        _net_gen: NetGen,
        policy: &PolicyHandle,
    ) -> Result<Arc<TestCap>, CapError> {
        if lock(&self.absent).contains(&gateway.gw) {
            return Err(CapError::InvalidGateway("test: network absent"));
        }
        let Some(router) = lock(&self.routers).get(&gateway.gw).copied() else {
            return Err(CapError::InvalidGateway("test: no router for this gateway"));
        };
        self.builds.fetch_add(1, Ordering::SeqCst);
        let cap = TestCap::with_endpoint(gateway.clone(), &router, policy.clone());
        lock(&self.built).push(cap.clone());
        debug_assert!(cap.is_valid());
        Ok(cap)
    }
}

/// What a [`ScriptedLookup`] answers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Gateway(Gateway),
    NoRoute,
    Error,
}

/// A gateway lookup whose answer the test sets. Counts its calls.
#[derive(Debug)]
pub struct ScriptedLookup {
    answer: Mutex<Answer>,
    calls: AtomicUsize,
}

impl ScriptedLookup {
    /// A lookup answering `gw`.
    pub fn new(gw: Gateway) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Answer::Gateway(gw)),
            calls: AtomicUsize::new(0),
        })
    }

    /// Answer `gw` from now on.
    pub fn set(&self, gw: Gateway) {
        *lock(&self.answer) = Answer::Gateway(gw);
    }

    /// Answer "no default route" (`Ok(None)`) from now on.
    pub fn set_no_route(&self) {
        *lock(&self.answer) = Answer::NoRoute;
    }

    /// Fail from now on.
    pub fn set_error(&self) {
        *lock(&self.answer) = Answer::Error;
    }

    /// How many lookups happened.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl GatewayLookup for ScriptedLookup {
    fn lookup(&self) -> Result<Option<Gateway>, LookupError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &*lock(&self.answer) {
            Answer::Gateway(g) => Ok(Some(g.clone())),
            Answer::NoRoute => Ok(None),
            Answer::Error => Err(LookupError::Ambiguous),
        }
    }
}

/// A lookup that must never run: test configurations that disable the mapper install it, and a
/// call panics the test.
#[derive(Debug, Default, Clone, Copy)]
pub struct PanicLookup;

impl GatewayLookup for PanicLookup {
    fn lookup(&self) -> Result<Option<Gateway>, LookupError> {
        panic!("the gateway lookup ran in a test configuration that must never touch the network");
    }
}

/// A manual clock: the real monotonic clock plus an offset the test advances, and a wall clock
/// that can also move on its own (a suspend, or a wall-clock jump).
#[derive(Debug, Default)]
pub struct ManualClock {
    offset_ms: AtomicU64,
    wall_extra_ms: AtomicU64,
}

impl ManualClock {
    /// A clock with no offset.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Move both clocks forward by `d`.
    pub fn advance(&self, d: Duration) {
        self.offset_ms.fetch_add(ms(d), Ordering::SeqCst);
    }

    /// The host slept for `d`: the wall clock moved, the monotonic clock did not.
    pub fn suspend(&self, d: Duration) {
        self.wall_extra_ms.fetch_add(ms(d), Ordering::SeqCst);
    }

    fn offset(&self) -> Duration {
        Duration::from_millis(self.offset_ms.load(Ordering::SeqCst))
    }
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        Instant::now() + self.offset()
    }

    fn wall(&self) -> SystemTime {
        SystemTime::now()
            + self.offset()
            + Duration::from_millis(self.wall_extra_ms.load(Ordering::SeqCst))
    }
}
