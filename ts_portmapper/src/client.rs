//! The lifecycle client: one UDP mapping for the node's underlay port, created, renewed, expired
//! and released with generation-guarded transitions.
//!
//! # Lifecycle and generations
//!
//! All state lives in one `std::sync::Mutex<Lifecycle>` that is never held across an `.await`. Every
//! invalidation (local port change, network change, network down, epoch rollback, disable, close)
//! bumps `Lifecycle::generation`, aborts the in-flight attempt and takes the mapping out. An attempt snapshots
//! the generation when it starts; when its I/O finishes it commits only if the generation is
//! unchanged and the client still runs. A stale success is never installed: its rule goes to the
//! owned-rule ledger as orphaned and is deleted like any other leftover.
//!
//! # Router state
//!
//! A rule is recorded in the ledger (`owned`) **before** its MAP is sent, so a rule whose
//! reply was lost, or that committed after an invalidation, is still deletable. Deletes go only to
//! a network that still validates, only while the policy allows LAN sends, and only before the
//! router's grant ends. The ledger holds at most four rules (`owned::MAX_OWNED`).
//!
//! # Scheduling
//!
//! [`crate::schedule`] keeps attempt spacing, renewal and expiry apart: a failed renewal keeps the
//! mapping until its local expiry and retries on backoff, and expiry happens whatever the activity.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    net::{Ipv4Addr, SocketAddrV4},
    num::{NonZeroU16, NonZeroU32},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};

use tokio::{
    sync::{Notify, watch},
    task::{AbortHandle, JoinSet},
    time::Instant,
};

use crate::{
    Gateway, GatewayCap, GatewayLookup, LookupError, PolicyHandle, PxpTransport,
    cap::{CapError, LanDest, NetGen},
    clock::{Clock, SystemClock},
    gateway::{GatewayOverride, SystemLookup},
    is_advertisable, is_plausible_external,
    oneshot::{self, MapError, Proto, ProtoSet, Rule, delete_request_bytes, lease_deadline},
    owned::{LeftReason, OwnedRule, OwnedRules, RuleId},
    pcp, pmp,
    schedule::{Failure, Lease, REQUESTED_LIFETIME, Schedule},
};

#[path = "lifecycle.rs"]
mod lifecycle;
use lifecycle::*;

/// How long a positive probe result is trusted (Go `trustServiceStillAvailableDuration`).
pub const PROBE_CACHE: Duration = Duration::from_secs(10 * 60);
/// After a probe this recent found nothing, an attempt is not even tried (Go: 5 s).
pub const RECENT_PROBE: Duration = Duration::from_secs(5);
/// A wall-clock vs monotonic disagreement larger than this is taken as a resume or a clock jump.
pub const CLOCK_SKEW: Duration = Duration::from_secs(30);
/// The most distinct warnings remembered per network generation (for warn-once), in each of the
/// two budgets (see `Lifecycle::warned_router`).
const MAX_WARNED: usize = 32;

/// Builds the capability for a gateway. Building is also how an old network is revalidated before
/// a delete is sent to it: a gateway whose interface no longer holds its address fails to build.
pub trait CapFactory<T: PxpTransport>: Send + Sync + 'static {
    /// Validate `gateway` and build its capability for `net_gen`, sharing `policy`.
    fn build(
        &self,
        gateway: &Gateway,
        net_gen: NetGen,
        policy: &PolicyHandle,
    ) -> Result<Arc<T>, CapError>;
}

/// The production factory: [`GatewayCap::validate`].
pub struct SystemCaps {
    lookup: Arc<dyn GatewayLookup>,
}

impl SystemCaps {
    /// A factory whose source-IP-mode caps revalidate against `lookup`.
    pub fn new(lookup: Arc<dyn GatewayLookup>) -> Self {
        Self { lookup }
    }
}

impl CapFactory<GatewayCap> for SystemCaps {
    fn build(
        &self,
        gateway: &Gateway,
        net_gen: NetGen,
        policy: &PolicyHandle,
    ) -> Result<Arc<GatewayCap>, CapError> {
        GatewayCap::validate(
            gateway.clone(),
            net_gen,
            policy.clone(),
            Some(self.lookup.clone()),
        )
    }
}

/// Client configuration.
pub struct Config<T: PxpTransport> {
    /// Where the gateway comes from.
    pub lookup: Arc<dyn GatewayLookup>,
    /// How capabilities are built.
    pub caps: Arc<dyn CapFactory<T>>,
    /// The time source.
    pub clock: Arc<dyn Clock>,
    /// The protocols that may be used (both by default).
    pub protos: ProtoSet,
    /// Advertise an external address that is private, shared (CGNAT) or otherwise not publicly
    /// reachable. `true` (the default) is Go's behaviour; the mapping is kept and renewed either
    /// way.
    pub advertise_nonpublic_external: bool,
    /// The lifetime requested for every mapping.
    pub lifetime: NonZeroU32,
}

impl Config<GatewayCap> {
    /// The production configuration: the OS gateway lookup (or a validated override), real caps
    /// and clocks, both protocols, Go's advertising default.
    pub fn system(gateway_override: Option<GatewayOverride>) -> Self {
        let lookup: Arc<dyn GatewayLookup> = Arc::new(SystemLookup::new(gateway_override));
        Self {
            caps: Arc::new(SystemCaps::new(lookup.clone())),
            lookup,
            clock: Arc::new(SystemClock),
            protos: ProtoSet::BOTH,
            advertise_nonpublic_external: true,
            lifetime: requested_lifetime(),
        }
    }
}

/// [`REQUESTED_LIFETIME`] as a `NonZeroU32`.
pub const fn requested_lifetime() -> NonZeroU32 {
    match NonZeroU32::new(REQUESTED_LIFETIME) {
        Some(l) => l,
        None => panic!("nonzero"),
    }
}

/// Why mapping is disabled at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisableReason {
    /// Control's `only-tcp-443` attribute: no UDP at all, deletes included.
    OnlyTcp443,
}

/// What the client knows about the LAN's port-mapping services. `None` means "not checked".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeFacets {
    /// UPnP-IGD (never probed in this phase, so always `None`).
    pub upnp: Option<bool>,
    /// NAT-PMP.
    pub pmp: Option<bool>,
    /// PCP.
    pub pcp: Option<bool>,
}

/// A mapping as published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortmapEndpoint {
    /// The router's external address and port.
    pub external: SocketAddrV4,
    /// The protocol that holds it.
    pub proto: Proto,
    /// When local trust ends, on the client's clock.
    pub expires_at: Instant,
}

/// The published state. A `watch` carries the latest value and may coalesce intermediate ones;
/// consumers re-read it, and nothing promises exactly-once delivery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortmapState {
    /// The client's generation when this was published.
    pub generation: u64,
    /// The current mapping, if any.
    pub mapping: Option<PortmapEndpoint>,
    /// Whether the mapping may be offered to peers (after the advertising policy). Never true
    /// without a mapping.
    pub advertise: bool,
    /// The probe facets.
    pub facets: ProbeFacets,
}

impl PortmapState {
    /// The endpoint to advertise, if any: the mapping when [`advertise`](Self::advertise) holds.
    pub fn advertised(&self) -> Option<PortmapEndpoint> {
        self.mapping.filter(|_| self.advertise)
    }
}

/// A client error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Mapping is disabled (policy or `only-tcp-443`).
    #[error("port mapping is disabled")]
    Disabled,
    /// The client is closing or closed.
    #[error("port mapper closed")]
    Closed,
    /// No port-mapping service is available.
    #[error("no port-mapping service")]
    NoServices,
    /// The local port is 0: never mapped (a request with internal port 0 means "all ports").
    #[error("local port 0 is never mapped")]
    LocalPortZero,
    /// No local port was set yet.
    #[error("no local port")]
    NoLocalPort,
    /// No usable network (no default route, or the gateway did not validate).
    #[error("no usable gateway")]
    NoNetwork,
    /// The gateway lookup failed.
    #[error("{0}")]
    Gateway(LookupError),
    /// The capability refused or the OS failed.
    #[error("{0}")]
    Cap(CapError),
    /// The exchange failed or the router refused.
    #[error("{0}")]
    Map(MapError),
    /// The result arrived after an invalidation and was not installed.
    #[error("stale result discarded")]
    Stale,
    /// An attempt is already in flight.
    #[error("attempt in flight")]
    Busy,
    /// The next attempt is not due yet.
    #[error("backing off")]
    Backoff,
    /// The owned-rule ledger is full.
    #[error("too many outstanding router rules")]
    LedgerFull,
    /// The OS random source failed.
    #[error("{0}")]
    Nonce(pcp::NonceError),
}

/// What [`Client::check_network`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum NetCheck {
    /// Same gateway, self address and interface.
    Unchanged,
    /// A new network; the old one's rules are released if it still validates.
    Changed,
    /// No default route, a lookup error or a gateway that does not validate: like network-down.
    Down,
    /// The client is not running.
    Inactive,
}

/// When the driver should next wake the client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScheduleSnapshot {
    /// The current mapping's local expiry.
    pub expires_at: Option<Instant>,
    /// When to renew the current mapping: `max(renew_after, earliest attempt start)`.
    pub renewal_due: Option<Instant>,
    /// The earliest next attempt start.
    pub next_attempt: Option<Instant>,
    /// Set when a wanted attempt was refused by spacing or failed: when the next may start.
    pub retry_at: Option<Instant>,
    /// Whether the refusal was a failure backoff (rather than only the 2 s floor).
    pub backing_off: bool,
    /// Cleanup/recovery deadline, independent of peer activity. Absent while disabled/closed.
    pub cleanup_due: Option<Instant>,
}

struct Inner<T: PxpTransport> {
    cfg: Config<T>,
    policy: PolicyHandle,
    state: Mutex<Lifecycle<T>>,
    tx: watch::Sender<PortmapState>,
    tasks: Mutex<JoinSet<()>>,
    /// All cleanup waiters (including public/direct awaits) observe the same shutdown fence.
    stop_cleanup: watch::Sender<bool>,
    operations_changed: Notify,
}

/// The lifecycle client. Cheap to clone: clones share one state.
pub struct Client<T: PxpTransport + 'static> {
    inner: Arc<Inner<T>>,
}

impl<T: PxpTransport + 'static> Clone for Client<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: PxpTransport + 'static> fmt::Debug for Client<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

fn lock<S>(m: &Mutex<S>) -> MutexGuard<'_, S> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A jitter factor in `[0.8, 1.2]` from the OS random source (1.0 if it fails).
fn jitter() -> f64 {
    let mut b = [0u8; 4];
    if getrandom::fill(&mut b).is_err() {
        return 1.0;
    }
    0.8 + 0.4 * f64::from(u32::from_le_bytes(b)) / f64::from(u32::MAX)
}

/// How an attempt's failure spaces the next attempt.
fn failure_kind(e: &MapError) -> Failure {
    match e {
        MapError::Pmp {
            code: pmp::ResultCode::NotAuthorized,
            ..
        }
        | MapError::Pcp {
            code: pcp::ResultCode::NotAuthorized,
            ..
        } => Failure::NotAuthorized,
        MapError::Pcp { lifetime, .. } | MapError::PcpUnverified { lifetime, .. } => {
            Failure::Refused {
                hold: Some(Duration::from_secs(u64::from(*lifetime))),
            }
        }
        MapError::Pmp { .. } => Failure::Refused { hold: None },
        MapError::PmpUnverified { .. }
        | MapError::PmpAddr { .. }
        | MapError::NoServices { .. }
        | MapError::Cap(_)
        | MapError::Nonce(_) => Failure::Transient,
    }
}

/// A result code's name for a warn-once key: unknown codes share one key, so a router cannot
/// mint new keys by varying the code.
fn code_key(name: String, unknown: bool) -> String {
    if unknown { "unknown".to_owned() } else { name }
}

fn pmp_code_key(c: pmp::ResultCode) -> String {
    code_key(c.to_string(), matches!(c, pmp::ResultCode::Unknown(_)))
}

fn pcp_code_key(c: pcp::ResultCode) -> String {
    code_key(c.to_string(), matches!(c, pcp::ResultCode::Unknown(_)))
}

/// A capability error for a warn-once key: its kind, never free text.
fn cap_key(e: &CapError) -> String {
    match e {
        CapError::Denied(r) => format!("denied {r}"),
        CapError::InvalidGateway(why) => format!("invalid-gateway {why}"),
        CapError::ReservedPort(p) => format!("reserved-port {p}"),
        CapError::NoRuntime => "no-runtime".to_owned(),
        CapError::Io {
            op, raw_os_error, ..
        } => format!("io {op} {raw_os_error:?}"),
    }
}

/// What makes two failures "the same" for warn-once: the kind and result code, never the epoch,
/// lifetime, counts or reply text that change from reply to reply (the warning logs the error
/// itself). The flag says whether the key goes to the forgeable-router-reply budget.
fn warn_key(e: &MapError) -> (String, bool) {
    match e {
        MapError::Pmp { code, .. } => (format!("pmp {}", pmp_code_key(*code)), true),
        MapError::PmpUnverified { code, .. } => {
            (format!("pmp-unverified {}", pmp_code_key(*code)), true)
        }
        MapError::Pcp { code, .. } => (format!("pcp {}", pcp_code_key(*code)), false),
        MapError::PcpUnverified { code, .. } => {
            (format!("pcp-unverified {}", pcp_code_key(*code)), true)
        }
        MapError::PmpAddr { code, .. } => (format!("pmp-addr {}", pmp_code_key(*code)), true),
        MapError::NoServices { malformed } => (
            if malformed.is_some() {
                "no-services malformed".to_owned()
            } else {
                "no-services".to_owned()
            },
            true,
        ),
        MapError::Cap(c) => (format!("cap {}", cap_key(c)), false),
        MapError::Nonce(_) => ("nonce".to_owned(), false),
    }
}

/// Whether a failed create may still have left a rule on the router. Only a refusal tied to our
/// own request proves it did not.
fn may_exist(e: &MapError) -> bool {
    !matches!(e, MapError::Pmp { .. } | MapError::Pcp { .. })
}

impl<T: PxpTransport + 'static> Client<T> {
    /// A client and the receiver its state is published on. No I/O happens until the driver (or
    /// a caller) asks for it.
    pub fn new(cfg: Config<T>) -> (Self, watch::Receiver<PortmapState>) {
        let (tx, rx) = watch::channel(PortmapState::default());
        let client = Self {
            inner: Arc::new(Inner {
                cfg,
                policy: PolicyHandle::new(true),
                state: Mutex::new(Lifecycle::new()),
                tx,
                tasks: Mutex::new(JoinSet::new()),
                stop_cleanup: watch::channel(false).0,
                operations_changed: Notify::new(),
            }),
        };
        (client, rx)
    }

    /// A new receiver of the published state.
    pub fn subscribe(&self) -> watch::Receiver<PortmapState> {
        self.inner.tx.subscribe()
    }

    /// The policy shared by every capability this client builds.
    pub fn policy(&self) -> &PolicyHandle {
        &self.inner.policy
    }

    fn now(&self) -> Instant {
        self.inner.cfg.clock.now()
    }

    fn state(&self) -> MutexGuard<'_, Lifecycle<T>> {
        lock(&self.inner.state)
    }

    // ---------------------------------------------------------------------------------------
    // Publishing

    fn snapshot(&self, st: &mut Lifecycle<T>) -> PortmapState {
        let mapping = st
            .mapping
            .as_ref()
            .filter(|_| !st.rebind_pending)
            .map(|h| PortmapEndpoint {
                external: h.m.external,
                proto: h.m.proto,
                expires_at: h.lease.expires_at,
            });
        let advertise = mapping.is_some_and(|m| {
            let ip = *m.external.ip();
            let valid = m.external.port() != 0 && is_plausible_external(ip);
            let allowed = self.inner.cfg.advertise_nonpublic_external || is_advertisable(ip);
            if valid && !allowed && st.note_once(format!("suppress {}", m.external)) {
                tracing::info!(
                    external = %m.external,
                    "portmapper: not advertising a non-public external address; the mapping is \
                     kept and renewed"
                );
            }
            valid && allowed
        });
        PortmapState {
            generation: st.generation,
            mapping,
            advertise,
            facets: st.facets,
        }
    }

    fn publish(&self, st: &mut Lifecycle<T>) {
        let s = self.snapshot(st);
        self.inner.tx.send_replace(s);
    }

    // ---------------------------------------------------------------------------------------
    // Invalidation

    /// Spawn a cleanup of orphaned rules, if a runtime is available (otherwise the next tick or
    /// close does it).
    fn spawn_cleanup(&self) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let me = self.clone();
        let mut tasks = lock(&self.inner.tasks);
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            me.cleanup().await;
        });
    }

    // ---------------------------------------------------------------------------------------
    // Inputs from the driver

    /// Set the local (underlay) port to map. A change invalidates the mapping and releases its
    /// rule. Port 0 is never mapped: it returns [`Error::LocalPortZero`] and invalidates.
    pub fn set_local_port(&self, port: u16) -> Result<(), Error> {
        let new = NonZeroU16::new(port);
        let changed = {
            let mut st = self.state();
            let changed = st.port_changed(new);
            if changed {
                self.publish(&mut st);
            }
            changed
        };
        if changed {
            self.spawn_cleanup();
        }
        new.map(drop).ok_or(Error::LocalPortZero)
    }

    /// The underlay socket was rebound: `Some(port)` on success, `None` when the rebind left no
    /// socket. Withdraws synchronously without OS calls. A same-port mapping is kept privately
    /// until asynchronous network validation restores it; a changed port or failed rebind
    /// invalidates ownership for cleanup.
    pub fn note_rebind(&self, port: Option<u16>) {
        let Some(port) = port else {
            {
                let mut st = self.state();
                st.rebind_failed();
                self.publish(&mut st);
            }
            self.spawn_cleanup();
            return;
        };
        let same = {
            let st = self.state();
            st.local_port == NonZeroU16::new(port)
        };
        if same {
            let mut st = self.state();
            st.rebind_started(true);
            self.publish(&mut st);
        } else {
            let _ignore = self.set_local_port(port);
            let mut st = self.state();
            st.rebind_started(false);
            self.publish(&mut st);
        }
    }

    /// The network went down: invalidate without releasing anything (a delete could reach the
    /// wrong router).
    pub fn note_network_down(&self) {
        let mut st = self.state();
        // A closed/closing client may still have deferred release duty in an operation
        // finalizer. Network-down must fence those capabilities too.
        st.network_down("network down");
        self.publish(&mut st);
    }

    /// Look the gateway up and compare it with the current network (run by the driver's
    /// periodic poll, independent of activity). A new identity invalidates and releases the old
    /// rules to the old network only if it still validates; no gateway, a lookup error or a
    /// gateway that fails validation behaves like network-down.
    pub async fn check_network(&self) -> NetCheck {
        let (generation, candidate_gen, known) = {
            let mut st = self.state();
            if st.phase != Phase::Running {
                return NetCheck::Inactive;
            }
            let g = st.network_lookup_started();
            (
                st.generation,
                g,
                st.net
                    .as_ref()
                    .map(|n| (n.gateway.clone(), n.net_gen, n.cap.is_valid())),
            )
        };
        let lookup = self.inner.cfg.lookup.clone();
        let caps = self.inner.cfg.caps.clone();
        let policy = self.inner.policy.clone();
        let result = crate::blocking::run(move || {
            let gw = match lookup.lookup() {
                Ok(Some(gw)) => gw,
                Ok(None) => return Discovery::Down(None),
                Err(e) => return Discovery::Down(Some(e)),
            };
            let net_gen = match known {
                Some((old, n, valid)) if old.same_network(&gw) => {
                    if valid {
                        return Discovery::Unchanged;
                    }
                    n
                }
                _ => candidate_gen,
            };
            match caps.build(&gw, net_gen, &policy).and_then(|cap| {
                caps.build(&gw, net_gen, &policy)
                    .map(|release| (cap, release))
            }) {
                Ok((cap, release_cap)) => Discovery::Ready(gw, net_gen, cap, release_cap),
                Err(e) => Discovery::Rejected(gw, e),
            }
        })
        .await;
        let mut st = self.state();
        if st.phase != Phase::Running || st.generation != generation {
            return NetCheck::Inactive;
        }
        let (gw, net_gen, cap, release_cap) = match result {
            Some(Discovery::Ready(gw, n, cap, release)) => (gw, n, cap, release),
            Some(Discovery::Unchanged) => return NetCheck::Unchanged,
            Some(Discovery::Rejected(gw, e)) => {
                if st.warn_once(format!("gateway {gw} {}", cap_key(&e))) {
                    tracing::warn!(gateway = %gw, error = %e, "portmapper: gateway rejected");
                }
                if st.net.is_some() {
                    st.network_down("gateway rejected");
                    self.publish(&mut st);
                }
                return NetCheck::Down;
            }
            Some(Discovery::Down(err)) => {
                if let Some(e) = err
                    && st.warn_once(format!("lookup {e}"))
                {
                    tracing::warn!(error = %e, "portmapper: gateway lookup failed");
                }
                if st.net.is_some() {
                    st.network_down("no usable default route");
                    self.publish(&mut st);
                }
                return NetCheck::Down;
            }
            None => return NetCheck::Inactive,
        };
        let same = st.network_validated(gw, net_gen, cap, release_cap);
        self.publish(&mut st);
        drop(st);
        if !same {
            self.spawn_cleanup();
        }
        NetCheck::Changed
    }

    /// Compare the wall clock's progress with the monotonic clock's since the last call. A
    /// disagreement over [`CLOCK_SKEW`] (a resume from sleep, or a wall-clock jump) forces a fresh
    /// probe and makes the mapping due for renewal now (still subject to attempt spacing).
    ///
    /// [`Instant`] stops while the host sleeps, but the router's clock does not: when the wall
    /// clock moved further than the monotonic one, the trusted advertisement lease is aged by
    /// the difference. Possible ownership is never shortened by an unverified wall-clock step. A mapping whose local trust ended during the sleep
    /// is withdrawn at once; one that is still trusted keeps only what is left of its lease, so a
    /// failed renewal cannot keep advertising it past the router's grant. Either way the new
    /// state is published. Returns whether a jump was seen. A false positive (a forward wall-clock
    /// step) costs at most one renewal, or one re-create when the step exceeds the lease.
    pub fn check_clock(&self) -> bool {
        let now = self.now();
        let wall = self.inner.cfg.clock.wall();
        let mut st = self.state();
        let Some(slept) = st.clock_observed(now, wall) else {
            return false;
        };
        tracing::info!(
            slept_secs = slept.as_secs(),
            "portmapper: resume or clock jump; re-probing and renewing"
        );
        let changed = st.clock_aged(now, slept);
        if changed {
            self.publish(&mut st);
        }
        true
    }

    /// Turn mapping off at runtime (control's `only-tcp-443`): the policy that every send checks
    /// is cleared first, in-flight work is aborted, the mapping is withdrawn, and **no** further LAN
    /// packet is sent, deletes included. Owned rules are left until re-enabled on the same network
    /// (then deleted first) or until the router's grant ends.
    pub fn disable(&self, why: DisableReason) {
        self.inner.policy.set_lan_sends_allowed(false);
        let mut st = self.state();
        if !st.policy_disabled(why) {
            return;
        }
        self.publish(&mut st);
    }

    /// Undo [`disable`](Self::disable). Leftover rules are deleted by the next
    /// [`tick`](Self::tick) before anything else.
    pub fn enable(&self) {
        let mut st = self.state();
        if !st.policy_enabled(&self.inner.policy) {
            return;
        }
        self.publish(&mut st);
    }

    /// Whether a usable network is known.
    pub fn has_network(&self) -> bool {
        self.state().net.as_ref().is_some_and(|n| n.cap.is_valid())
    }

    /// Whether a mapping is held and not expired.
    pub fn have_mapping(&self) -> bool {
        let now = self.now();
        self.state()
            .mapping
            .as_ref()
            .is_some_and(|h| !h.lease.expired(now))
    }

    /// The current mapping's local expiry, renewal and the next attempt start.
    pub fn schedule(&self) -> ScheduleSnapshot {
        let st = self.state();
        ScheduleSnapshot {
            expires_at: st.mapping.as_ref().map(|h| h.lease.expires_at),
            renewal_due: st.mapping.as_ref().map(|h| st.sched.renewal_due(&h.lease)),
            next_attempt: st.sched.earliest_start(),
            // Only while an attempt could actually start: a leftover request with mapping
            // disabled or no local port would otherwise re-arm the driver every second.
            retry_at: (st.retry_wanted
                && st.phase == Phase::Running
                && st.disabled.is_none()
                && st.local_port.is_some())
            .then(|| st.sched.earliest_start())
            .flatten(),
            backing_off: st.sched.failures > 0,
            cleanup_due: (st.phase == Phase::Running
                && st.disabled.is_none()
                && self.inner.policy.lan_sends_allowed())
            .then(|| st.owned.next_cleanup(self.now()))
            .flatten(),
        }
    }

    /// The real monotonic instant for `t` on the client's clock (for arming timers).
    pub fn to_real(&self, t: Instant) -> Instant {
        self.inner.cfg.clock.to_real(t)
    }

    /// Withdraw the mapping if its local trust has ended, whatever the activity. Returns whether
    /// it did.
    pub fn expire_if_due(&self) -> bool {
        let now = self.now();
        let mut st = self.state();
        let expired = st.mapping.as_ref().is_some_and(|h| h.lease.expired(now));
        if !expired {
            return false;
        }
        st.lease_expired(now);
        self.publish(&mut st);
        true
    }

    // ---------------------------------------------------------------------------------------
    // Probe

    /// Probe for NAT-PMP and PCP, respecting the positive cache (a service seen within
    /// [`PROBE_CACHE`] is not probed again). Returns the facets.
    pub async fn probe(&self) -> Result<ProbeFacets, Error> {
        let now = self.now();
        // A mapping committed after this instant is newer than any reply this probe gets.
        let started = now;
        let (generation, cap, want) = {
            let mut st = self.state();
            if st.phase != Phase::Running {
                return Err(Error::Closed);
            }
            if st.disabled.is_some() || !self.inner.policy.lan_sends_allowed() {
                return Err(Error::Disabled);
            }
            let Some(net) = &st.net else {
                return Err(Error::NoNetwork);
            };
            let cap = net.cap.clone();
            let protos = self.inner.cfg.protos;
            let want = ProtoSet {
                pmp: protos.pmp && !st.probe.saw_pmp(now),
                pcp: protos.pcp && !st.probe.saw_pcp(now),
            };
            if !want.pmp && !want.pcp {
                st.probe_cached(now);
                let facets = st.facets;
                return Ok(facets);
            }
            if st.probe.found_nothing && !st.sched.may_start(now) {
                // Nothing answered last time and the backoff still holds: report that again.
                return Ok(st.facets);
            }
            (st.generation, cap, want)
        };
        let r = match oneshot::probe(&*cap, want).await {
            Ok(r) => r,
            Err(e) => {
                let mut st = self.state();
                if st.warn_once(format!("probe {}", cap_key(&e))) {
                    tracing::warn!(error = %e, "portmapper: probe failed");
                }
                return Err(Error::Cap(e));
            }
        };
        let now = self.now();
        let mut st = self.state();
        if generation != st.generation || st.phase != Phase::Running || st.disabled.is_some() {
            return Err(Error::Stale);
        }
        if !r.errors.is_empty() && st.warn_once_router("probe-malformed".to_owned()) {
            tracing::warn!(errors = ?r.errors, "portmapper: malformed replies to the probe");
        }
        let rolled_back =
            st.probe_observed(&r, want, self.inner.cfg.protos, started, now, cap.gateway());
        self.publish(&mut st);
        let facets = st.facets;
        drop(st);
        if rolled_back {
            // An attempt that was in flight may have left a rule on the restarted router.
            self.spawn_cleanup();
        }
        Ok(facets)
    }

    // ---------------------------------------------------------------------------------------
    // Attempts

    /// Return the cached mapping if it is valid, starting a renewal in the background when it is
    /// due; with no valid mapping, start creating one. Never blocks; every start respects attempt
    /// spacing.
    pub fn get_cached_mapping_or_start_creating_one(&self) -> Option<SocketAddrV4> {
        let now = self.now();
        let mut st = self.state();
        if st.mapping.as_ref().is_some_and(|h| h.lease.expired(now)) {
            st.lease_expired(now);
            self.publish(&mut st);
        }
        if st.rebind_pending {
            return None;
        }
        let out = st.mapping.as_ref().map(|h| (h.m.external, h.lease));
        match out {
            Some((external, lease)) => {
                if lease.renew_due(now) {
                    let _ignore = self.maybe_start_locked(&mut st, now);
                }
                Some(external)
            }
            None => {
                let _ignore = self.maybe_start_locked(&mut st, now);
                None
            }
        }
    }

    /// Begin an attempt under the lock: check every precondition, choose the protocol and
    /// rule, record the rule in the ledger **before** sending, and spawn the I/O.
    fn maybe_start_locked(&self, st: &mut Lifecycle<T>, now: Instant) -> Result<(), Error> {
        let (id, ctx) = st.map_started(&self.inner.cfg, &self.inner.policy, now)?;
        let rule_id = ctx.rule_id;
        let guard = SettlementGuard {
            client: self.clone(),
            event: FinalizerEvent::Map { id, rule_id },
        };
        let me = self.clone();
        let abort = {
            let mut tasks = lock(&self.inner.tasks);
            while tasks.try_join_next().is_some() {}
            tasks.spawn(async move {
                let need_cleanup = me.run_attempt(ctx).await;
                // Single-flight ends with the attempt, not with the cleanup that may follow it.
                drop(guard);
                if need_cleanup {
                    me.cleanup().await;
                }
            })
        };
        st.map_task_attached(id, abort);
        Ok(())
    }

    /// Run one attempt's I/O and commit (or reject) its result. Returns whether orphaned rules
    /// are waiting for a cleanup.
    async fn run_attempt(&self, ctx: AttemptCtx<T>) -> bool {
        let res = oneshot::map_with_evidence(
            &*ctx.cap,
            &ctx.rule,
            self.inner.cfg.lifetime,
            ctx.prev.as_ref(),
            &ctx.evidence,
        )
        .await;
        let now = self.now();
        let mut st = self.state();
        match res {
            Ok(m) => {
                let (publish, cleanup) = st.map_success(&ctx, m, now);
                if publish {
                    self.publish(&mut st);
                }
                cleanup
            }
            Err(e) => st.map_refused(&ctx, e, now),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Cleanup, tick, close

    /// Delete orphaned rules: only while the policy allows LAN sends, only to a network that still
    /// validates, and only before the router's possible grant ends. Unacknowledged rules keep
    /// admission slots, with infrequent recovery attempts after the initial bounded retries.
    /// Returns how many deletes were acknowledged.
    pub async fn cleanup(&self) -> usize {
        let mut stop = self.inner.stop_cleanup.subscribe();
        if *stop.borrow() {
            return 0;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => 0,
            acked = self.cleanup_inner(false) => acked,
        }
    }

    async fn cleanup_inner(&self, closing: bool) -> usize {
        let now = self.now();
        let claimed = {
            let mut st = self.state();
            st.cleanup_started(closing, &self.inner.policy, now)
        };
        let mut guard = SettlementGuard {
            client: self.clone(),
            event: FinalizerEvent::Delete(claimed.iter().map(|e| e.id).collect()),
        };
        let mut acked = 0;
        // An entry leaves the guard only once it is settled, so a cleanup cancelled mid-delete
        // (close aborting it, or its budget running out) hands the entry back for another try.
        for e in claimed {
            let cap = if closing {
                self.state()
                    .release_caps
                    .get(&e.id)
                    .filter(|cap| cap.is_valid())
                    .cloned()
            } else {
                let caps = self.inner.cfg.caps.clone();
                let gateway = e.gateway.clone();
                let policy = self.inner.policy.clone();
                crate::blocking::run(move || caps.build(&gateway, e.net_gen, &policy))
                    .await
                    .and_then(Result::ok)
            };
            let Some(cap) = cap else {
                self.state()
                    .delete_validation_failed(e.id, closing, self.now());
                tracing::debug!(
                    internal = e.rule.internal().get(),
                    "portmapper: release validation unavailable; ownership retained"
                );
                guard.settled(e.id);
                continue;
            };
            if !self.state().delete_validated(e.id, closing, cap.clone()) {
                continue;
            }
            if closing && cap.bind_mode() == crate::BindMode::SourceIp {
                // Source-only sends require a fresh OS route check. Leave these rules to expiry
                // on a timed/no-runtime release rather than initiating discovery during shutdown.
                self.state().delete_fenced(e.id);
                continue;
            }
            let r = oneshot::delete(&*cap, &e.rule).await;
            let ok = r.is_ok();
            let mut st = self.state();
            match r {
                Ok(()) => tracing::info!(
                    proto = %e.rule.proto(),
                    internal = e.rule.internal().get(),
                    gateway = %e.gateway.gw,
                    "portmapper: router rule released"
                ),
                Err(err) => tracing::debug!(error = %err, "portmapper: delete not acknowledged"),
            }
            if ok {
                acked += 1;
                st.delete_acknowledged(e.id, self.now());
            } else {
                st.delete_unacknowledged(e.id, self.now());
            }
            guard.settled(e.id);
        }
        acked
    }

    /// One activity-driven round: delete leftovers first, find the network if none is known,
    /// probe (cache-respecting), then return or start the mapping.
    pub async fn tick(&self) -> Option<SocketAddrV4> {
        if self.state().phase != Phase::Running {
            return None;
        }
        self.cleanup().await;
        if !self.has_network() {
            self.check_network().await;
        }
        let _ignore = self.probe().await;
        self.get_cached_mapping_or_start_creating_one()
    }

    /// Close: stop new work first, abort and await in-flight work, then send the deletes allowed
    /// by the ledger rules, all within `budget`. Idempotent.
    pub async fn close(&self, budget: Duration) {
        let deadline = tokio::time::Instant::now() + budget;
        {
            let mut st = self.state();
            if !st.close_started() {
                return;
            }
            self.inner.stop_cleanup.send_replace(true);
            self.publish(&mut st);
        }
        // If this close future is cancelled or panics at any await, its finalizer owns the
        // terminal release transition, including operations whose guards have not run yet.
        let _finish = SettlementGuard {
            client: self.clone(),
            event: FinalizerEvent::Close,
        };
        let mut tasks = std::mem::take(&mut *lock(&self.inner.tasks));
        tasks.abort_all();
        let _ = tokio::time::timeout_at(deadline, async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        // Public cleanup futures live in their callers, not our JoinSet. Cancel their inner
        // futures and wait for claim guards to hand back reservations before taking them.
        let _ = tokio::time::timeout_at(deadline, self.wait_for_operations()).await;
        let _ = tokio::time::timeout_at(deadline, self.cleanup_inner(true)).await;
        let mut st = self.state();
        st.close_finished();
        drop(st);
        self.release_ready_final();
    }

    async fn wait_for_operations(&self) {
        loop {
            let changed = self.inner.operations_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.state().owned.has_claims() {
                return;
            }
            changed.await;
        }
    }

    /// The `Drop`-path release: no runtime needed, no reply awaited. Marks the client closed and
    /// sends one unacknowledged delete per deletable rule. Does nothing after close, while the
    /// policy forbids LAN sends, or for a network that does not validate.
    pub fn release_blocking_best_effort(&self) {
        {
            let mut st = self.state();
            if !st.drop_requested() {
                return;
            }
            self.inner.stop_cleanup.send_replace(true);
            self.publish(&mut st);
        }
        lock(&self.inner.tasks).abort_all();
        self.release_ready_final();
    }

    /// Called by release and operation finalizers. Claim under the state lock, send outside it;
    /// retain ownership even when the final send succeeds (no acknowledgement was awaited).
    fn release_ready_final(&self) {
        let claimed = {
            let mut st = self.state();
            st.final_release_started(&self.inner.policy, self.now())
        };
        if claimed.is_empty() {
            return;
        }
        let _guard = SettlementGuard {
            client: self.clone(),
            event: FinalizerEvent::FinalRelease(claimed.iter().map(|e| e.id).collect()),
        };
        for e in claimed {
            let cap = self
                .state()
                .release_caps
                .get(&e.id)
                .filter(|cap| cap.is_valid())
                .cloned();
            let Some(cap) = cap else {
                log_left(&e, LeftReason::NetworkGone);
                continue;
            };
            let req = delete_request_bytes(&e.rule, e.gateway.self_ip);
            match cap.send_nowait(LanDest::Pxp, &req) {
                Ok(()) => {
                    tracing::info!(proto = %e.rule.proto(), internal = e.rule.internal().get(),
                    "portmapper: router rule release sent")
                }
                Err(err) => tracing::info!(error = %err, "portmapper: release not sent"),
            }
        }
    }

    fn settle_finalizer(&self, event: &FinalizerEvent) {
        match event {
            FinalizerEvent::Close => {
                self.release_blocking_best_effort();
                return;
            }
            FinalizerEvent::Map { id, rule_id } => self.state().map_finished(*id, *rule_id),
            FinalizerEvent::Delete(ids) => self.state().cleanup_cancelled(ids),
            FinalizerEvent::FinalRelease(ids) => self.state().final_release_finished(ids),
        }
        self.inner.operations_changed.notify_waiters();
        self.release_ready_final();
    }

    /// The number of rules in the owned-rule ledger (tests and diagnostics).
    pub fn owned_rules(&self) -> usize {
        self.state().owned.len()
    }

    /// Snapshot for the independent ownership oracle.
    #[cfg(test)]
    pub(crate) fn owned_snapshot(&self) -> Vec<OwnedRule> {
        self.state().owned.entries().to_vec()
    }

    /// Cleanup diagnostics for other crates' fake-router tests.
    #[cfg(feature = "test-harness")]
    pub fn cleanup_snapshot(&self) -> Vec<crate::testing::CleanupSnapshot> {
        self.state()
            .owned
            .entries()
            .iter()
            .map(|e| crate::testing::CleanupSnapshot {
                delete_tries: e.delete_tries,
                deleting: e.deleting(),
            })
            .collect()
    }

    /// Whether an attempt is in flight.
    pub fn attempt_in_flight(&self) -> bool {
        self.state().inflight.is_some()
    }

    /// Reap finished background tasks; returns how many are still running.
    pub fn reap(&self) -> usize {
        let mut tasks = lock(&self.inner.tasks);
        while tasks.try_join_next().is_some() {}
        tasks.len()
    }
}

enum Discovery<T> {
    Unchanged,
    Down(Option<LookupError>),
    Rejected(Gateway, CapError),
    Ready(Gateway, NetGen, Arc<T>, Arc<T>),
}

struct AttemptCtx<T> {
    generation: u64,
    cap: Arc<T>,
    net_gen: NetGen,
    rule: Rule,
    rule_id: RuleId,
    existed: bool,
    evidence: Arc<crate::SendEvidence>,
    prev: Option<oneshot::Mapping>,
}

/// One finalizer for MAP, cleanup and close. It only delivers its settlement event.
struct SettlementGuard<T: PxpTransport + 'static> {
    client: Client<T>,
    event: FinalizerEvent,
}

impl<T: PxpTransport + 'static> SettlementGuard<T> {
    fn settled(&mut self, id: RuleId) {
        if let FinalizerEvent::Delete(ids) = &mut self.event {
            ids.retain(|i| *i != id);
        }
    }
}

impl<T: PxpTransport + 'static> Drop for SettlementGuard<T> {
    fn drop(&mut self) {
        self.client.settle_finalizer(&self.event);
    }
}

fn log_left(e: &OwnedRule, why: LeftReason) {
    let secs = e
        .router_expiry()
        .saturating_duration_since(Instant::now())
        .as_secs();
    tracing::info!(
        proto = %e.rule.proto(),
        internal = e.rule.internal().get(),
        reason = ?why,
        "portmapper: router rule left to expire (at most {secs} s)"
    );
}

/// The client as the runtime drives it: object-safe, so the runtime needs no transport type.
pub trait PortMapper: Send + Sync + 'static {
    /// A receiver of the published state.
    fn subscribe(&self) -> watch::Receiver<PortmapState>;
    /// See [`Client::set_local_port`].
    fn set_local_port(&self, port: u16) -> Result<(), Error>;
    /// See [`Client::note_rebind`].
    fn note_rebind(&self, port: Option<u16>);
    /// See [`Client::note_network_down`].
    fn note_network_down(&self);
    /// See [`Client::check_network`].
    fn check_network(&self) -> Pin<Box<dyn Future<Output = NetCheck> + Send + '_>>;
    /// See [`Client::check_clock`].
    fn check_clock(&self) -> bool;
    /// See [`Client::disable`].
    fn disable(&self, why: DisableReason);
    /// See [`Client::enable`].
    fn enable(&self);
    /// See [`Client::expire_if_due`].
    fn expire_if_due(&self) -> bool;
    /// See [`Client::schedule`].
    fn schedule(&self) -> ScheduleSnapshot;
    /// See [`Client::to_real`].
    fn to_real(&self, t: Instant) -> Instant;
    /// See [`Client::tick`].
    fn tick(&self) -> Pin<Box<dyn Future<Output = Option<SocketAddrV4>> + Send + '_>>;
    /// See [`Client::cleanup`].
    fn cleanup(&self) -> Pin<Box<dyn Future<Output = usize> + Send + '_>>;
    /// See [`Client::close`].
    fn close(&self, budget: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
    /// See [`Client::release_blocking_best_effort`].
    fn release_blocking_best_effort(&self);
    /// See [`Client::reap`].
    fn reap(&self) -> usize;
}

impl<T: PxpTransport + 'static> PortMapper for Client<T> {
    fn subscribe(&self) -> watch::Receiver<PortmapState> {
        Client::subscribe(self)
    }
    fn set_local_port(&self, port: u16) -> Result<(), Error> {
        Client::set_local_port(self, port)
    }
    fn note_rebind(&self, port: Option<u16>) {
        Client::note_rebind(self, port);
    }
    fn note_network_down(&self) {
        Client::note_network_down(self);
    }
    fn check_network(&self) -> Pin<Box<dyn Future<Output = NetCheck> + Send + '_>> {
        Box::pin(Client::check_network(self))
    }
    fn check_clock(&self) -> bool {
        Client::check_clock(self)
    }
    fn disable(&self, why: DisableReason) {
        Client::disable(self, why);
    }
    fn enable(&self) {
        Client::enable(self);
    }
    fn expire_if_due(&self) -> bool {
        Client::expire_if_due(self)
    }
    fn schedule(&self) -> ScheduleSnapshot {
        Client::schedule(self)
    }
    fn to_real(&self, t: Instant) -> Instant {
        Client::to_real(self, t)
    }
    fn tick(&self) -> Pin<Box<dyn Future<Output = Option<SocketAddrV4>> + Send + '_>> {
        Box::pin(Client::tick(self))
    }
    fn cleanup(&self) -> Pin<Box<dyn Future<Output = usize> + Send + '_>> {
        Box::pin(Client::cleanup(self))
    }
    fn close(&self, budget: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(Client::close(self, budget))
    }
    fn release_blocking_best_effort(&self) {
        Client::release_blocking_best_effort(self);
    }
    fn reap(&self) -> usize {
        Client::reap(self)
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
