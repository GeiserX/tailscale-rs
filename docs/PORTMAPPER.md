# NAT port mapper (NAT-PMP and PCP)

[`ts_portmapper`](../ts_portmapper/src/lib.rs) asks the LAN gateway for an inbound UDP mapping to
the node's underlay port, as Go Tailscale's `net/portmapper` does, so that a peer behind a hard
NAT can reach the node directly instead of over DERP. NAT-PMP (RFC 6886) and PCP (RFC 6887) are
implemented. UPnP-IGD is not (bead `tsr-x4yg`, phase 2).

The crate holds the lifecycle client, the codecs, the gateway lookup and `GatewayCap`, the only
code that sends packets. (The gateway lookup's kernel source-address check connects a UDP socket
but never sends on it.) Nothing in the node runs it yet.

## Deviations from Go

- **Advertising (`advertise_nonpublic_external`).** The default is Go's: advertise every external
  address. With the option off, a private or CGNAT external address (a double NAT) is kept and
  renewed, but not advertised.
- **Renewal while idle (`renew_while_idle`).** The default is Go's: renewal rides on activity (the
  periodic ReSTUN and other kicks). With the option on, a due mapping is renewed even while idle,
  as long as there are peers. With no peers a mapping is never renewed and expires.
- **Notifications.** Go publishes every successful mapping (NAT-PMP, PCP, UPnP, including a
  reused one) and never a loss, expiry or disable. Here loss, expiry and disable publish too, for
  both protocols.
- **Strict replies.** Replies are accepted only from exactly `gateway:5351`, and every field is
  validated: version, opcode, R bit, length, internal port, protocol and nonce. Go's probe checks
  only the source port.
- **NAT-PMP delete.** The suggested external port is 0, as RFC 6886 §3.4 requires. Go sends the
  current one.
- **PCP nonce and delete.** The nonce is kept for renewal and delete and every MAP reply must echo
  it (RFC 6887 §11.1, §15.1). Go v1.102.4 draws a fresh nonce for every request, including the
  delete, and never checks the reply nonce. The PCP delete suggests port 0 and `::ffff:0.0.0.0`;
  Go sends the current external address and port.
- **Renewal protocol.** A usable mapping keeps its owning protocol, even if another service
  becomes available. PMP and PCP may share one router rule, so switching and then deleting the
  old rule could delete its replacement.
- **Gateway selection.** Only the most preferred default route counts, and it must be private and
  on-link. There is no fall-through to a less preferred private route (Go can pick a VPN gateway).
  Sockets are bound to the host's own address and, on macOS and on Linux with permission for
  `SO_BINDTODEVICE`, to its interface. Otherwise (source-address mode) the route is checked again
  before each send.
- **Lease trust.** Local trust is `min(granted, 2 h)`. A PCP grant longer than requested is
  recorded as the router's expiry but not trusted beyond 2 h.
- **Renewal timing.** Renewal starts at half the trusted lifetime, clamped to between 10 s and 1 h
  and never later than expiry. Go renews at half the granted lifetime.
- **IPv4 only.** Mappings are for the IPv4 underlay socket. A PCP reply with a native IPv6
  external address is rejected; Go accepts it.
- **Epoch.** Go's rule applies to probe replies only. An epoch that goes backwards drops the
  mapping without a release.
- **PCP seen.** A PCP ANNOUNCE reply counts as "PCP seen" and is checked for an epoch rollback
  only when its result is SUCCESS. Go records any ANNOUNCE reply, NOT_AUTHORIZED and
  ADDRESS_MISMATCH included, and then prefers PCP for the next MAP.
- **Attempt spacing.** Go retries a failed create on the next ReSTUN with no backoff (only a 5 s
  skip after a probe that found nothing). Here consecutive failures space attempts
  10/30/60/120/300/600 s (±20 %), no two attempts start within 2 s, and a PCP error lifetime is
  honoured up to 30 min; while that backoff holds, a probe after one that found nothing is
  skipped too. This bounds LAN traffic to a refusing or absent router.
- **Probe and MAP exchange.** The probe returns as soon as NAT-PMP and PCP are both decided (Go
  waits the full 250 ms unless UPnP also answered), and the NAT-PMP MAP always sends the
  public-address request alongside (Go sends it only when it has no recent public address).

## Router state, stated honestly

- **Normal state.** One UDP rule, `external:assigned → self_ip:underlay port`. It is open to any
  source host. WireGuard and disco authenticate the traffic, but the listener receives unsolicited
  internet UDP, the same exposure Go accepts.
- **Clean shutdown.** Deletes use cached validated capabilities within the shutdown timeout
  (at most 1 s of it), with no fresh OS discovery. The `Drop` path also sends them, best-effort
  and unacknowledged. Source-IP-only Linux mode needs fresh route validation before a send, so
  timed/Drop release fails closed there and leaves the rule to expiry. A lost delete also leaves
  the rule until its granted lifetime ends.
- **Crash, SIGKILL or power loss.** Rules survive until the router's **granted** lifetime ends. We
  ask for 7200 s. PCP may legally grant more, so the bound is "granted lifetime", not "2 h".
- **Outstanding rules.** The ledger holds at most four, including rules whose deletes failed or
  whose networks disappeared. Such tombstones keep their slots until acknowledgement or possible
  router expiry. After three unacknowledged deletes, fresh validation and retries continue at
  most once per rule per ten minutes, without freeing its slot. Every MAP reserves its identity
  before I/O. Possible ownership expands only when its nonblocking send syscall is attempted,
  after socket setup, route validation and the final send permit. A fresh never-sent identity
  retires without DELETE; an unsent adoption/renewal retains its previous grant and nonce/protocol.
  NAT-PMP's public-address request alone cannot create a mapping. A matched success records the
  actual grant. An unanswered MAP keeps its slot for the requested lifetime (7200 s) from the
  latest syscall attempt: a NAT-PMP gateway should not grant longer than requested (RFC 6886
  §3.3), and Go trusts no unanswered MAP at all. A PCP server may grant longer; such an unobserved
  longer grant is forgotten after 7200 s and left to the router's own expiry, as after a crash.
  Four unresolved rules can therefore stop further creates for up to two hours, never for the
  rest of the process. Wall-clock jumps withdraw
  advertisement trust but do not shorten possible ownership.
- **Network down.** Nothing is deleted, since a delete could reach the wrong router. Such rules are
  left to expire. A create for the same rule on the same network adopts them, because PCP refuses a
  second nonce for a live rule.
- **`only-tcp-443`.** No deletes either: the knob means "no UDP". Leftovers are deleted first if
  the knob is lifted on the same network.
- **DHCP reassignment.** A later holder of our LAN address could receive traffic for a stale rule
  until it expires.
- **Never.** No wildcard deletes (internal port 0) and no overwriting of other clients' rules. A
  delete names our own internal port, so a co-resident Go `tailscaled` (41644) keeps its mapping.

## OS discovery and rebind

Routing-table reads, interface enumeration, capability validation and source-mode route checks
run on a bounded worker: at most four detached OS threads, with a one-second wait budget (the
exchange deadline can be shorter). Cancellation retains the worker slot until its OS call ends;
a stuck call cannot block a Tokio worker or runtime teardown. Results are generation checked.
A same-port rebind withdraws the endpoint synchronously and restores it after fresh asynchronous
network validation. A changed port invalidates ownership for cleanup immediately.

## Lifecycle transitions

The private [`Lifecycle`](../ts_portmapper/src/lifecycle.rs) owner serializes settlement under
the client state mutex. Production callers have only an immutable state view and named event
methods; mutable access for fault injection exists only in tests. I/O and discovery run outside
that mutex. The ledger conserves **possible router ownership**, separately from the shorter
advertisement lease. Its four slots include fenced and terminal orphans. An unacknowledged
final send never retires a slot. A UDP wire identity (gateway, self address, interface, internal
port) has at most one MAP or delete reservation, across both protocols.

An entry is pending, active (backed by a held lease), or orphaned. A MAP reservation retains that
disposition while its operation lives; a delete reservation always owns an orphan. Fenced means
that deletion is forbidden until validated adoption. Final duty is an obligation handed to the
current reservation, or claimed immediately if idle. Retired entries leave the ledger only with
the evidence below. Close progresses Running → Closing → Closed; direct Drop-path release
progresses Running → Closed (or completes Closing → Closed).

| Event | Required evidence / precondition | Settlement and next owner |
|---|---|---|
| Create / adopt / renew | Validated owning network, enabled policy, spacing, no existing reservation for the wire identity; free admission capacity only for a new identity | Reserve MAP before I/O; expand the possible grant at its syscall boundary, not admission; operation owns entry; renewal/adoption reuses its slot, protocol and nonce even when the ledger is full |
| MAP success | Matched identity/nonce and grant | Current generation: active entry plus held lease; stale generation: orphan with observed grant; MAP reservation survives until finalizer |
| MAP never sent | Transport future ended or was dropped; no MAP syscall was entered (including setup, route, deadline or permit failure); a PMP address request alone is insufficient | Retire a fresh reservation without DELETE and free its slot; adoption/renewal retains prior possible expiry and protocol/nonce, with no added grant |
| MAP refusal / loss | Matched refusal or proven pre-MAP local rejection retires only a new create; an existing rule may still live | Keep held renewal; otherwise retain an orphan for uncertain ownership (including a partial PMP success); matched new-create refusal retires |
| MAP completion / cancellation | Operation finalizer, including cancellation before first poll | Return reservation; a never-sent fresh reservation retires; otherwise unsettled pending becomes orphan, retaining prior ownership or the attempted MAP's possible grant; held active remains held; orphan goes to cleanup or deferred final duty |
| Lease expiry / clock aging | Trusted lease expired; clock aging alone is not router-expiry evidence | Remove held owner, orphan even during renewal, keep reservation/nonce/grant; retire only if possible router expiry is proven and no MAP owns it |
| Cleanup claim | Idle, unfenced orphan; retry due, or closing | Delete operation owns reservation; reserve recovery cooldown before validation/I/O |
| Delete acknowledgement | Matched per-rule acknowledgement | Retire slot; operation finalizer becomes a no-op for that entry |
| Delete refusal / loss | No acknowledgement | Return orphan, count attempt; after three attempts use ten-minute recovery spacing with fresh owning-network validation |
| Ordinary cleanup validation unavailable | Worker timeout/failure while Running | Retain orphan, return delete reservation and defer fresh validation/recovery for ten minutes |
| Close-time validation unavailable / source-IP-only capability | Closing client; no valid cached release capability, or cached capability requires fresh source-route validation | Terminally fence orphan and return delete reservation; retain admission slot, schedule no recovery and send nothing; no fresh discovery during close |
| Cleanup cancellation | Operation finalizer | Retain orphan and return reservation without manufacturing acknowledgement; pending final duty can pass to final release |
| Accepted router reset | Fresh nonzero probe epoch rollback, held lease committed before probe; same gateway/protocol | Retire idle affected entries; retain reserved entries whose requests may reach restarted router; orphan held lease |
| Port / network change | Generation change; old network must freshly validate before cleanup | Withdraw held lease, cancel MAP handle but preserve its reservation until finalizer; orphan entries; retain old release capabilities |
| Network down / rejected network | Synchronous notification or failed validation | Orphan and fence entries, invalidate normal and release send gates; no delete; validated same-identity adoption can retain nonce and reopen entry |
| Same-port rebind | Socket rebound, awaiting asynchronous validation | Withdraw advertisement, cancel MAP handle; privately retain held owner until network validation or expiry; reservation stays with operation |
| Failed rebind | Rebind left no underlay socket | Clear local port, invalidate/withdraw held mapping, cancel MAP handle and orphan entries; schedule cleanup; reservations stay with operations until finalization |
| Policy disable / enable | Shared send permit fences disable before it returns | Disable withdraws held lease/cancels attempt and retains orphans; no LAN sends. Enable permits cleanup on validated network |
| Close begin | Running client; one absolute shutdown deadline | Closing, stop new work, cancel MAP/tasks/public cleanup; wait for reservations, then cleanup with cached capabilities |
| Close completion / cancellation | Closing client; terminal transition is idempotent | Closing → Closed; arm final duty once on unresolved entries; live operations retain reservation and inherit duty |
| Drop-path release | Running or Closing client; no runtime required; Closed is a no-op | Running → Closed or Closing → Closed; invalidate/withdraw held mapping, cancel work and arm final duty once; live operations retain reservation and inherit duty |
| Final release | Unfenced idle orphan, unexpired possible grant, enabled policy, cached valid interface-bound capability | Consume duty, reserve delete through nonblocking send outside state lock; return counted terminal orphan without acknowledgement; no route discovery |
| Proven router expiry | Monotonic possible-grant deadline reached, no operation reservation | Retire slot; wall-clock correction alone cannot justify retirement |

The send permit is separate from the state mutex: readiness and route validation precede it;
the final validity/policy check and one nonblocking syscall hold it. Invalidation and disable
share it. No permit holder acquires the state mutex or awaits. Runtime-less final release uses
the same permit and retains its reservation until the syscall returns.
