# AGENTS.md

- This project is written in Rust.
- Follow the guidelines in CONTRIBUTING.md.
- Use GitHub markdown for docs, summaries of your work, etc.
- Commits must be signed off by the user in the form `Signed-off-by: "COMMITTER" <COMMITTER_EMAIL>`.
- When submitting a PR or filing an issue, include the text `Created using AGENT_NAME` where AGENT_NAME is your name.

## Proxy egress for exit nodes (capability beyond strict tsnet parity)

This fork carries one capability Go `tsnet` does not: an exit node can egress the traffic it
forwards through an **upstream proxy** instead of out its own origin IP. An exit node (e.g. on a
cloud VPS) can route a peer's internet-bound traffic through a **residential proxy** — the cloud
host's real IP never appears upstream.

- **Provider:** a residential proxy (configured by the deployer).
- **Where it lives:** the `RealDialer` trait in `ts_forwarder` is the single anti-leak
  chokepoint. `ProxyExitDialer` implements SOCKS5 (RFC 1928/1929) and HTTP `CONNECT`
  hand-rolled with **zero new dependencies** (keeps the `ring`-only, musl-clean egress path
  intact — never pull in `aws-lc-rs`/`openssl`/native-TLS on this path).
- **Config chain:** `tailscale::Config::exit_proxy` (`ExitProxyConfig` / `ExitProxyScheme`) →
  `ts_control::Config` (transport-only; `ts_control` never reads it and must not depend on
  `ts_forwarder`) → `ForwarderConfig::from_control_config` (converted to
  `ts_forwarder::ProxyConfig` at the `ts_runtime` boundary) → `forwarder_actor::dialer_choice`.
- **Fail-closed is sacred.** The proxy dialer is only selected when `forward_exit_egress` is
  set AND an `exit_proxy` is configured. Any proxy connect/handshake failure **drops the flow**
  — it never falls back to a direct host-IP dial. UDP over proxy fails closed. An SSRF guard
  rejects forbidden exit destinations (loopback / link-local / unspecified). Proxy credentials
  are redacted from `Debug`. The default `DirectDialer` structurally refuses exit egress, so the
  real origin IP can never leak by accident.
- **Deployer note — the SSRF guard is scoped to `ExitNode` flows by design.** The
  forbidden-destination check (`exit_dst_is_forbidden`) gates only the `0.0.0.0/0` exit class; a
  `Subnet` flow (a destination covered by a *narrower* advertised route) skips it, because a subnet
  route legitimately targets a private range — that private range **is** the routed subnet. This is
  **not** an attacker-controllable SSRF: the flow class is derived from the operator's **own
  `advertised_routes`**, never from the peer. But it does mean that **if an operator advertises a
  sensitive internal range as a forwarded subnet route, the forwarder will dial into it.** Do not
  advertise ranges you don't intend peers to reach — in particular never advertise the host's
  link-local (`169.254.0.0/16`), the tailnet CGNAT range (`100.64.0.0/10`), or loopback as a
  forwardable subnet. (Advertising `0.0.0.0/0` as an exit node is the normal case and stays behind
  the SSRF guard.)

## Exit-node memory: `tcp_buffer_size` at scale

The userspace netstack has **no TCP window auto-tuning**, so `Config::tcp_buffer_size` (default
**256 KiB per direction**, raised from 16 KiB in v0.5.3 to stop a single flow being throttled to
~1.6 Mbps at 80 ms RTT) is allocated **eagerly per socket** — one rx buffer and one tx buffer, so
~512 KiB per TCP socket. The **forwarder** netstack opens one socket per forwarded exit/subnet
flow, so concurrent-flow count multiplies this directly: a host carrying ~1,000 simultaneous
forwarded flows pins ~512 MB in TCP buffers alone — a real fraction of a small cloud VPS exit
node. On a small box that forwards many concurrent flows, set
`Config::tcp_buffer_size` lower (e.g. `Some(64 * 1024)`) and accept the per-flow throughput cap as
the trade. `None` keeps the throughput-optimized 256 KiB default. Both the application and
forwarder netstacks share this one value (see `ts_runtime::netstack_config_from`).

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:970c3bf2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   bd dolt push
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

## Where the tracker syncs

This repo is public, so its tracker syncs only to the private remote named by `sync.remote` in `.beads/config.yaml`. The block above says sync uses "your git remote". Here that never means this GitHub repo. Don't add it as a Dolt remote and don't push `refs/dolt/*` to it.
