# Building GeiserX for the GL-SFT1200 (mipsel, soft-float)

Cross-compiles the `peer_ping` example (and the `tailscale` lib) for the GL-SFT1200 travel
router — `mipsel-unknown-linux-musl`, **soft-float**, MIPS32r2, statically linked. Verified
2026-07-10: `Finished release in 2m07s` (after the one-time build-std warm-up), 8.45 MB static
binary, `FP ABI: Soft float`.

Ready-to-run: [`scripts/build-mipsel.sh`](scripts/build-mipsel.sh).

## Float ABI — the thing to get right
Rust's `mipsel-unknown-linux-musl` target is **`+soft-float`** (`features: "+mips32r2,+soft-float"`,
o32). It must be paired with a **soft-float** musl C toolchain for `ring`'s C/asm and the final
link. Do **not** use the OpenWrt `mipsel_24kc+24kf` toolchain — despite living on the same device,
it is built **hard-float** (`FP ABI: Hard float`, `-mhard-float`), so pairing it with Rust's
soft-float objects is a float-ABI mismatch. We use the musl.cc `mipsel-linux-muslsf-cross`
toolchain. A fully-static soft-float binary runs fine on the hard-float device (static =
self-contained), and soft-float FP cost is negligible here: the heavy crypto rides the **kernel-wg**
path (kernel does it), so the userspace binary barely touches floating point.

Confirm the output: `readelf -A peer_ping` → `FP ABI: Soft float`, `MIPS32 rel2`.

## Toolchain
```sh
curl -fsSL https://musl.cc/mipsel-linux-muslsf-cross.tgz | tar xz -C /opt
# gcc 11.2.1, ships its unwinder as libgcc_eh.a
```

## The build recipe
Tier-3 target ⇒ nightly + `-Z build-std`. The blocker is the **musl unwind/crt linkage**, fixed
three ways (all in `scripts/build-mipsel.sh`):

1. **`-C link-self-contained=no`** — under `-Z build-std` Rust does not emit its self-contained
   `crt*.o`; let the cross-gcc sysroot supply `crt1/crti/crtbegin/crtend/crtn`.
2. **`panic=abort`** (`CARGO_PROFILE_RELEASE_PANIC=abort` + `-Z build-std=std,panic_abort`) — drop
   the unwinder. (`panic_immediate_abort` is now a hard error on current nightly; plain `abort` is
   enough.)
3. **`ln -sf libgcc_eh.a libunwind.a`** in the gcc libdir — Rust's musl std still
   `#[link(name = "unwind")]`s even under panic=abort; muslsf ships the ABI-compatible unwinder as
   `libgcc_eh.a`. Symlink (not a RUSTFLAG) so the compile cache is preserved and only the final link
   re-runs.

Plus the one source change (**already in the kernel-wg WIP**): `ts_metrics` uses
`portable_atomic::AtomicU64` (32-bit mipsel has no native 64-bit atomics; keep the `fallback`
feature).

## Build target
The root crate `geiserx_tailscale` is **lib-only** (`[lib] name = "tailscale"`) — there is no
`tailscale` bin. The runnable is the **`peer_ping` example** (tailnet join / registration smoke
test; no `required-features`):

```sh
cargo +nightly build --release --target mipsel-unknown-linux-musl \
  -Z build-std=std,panic_abort \
  -p geiserx_tailscale --example peer_ping --features kernel-wg
# -> target/mipsel-unknown-linux-musl/release/examples/peer_ping
```

## On-device result (2026-07-10)
`peer_ping` cross-built here **joined a real tailnet from a GL-SFT1200**: registered with
`controlplane.tailscale.com`, completed the interactive login, pulled a netmap, selected DERP,
and brought up the kernel-WireGuard interface `wg-ts` (hybrid dataplane). Notes:
- **Soft-float binary runs fine** on the hard-float device (static = self-contained).
- **Uplink matters:** a weak 5 GHz repeater link at 60% packet loss made the control stream
  unholdable; 2.4 GHz (-43 dBm, 0% loss) was solid. Not a client bug — the environment.
- **`wg-ts` shows no address with a placeholder `--peer`** — expected: the hybrid rule only
  puts *direct-endpoint* peers on the kernel path; the node's own traffic uses the userspace
  netstack.

## Fix applied: followup 410 must re-register, not die (control_runner.rs)
The interactive login was killing the runner: when the user **approves**, control **consumes the
auth path**, and the very next followup poll returns `410 "auth path not found"`. The catch-all
`Err(e)` arm classified that as a terminal `Internal(Http, Registration)` and stopped the runner —
so the user's *own approval* aborted the login. Patch (in the `on_start` poll loop): when
`login_url.is_some()` and the error is `Internal(Http, Registration)`, **drop the followup
(`login_url = None`) and `continue`** — re-register once. An approved key then returns
`MachineAuthorized` (`Ok(())` → login completes); an expired one returns a fresh AuthURL. Bounded
(no infinite loop: on re-register `login_url` is None, so a repeat error is terminal). Verified
end-to-end on device: approval → `re-registering` → `registered, starting netmap stream` →
connected.

## R_MIPS_JALR — not a factor here
The `R_MIPS_JALR` relocation bug (LLVM leaks the `\x01` no-mangle prefix into the jalr hint symbol →
phantom undefined symbol) only fires when **`aws-lc-sys`** is in the graph, i.e. `--features ssh`.
The default/`kernel-wg` graph is **ring-only + pure-Rust netlink**, so it never appears. If you ever
enable `ssh`, the workaround is `RUSTFLAGS="-C relocation-model=static"` (non-PIC emits a direct
`jal`/`R_MIPS_26`, no jalr hint, no `\x01` symbol).
