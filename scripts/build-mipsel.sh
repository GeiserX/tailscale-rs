#!/bin/sh
# GeiserX -> GL-SFT1200 (mipsel-unknown-linux-musl, SOFT-FLOAT) cross-build.
# Rust mipsel-unknown-linux-musl is +soft-float; match it with a soft-float musl toolchain
# (NOT the OpenWrt hard-float one). Heavy crypto rides the kernel-wg path, so soft-float FP
# in the binary is a non-issue. Fixes the musl unwind/crt linkage (not R_MIPS_JALR, which is
# aws-lc/ssh-only and not in this feature graph).
set -eu
export RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
export RUSTUP_TOOLCHAIN=nightly

TC=/opt/mipsel-linux-muslsf-cross
CC="$TC/bin/mipsel-linux-muslsf-gcc"
AR="$TC/bin/mipsel-linux-muslsf-ar"

export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER="$CC"
export CC_mipsel_unknown_linux_musl="$CC"
export AR_mipsel_unknown_linux_musl="$AR"
# +crt-static (static musl) + link-self-contained=no (sysroot supplies crt*.o under build-std)
export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=no"
# drop the unwinder (panic=abort) so std does not need a real libunwind
export CARGO_PROFILE_RELEASE_PANIC=abort

# unwind shim: rust musl std still #[link(name=unwind)]s; muslsf ships it as libgcc_eh.a
GCC_LIBDIR="$(dirname "$("$CC" -print-libgcc-file-name)")"
[ -f "$GCC_LIBDIR/libunwind.a" ] || ln -sf "$GCC_LIBDIR/libgcc_eh.a" "$GCC_LIBDIR/libunwind.a"

cd /home/builder/tailscale-rs-geiserx
exec cargo +nightly build --release \
  --target mipsel-unknown-linux-musl \
  -Z build-std=std,panic_abort \
  -p geiserx_tailscale --example peer_ping --features kernel-wg
