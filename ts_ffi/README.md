# ts_ffi

C bindings to `tailscale-rs`.

`tailscale.h` is automatically generated in this directory when you `cargo build`. The library name
is `tailscalers` (`../target/*/libtailscalers.{a,so}`).

## A note on `unsafe`

This crate is the C FFI boundary, so it is where essentially all of the workspace's `unsafe` lives.
That is inherent to the job: `extern "C"` entry points receive raw pointers and C strings from the
caller, which Rust cannot prove valid, so dereferencing them is unavoidably `unsafe`. The rest of
the workspace is overwhelmingly safe Rust — many crates carry `#![deny(unsafe_code)]` or
`#![forbid(unsafe_code)]`.

Within this crate the `unsafe` surface is kept honest: every `pub unsafe extern "C" fn` documents
its caller contract in a `# Safety` doc section (see the module-level `# Safety` in `lib.rs` for the
blanket invariants — non-null, initialized, `CStr`-valid), and every `unsafe` block carries a
`// SAFETY:` comment naming the invariant it relies on. Raw-pointer reads are converted to safe Rust
references/slices as early as possible so the logic runs in safe code. See `CONTRIBUTING.md` for the
project-wide `unsafe` policy.
