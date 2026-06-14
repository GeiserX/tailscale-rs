//! Host environment detection for the `Hostinfo` advertised to control, mirroring Go
//! `hostinfo.New()` so a node looks like a genuine Tailscale/tsnet client rather than an empty
//! shell.
//!
//! Go's `hostinfo.New()` (`hostinfo/hostinfo.go`) fills a dense field set: `IPNVersion`
//! (`version.Long()`), `OS` (`version.OS()`), `OSVersion`, `GoArch`/`GoVersion`, `Machine`
//! (`uname -m`), `Distro*`, `Package`, etc. The fork previously sent almost none of these — an empty
//! `OS` and an `IPNVersion` of the crate version (e.g. `0.37.4`) are glaring tells that this is not
//! `tailscaled`. This module sources the environmentally-true values once and exposes them as a
//! borrowable owned struct (the wire [`HostInfo`](ts_control_serde::HostInfo) is all `&'a str`).
//!
//! Field sourcing is deliberately conservative: we fill what we can determine truthfully and
//! cheaply (`OS`/arch/machine from the build + `std::env::consts`, an `OSVersion` from `uname` on
//! unix). Best-effort Linux niceties Go also fills — `Distro`/`DistroVersion`/`DistroCodeName` from
//! `/etc/os-release`, cloud detection, container detection — are left for a follow-up (tracked on the
//! bead); their absence is far less distinguishing than the empty `OS`/fake `IPNVersion` this fixes.

/// The Tailscale release this fork advertises capability-parity with. Kept in sync with
/// [`CapabilityVersion::CURRENT`](ts_capabilityversion::CapabilityVersion::CURRENT): capver 130
/// corresponds to the Tailscale 1.100 line, so a `1.100.x` `IPNVersion` is coherent with the capver
/// we already send (a mismatched pair would itself be a tell).
const TAILSCALE_VERSION: &str = "1.100.0";

/// The Go toolchain version the [`TAILSCALE_VERSION`] release was built with, reported as
/// `HostInfo.GoVersion`. A genuine Go-built Tailscale node ALWAYS sends this (`runtime.Version()`);
/// omitting it while sending `Package="tsnet"` + a Tailscale `IPNVersion` would be an internally
/// inconsistent set a detector could key on (no real Go binary lacks a Go version). This fork has no
/// honest Go version, so — exactly as with the synthetic [`TAILSCALE_VERSION`] — we present the
/// toolchain that release shipped with, pinned to it (not a runtime probe) so the pair stays
/// coherent. `go1.24` is the toolchain line the Tailscale 1.100 series was built with.
const GO_VERSION: &str = "go1.24.4";

/// Owned host-environment facts, detected once and borrowed into a wire
/// [`HostInfo`](ts_control_serde::HostInfo).
///
/// Construct with [`HostInfoData::detect`], bind it at the call site (so its owned strings outlive
/// the borrowing `HostInfo`), then borrow its fields into the `HostInfo` literal — directly at the
/// register/logout sites, or via
/// [`MapRequestBuilder::host_environment`](crate::map_request_builder::MapRequestBuilder::host_environment)
/// on the map-poll path.
#[derive(Debug, Clone)]
pub struct HostInfoData {
    /// `version.Long()`-shaped client version string.
    pub ipn_version: String,
    /// `version.OS()`-style OS name (e.g. `linux`, `macOS`, `windows`).
    pub os: String,
    /// OS version string (kernel/release), best-effort; empty when undetermined.
    pub os_version: String,
    /// `runtime.GOARCH`-style arch (e.g. `amd64`, `arm64`).
    pub go_arch: String,
    /// The Go toolchain version, reported as `HostInfo.GoVersion` (e.g. `go1.24.4`).
    pub go_version: String,
    /// `uname -m`-style machine (e.g. `x86_64`, `aarch64`).
    pub machine: String,
}

impl HostInfoData {
    /// Detect the host environment, mirroring the subset of Go `hostinfo.New()` we can fill
    /// truthfully without platform-specific probing beyond `uname`.
    pub fn detect() -> Self {
        Self {
            ipn_version: ipn_version_long(),
            os: go_style_os(),
            os_version: os_version(),
            go_arch: go_style_arch(),
            go_version: GO_VERSION.to_string(),
            machine: uname_machine(),
        }
    }
}

/// The `HostInfo.Package` value a node embedding a Tailscale engine reports. tsnet sets this via
/// `hostinfo.SetPackage("tsnet")` (`tsnet.go`); this fork is the same shape, so it presents the same
/// package so it does not stand out as an unknown/empty packaging.
pub const PACKAGE_TSNET: &str = "tsnet";

/// A `version.Long()`-shaped version string: `"<ver>-dev<date>-t<commit>"` in Go. We don't carry a
/// VCS commit/date in this crate, so we emit the stable `<ver>` base (`1.100.0`) — a real, plausible
/// Tailscale release string that matches the capability version we advertise. This is the value the
/// admin console and control see; it must NOT be the crate version (e.g. `0.37.4`), which no real
/// `tailscaled` ever reports.
fn ipn_version_long() -> String {
    TAILSCALE_VERSION.to_string()
}

/// Map Rust's `std::env::consts::OS` to Go `version.OS()`'s spelling. Go reports `macOS` (not
/// `darwin`), `iOS`, `windows`, `linux`, etc. Rust's `OS` is `macos`/`windows`/`linux`/`ios`/…, so
/// only the Apple platforms need re-casing; everything else already matches Go's lowercase form.
fn go_style_os() -> String {
    match std::env::consts::OS {
        "macos" => "macOS".to_string(),
        "ios" => "iOS".to_string(),
        other => other.to_string(),
    }
}

/// Map Rust's `std::env::consts::ARCH` to Go's `runtime.GOARCH` spelling. The common divergences:
/// `x86_64`→`amd64`, `aarch64`→`arm64`, `x86`→`386`. Anything else is passed through (most match,
/// e.g. `arm`, `riscv64`, `s390x`, `ppc64le`).
fn go_style_arch() -> String {
    match std::env::consts::ARCH {
        "x86_64" => "amd64".to_string(),
        "aarch64" => "arm64".to_string(),
        "x86" => "386".to_string(),
        other => other.to_string(),
    }
}

/// Best-effort OS version string. On unix we read `uname` release (`uname -r`-equivalent), matching
/// Go's "kernel version only" `OSVersion` on Linux (Tailscale 1.32+). Empty when undetermined —
/// which is still better than the prior always-empty `OS`+`OSVersion` pair.
#[cfg(unix)]
fn os_version() -> String {
    uname_field(UnameField::Release)
}

#[cfg(not(unix))]
fn os_version() -> String {
    String::new()
}

/// `uname -m`-style machine architecture (the kernel's hardware name, e.g. `x86_64`/`aarch64`),
/// which Go fills from `unameMachine`. This is distinct from `GoArch` (Go's build arch): on Linux
/// they differ in spelling (`x86_64` vs `amd64`).
#[cfg(unix)]
fn uname_machine() -> String {
    uname_field(UnameField::Machine)
}

#[cfg(not(unix))]
fn uname_machine() -> String {
    // No `uname` off unix; fall back to the Go-arch spelling so the field is at least populated
    // consistently rather than empty.
    go_style_arch()
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum UnameField {
    Release,
    Machine,
}

/// Read a field of `uname(2)` via libc, returning the NUL-terminated string as a `String` (empty on
/// any error). `libc::utsname` is a fixed C struct of `c_char` arrays; we copy out the requested
/// field up to its first NUL.
#[cfg(unix)]
fn uname_field(field: UnameField) -> String {
    // SAFETY: `utsname` is plain old data; `uname` fills it or returns < 0 (then we return empty).
    unsafe {
        let mut uts: libc::utsname = core::mem::zeroed();
        if libc::uname(&mut uts) != 0 {
            return String::new();
        }
        let buf: &[libc::c_char] = match field {
            UnameField::Release => &uts.release,
            UnameField::Machine => &uts.machine,
        };
        let bytes: &[u8] = core::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len());
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use ts_control_serde::HostInfo;

    use super::*;

    #[test]
    fn ipn_version_is_tailscale_shaped_not_crate_version() {
        let v = ipn_version_long();
        // Must be a plausible Tailscale release, never the crate version (e.g. "0.37.4") which no
        // real tailscaled reports. Coheres with the capability version we advertise (1.100 line).
        assert_eq!(v, "1.100.0");
        assert!(
            v.starts_with("1."),
            "IPNVersion must look like a Tailscale 1.x release, got {v:?}"
        );
    }

    #[test]
    fn os_is_go_style_and_nonempty() {
        let os = go_style_os();
        assert!(!os.is_empty(), "OS must never be empty (the loudest tell)");
        // The Apple re-casing must apply; everything else passes through lowercase.
        match std::env::consts::OS {
            "macos" => assert_eq!(os, "macOS"),
            "ios" => assert_eq!(os, "iOS"),
            other => assert_eq!(os, other),
        }
    }

    #[test]
    fn arch_maps_rust_to_go_spelling() {
        let arch = go_style_arch();
        assert!(!arch.is_empty());
        // The three common divergences must be remapped to Go's GOARCH spelling.
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(arch, "amd64"),
            "aarch64" => assert_eq!(arch, "arm64"),
            "x86" => assert_eq!(arch, "386"),
            other => assert_eq!(arch, other),
        }
    }

    #[test]
    fn detect_fills_the_loud_fingerprint_fields() {
        let h = HostInfoData::detect();
        // The fields whose emptiness/fakeness were the fingerprint: all must be populated.
        assert!(!h.ipn_version.is_empty());
        assert_ne!(h.ipn_version, env!("CARGO_PKG_VERSION"));
        assert!(!h.os.is_empty());
        assert!(!h.go_arch.is_empty());
        // GoVersion must be present (a real Go tailscale node always sends it; omitting it while
        // sending Package/Userspace/a Tailscale IPNVersion is an inconsistent pair).
        assert!(h.go_version.starts_with("go1."));
        // `machine` is uname-derived on unix (always available there); on non-unix it falls back to
        // the Go-arch spelling, so it is non-empty on every platform.
        assert!(!h.machine.is_empty());
    }

    #[test]
    fn borrows_into_hostinfo_like_the_call_sites() {
        // Mirror what register/logout do: bind the owned data, borrow its fields into a HostInfo.
        let h = HostInfoData::detect();
        let hi = HostInfo {
            ipn_version: &h.ipn_version,
            os: &h.os,
            os_version: &h.os_version,
            go_arch: &h.go_arch,
            go_version: &h.go_version,
            machine: &h.machine,
            package: PACKAGE_TSNET,
            userspace: Some(true),
            ..Default::default()
        };
        assert_eq!(hi.ipn_version, h.ipn_version);
        assert_eq!(hi.os, h.os);
        assert_eq!(hi.go_arch, h.go_arch);
        assert_eq!(hi.go_version, h.go_version);
        assert_eq!(hi.machine, h.machine);
        assert_eq!(hi.package, "tsnet");
        assert_eq!(hi.userspace, Some(true));
    }
}
