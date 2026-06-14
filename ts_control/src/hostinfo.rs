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
    /// Linux distribution id (`HostInfo.Distro`, e.g. `ubuntu`/`debian`), from `/etc/os-release`'s
    /// `ID`. Empty off Linux or when undetermined.
    pub distro: String,
    /// Distribution version (`HostInfo.DistroVersion`, e.g. `24.04`), from `/etc/os-release`'s
    /// `VERSION_ID`. Empty off Linux or when undetermined.
    pub distro_version: String,
    /// Distribution code name (`HostInfo.DistroCodeName`, e.g. `noble`/`jammy`), from
    /// `/etc/os-release`'s `VERSION_CODENAME`. Empty off Linux or when undetermined.
    pub distro_code_name: String,
}

impl HostInfoData {
    /// Detect the host environment, mirroring the subset of Go `hostinfo.New()` we can fill
    /// truthfully without platform-specific probing beyond `uname` and `/etc/os-release`.
    pub fn detect() -> Self {
        let (distro, distro_version, distro_code_name) = distro_meta();
        Self {
            ipn_version: ipn_version_long(),
            os: go_style_os(),
            os_version: os_version(),
            go_arch: go_style_arch(),
            go_version: GO_VERSION.to_string(),
            machine: uname_machine(),
            distro,
            distro_version,
            distro_code_name,
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

/// Best-effort OS version string.
///
/// On macOS, Go reports the **marketing/product** version (e.g. `15.6.1`) via
/// `sysctl kern.osproductversion` (`hostinfo_darwin.go` `osVersionDarwin`), NOT the Darwin kernel
/// release. The kernel release (`uname -r`, e.g. `24.6.0`) is itself an Apple tell and diverges from
/// what a real `tailscaled` macOS node sends, so we must read the product version here.
///
/// On Linux (and other unix), Go's `OSVersion` is the kernel release (Tailscale 1.32+), which
/// `uname -r` gives directly. Empty when undetermined — still better than the prior always-empty pair.
#[cfg(target_os = "macos")]
fn os_version() -> String {
    macos_product_version().unwrap_or_else(|| uname_field(UnameField::Release))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn os_version() -> String {
    uname_field(UnameField::Release)
}

#[cfg(not(unix))]
fn os_version() -> String {
    String::new()
}

/// The macOS product (marketing) version from `sysctl kern.osproductversion` (e.g. `15.6.1`), the
/// same source Go's `osVersionDarwin` uses. `None` on any sysctl error so the caller falls back to
/// the kernel release rather than reporting an empty `OSVersion`.
#[cfg(target_os = "macos")]
fn macos_product_version() -> Option<String> {
    let name = c"kern.osproductversion";
    // SAFETY: a sysctl string read. First call with a null `oldp` to learn the buffer size, then a
    // second call to fill a buffer of exactly that size. `name` is a valid NUL-terminated C string.
    unsafe {
        let mut len: libc::size_t = 0;
        if libc::sysctlbyname(
            name.as_ptr(),
            core::ptr::null_mut(),
            &mut len,
            core::ptr::null_mut(),
            0,
        ) != 0
            || len == 0
        {
            return None;
        }
        let mut buf = alloc::vec![0u8; len];
        if libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
            core::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        // `len` now includes the trailing NUL; trim it (and anything past the first NUL).
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if end == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&buf[..end]).into_owned())
    }
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

/// Best-effort `(distro, distro_version, distro_code_name)` from `/etc/os-release`, mirroring the
/// common path of Go `hostinfo_linux.go` `linuxVersionMeta`: `Distro` = `ID`, `DistroVersion` =
/// `VERSION_ID`, `DistroCodeName` = `VERSION_CODENAME`. All empty off Linux or when the file is
/// absent/unreadable (e.g. a container with no os-release). We read the standard `/etc/os-release`
/// only; Go's special-casing for Synology/OpenWrt/QNAP/Debian-version files is out of scope for the
/// fork's Linux-VPS / container deployment, where os-release is present and authoritative.
#[cfg(target_os = "linux")]
fn distro_meta() -> (String, String, String) {
    let Ok(contents) = std::fs::read_to_string("/etc/os-release") else {
        return (String::new(), String::new(), String::new());
    };
    parse_os_release(&contents)
}

#[cfg(not(target_os = "linux"))]
fn distro_meta() -> (String, String, String) {
    (String::new(), String::new(), String::new())
}

/// Parse the `(ID, VERSION_ID, VERSION_CODENAME)` triple from `/etc/os-release` content. Each line is
/// `KEY=VALUE`; values may be optionally double- or single-quoted (the os-release spec), so quotes
/// are stripped. Unknown keys, blanks, and comments are ignored. Factored out so the parsing is
/// unit-testable without a real `/etc/os-release`.
#[cfg(target_os = "linux")]
fn parse_os_release(contents: &str) -> (String, String, String) {
    let (mut id, mut version_id, mut codename) = (String::new(), String::new(), String::new());
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        match key.trim() {
            "ID" => id = value,
            "VERSION_ID" => version_id = value,
            "VERSION_CODENAME" => codename = value,
            _ => {}
        }
    }
    (id, version_id, codename)
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
            distro: &h.distro,
            distro_version: &h.distro_version,
            distro_code_name: &h.distro_code_name,
            package: PACKAGE_TSNET,
            userspace: Some(true),
            ..Default::default()
        };
        assert_eq!(hi.ipn_version, h.ipn_version);
        assert_eq!(hi.os, h.os);
        assert_eq!(hi.go_arch, h.go_arch);
        assert_eq!(hi.go_version, h.go_version);
        assert_eq!(hi.machine, h.machine);
        assert_eq!(hi.distro, h.distro);
        assert_eq!(hi.distro_version, h.distro_version);
        assert_eq!(hi.distro_code_name, h.distro_code_name);
        assert_eq!(hi.package, "tsnet");
        assert_eq!(hi.userspace, Some(true));
    }

    /// `/etc/os-release` parsing mirrors Go `linuxVersionMeta`: Distro=ID, DistroVersion=VERSION_ID,
    /// DistroCodeName=VERSION_CODENAME, with quotes stripped and unknown keys/comments/blanks ignored.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_os_release_extracts_id_version_codename() {
        // A realistic Ubuntu 24.04 os-release (quoted + unquoted values, extra keys, a comment).
        let sample = r#"
# /etc/os-release
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="24.04"
VERSION_CODENAME=noble
HOME_URL="https://www.ubuntu.com/"
"#;
        let (id, ver, code) = parse_os_release(sample);
        assert_eq!(id, "ubuntu");
        assert_eq!(ver, "24.04");
        assert_eq!(code, "noble");
    }

    /// A single-quoted value and a missing VERSION_CODENAME (some distros omit it) parse cleanly:
    /// quotes stripped, the absent field left empty (so it is omitted from the wire, not sent as "").
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_os_release_handles_single_quotes_and_missing_fields() {
        let sample = "ID='debian'\nVERSION_ID=\"12\"\n";
        let (id, ver, code) = parse_os_release(sample);
        assert_eq!(id, "debian");
        assert_eq!(ver, "12");
        assert_eq!(
            code, "",
            "absent VERSION_CODENAME stays empty (wire-omitted)"
        );
    }

    /// On macOS, `os_version` must be the marketing/product version (e.g. `15.6.1`), NOT the Darwin
    /// kernel release (`uname -r`, e.g. `24.6.0`) — the kernel release is an Apple tell that diverges
    /// from what a real tailscaled macOS node sends. The product version never starts with the
    /// Darwin-era major (>=20 for the modern macOS-11+ line is the kernel; product majors are 10-26).
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_os_version_is_product_not_kernel_release() {
        let product = os_version();
        assert!(
            !product.is_empty(),
            "macOS OSVersion must be populated (sysctl kern.osproductversion)"
        );
        // It must equal the sysctl product version, not the uname kernel release.
        let kernel = uname_field(UnameField::Release);
        assert_ne!(
            product, kernel,
            "OSVersion must be the macOS product version, not the Darwin kernel release"
        );
        if let Some(direct) = macos_product_version() {
            assert_eq!(product, direct);
        }
    }
}
