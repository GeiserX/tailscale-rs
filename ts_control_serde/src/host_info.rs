use alloc::{borrow::Cow, vec::Vec};

use serde::{Deserialize, Serialize};

use crate::{
    env_type::EnvType, location::Location, net_info::NetInfo, service::Service, tpm::TpmInfo,
};

/// A summary of a Tailscale host that a Tailscale node is running on. Includes information about
/// the version of Tailscale running on the host, the operating system, running services, and
/// various diagnostic/logging and configuration values.
#[serde_with::apply(
    bool => #[serde(skip_serializing_if = "crate::util::is_default")],
    &str => #[serde(borrow)] #[serde(skip_serializing_if = "str::is_empty")],
    Option => #[serde(skip_serializing_if = "Option::is_none")],
     _ => #[serde(default)],
)]
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct HostInfo<'a> {
    /// Version of the Tailscale code running on this Tailscale node, in long format.
    ///
    /// Wire key is `IPNVersion`, NOT the `rename_all = "PascalCase"` default `IpnVersion`: Go's
    /// `tailcfg.Hostinfo.IPNVersion` has an empty-name `json:",omitzero"` tag, so it marshals as the
    /// PascalCase Go field name verbatim — `IPNVersion`, preserving the `IPN` acronym. The serde
    /// `PascalCase` rule lowercases acronyms (`Ipn`), which a strict Go decoder treats as an unknown
    /// field and drops — so the explicit `rename` is required for the value to land at all (and an
    /// `IpnVersion` key is itself a not-Go tell). Same reason `os`/`os_version` are renamed below.
    #[serde(rename = "IPNVersion")]
    pub ipn_version: &'a str,
    /// Logtail ID of the Tailscale frontend (CLI) instance. Wire key `FrontendLogID` (Go's `ID`
    /// acronym), not the `PascalCase` default `FrontendLogId`.
    #[serde(rename = "FrontendLogID")]
    pub frontend_log_id: &'a str,
    /// Logtail ID of the Tailscale frontend (daemon) instance. Wire key `BackendLogID`, not
    /// `BackendLogId`.
    #[serde(rename = "BackendLogID")]
    pub backend_log_id: &'a str,
    /// A string indicating the operating system running on the Tailscale host. Wire key `OS` (Go
    /// `tailcfg.Hostinfo.OS`, empty-name tag → verbatim `OS`), not the `PascalCase` default `Os`.
    #[serde(rename = "OS")]
    pub os: &'a str,
    /// The version of the operating system, if available. The format is highly OS, version, and
    /// Tailscale version-specific.
    ///
    /// # Examples
    /// - Android: "10", "11", "12"
    /// - FreeBSD: "12.3-STABLE"
    /// - iOS/macOS: "15.6.1", "12.4.0"
    /// - Linux (before Tailscale 1.32): "Debian 10.4; kernel=5.10.0-17-amd64; container; env=kn"
    /// - Linux (Tailscale 1.32+): "5.10.0-17-amd64" (kernel version only)
    /// - Windows: "10.0.19044.1889"
    ///
    /// Wire key `OSVersion` (Go `tailcfg.Hostinfo.OSVersion`, empty-name tag → verbatim `OSVersion`),
    /// not the `PascalCase` default `OsVersion`.
    #[serde(rename = "OSVersion")]
    pub os_version: &'a str,

    /// Indicates whether or not this Tailscale node is running inside a container. Detection is
    /// best-effort only, and may not be accurate.
    ///
    /// Wire parity with Go `tailcfg.Hostinfo.Container` (`opt.Bool json:",omitzero"`): `Some(true)`/
    /// `Some(false)` marshal as the JSON bools `true`/`false` (Go's `opt.Bool.MarshalJSON`), and
    /// `None` is **omitted** by the struct-level `apply(Option => skip_serializing_if =
    /// Option::is_none)` rule above — Go's `omitzero` likewise drops an unset `opt.Bool` rather than
    /// sending `"Container":null`, so a non-container host sends no `Container` key at all (sending
    /// `null` would itself be a tell).
    pub container: Option<bool>,
    /// Represents the type of runtime environment that this Tailscale node is running in.
    #[serde(skip_serializing_if = "crate::util::is_default")]
    pub env: EnvType,
    /// The name of the Linux distribution this Tailscale node is installed on (e.g. "debian",
    /// "ubuntu", "nixos", etc).
    pub distro: &'a str,
    /// The version string of the Linux distribution this Tailscale node is installed on. For
    /// example, this field may be "20.04" or "24.04.3" on on Ubuntu installs.
    pub distro_version: &'a str,
    /// The code name of the Linux distribution this Tailscale node is installed on. For example,
    /// this field may be "jammy" or "bullseye" on Debian Linux installs.
    pub distro_code_name: &'a str,

    /// Disambiguates Tailscale nodes that run using `tsnet` (e.g. "k8s-operator", "golinks", etc).
    pub app: &'a str,
    /// Indicates whether or not a desktop environment was detected. Used only for Linux devices.
    pub desktop: Option<bool>,
    /// How this Tailscale node was packaged/delivered to the device (e.g. "choco", "appstore",
    /// etc). Empty string if the packaging mechanism is unknown.
    pub package: &'a str,
    /// Model of mobile phone for mobile devices (e.g. "Pixel 3a", "iPhone12,3").
    pub device_model: &'a str,
    /// Device token for sending push notifications to devices. Currently used for Apple Push
    /// Notifications (APNs) on iOS/macOS; will be used for Android in the future.
    pub push_device_token: &'a str,
    /// Hostname of this Tailscale node's host.
    ///
    /// A user-set machine name (e.g. macOS ComputerName) is free-form text that can contain a JSON
    /// escape (a literal `"`, a `\`, or — since Go's `json.Marshal` escapes `&`/`<`/`>` by default —
    /// an `&` in a name like `Tom & Jerry's Mac`). A borrowed `&str` cannot decode an escaped string,
    /// which would fail the whole `HostInfo`/peer decode; `Cow` borrows on the fast path and owns
    /// only when unescaping. `#[serde(borrow)]` is explicit here because the struct-level `apply`
    /// rule for `&str` does not match `Option<Cow<'a, str>>`.
    #[serde(borrow)]
    pub hostname: Option<Cow<'a, str>>,

    /// Indicates whether or not this Tailscale node's host is blocking incoming connections.
    pub shields_up: bool,
    /// Indicates this Tailscale node exists in the netmap because it's owned by a shared-to user.
    pub sharee_node: bool,
    /// Indicates the user has opted out of sending logs and receiving support from Tailscale.
    pub no_logs_no_support: bool,
    /// Indicates this Tailscale node would like to be wired up server-side (DNS, etc) to be
    /// able to use Tailscale Funnel, even if it's not currently enabled.
    ///
    /// For example, the user might only use it for intermittent foreground CLI serve sessions, for
    /// which they'd like it to work right away, even if it's disabled most of the time. As an
    /// optimization, this is only sent if [`HostInfo::ingress_enabled`] is `false`, as
    /// [`HostInfo::ingress_enabled`] implies that this option is `true`.
    pub wire_ingress: bool,
    /// Indicates whether or not this Tailscale node has any Tailscale Funnel endpoints enabled.
    pub ingress_enabled: bool,
    /// Indicates that this Tailscale node has opted-in to remote updates triggered by the admin
    /// console.
    pub allows_update: bool,

    /// The machine type (architecture) of this Tailscale node's host. Equivalent to the output of
    /// `uname --machine` on Linux.
    pub machine: &'a str,
    /// The `GOARCH` value of this Tailscale node's binary.
    pub go_arch: &'a str,
    /// The `GOARM`/`GOAMD64`/etc value of this Tailscale node's binary.
    pub go_arch_var: &'a str,
    /// The Go version this Tailscale node's binary was built with.
    pub go_version: &'a str,

    /// The set of IP ranges this Tailscale node can route. Wire key `RoutableIPs` (Go's `IPs`
    /// acronym), not the `PascalCase` default `RoutableIps`.
    #[serde(rename = "RoutableIPs")]
    pub routable_ips: Option<Vec<ipnet::IpNet>>,
    /// The set of ACL tags this Tailscale node wants to claim.
    pub request_tags: Option<Vec<&'a str>>,
    /// MAC address(es) to send Wake-on-LAN packets to wake this node. Each address is formatted as
    /// a lowercase hexadecimal string, with each byte of the address separated by colons. Wire key
    /// `WoLMACs` — Go's exact casing (`WoL` + `MACs`), not the `PascalCase` default `WolMacs`.
    #[serde(rename = "WoLMACs")]
    pub wol_macs: Option<Vec<&'a str>>,
    /// Services running on the Tailscale node's host to advertise to the Tailnet.
    pub services: Option<Vec<Service<'a>>>,

    /// Information about the host's network state and configuration, if available. Includes
    /// DERP home region and latencies to DERP regions, availability/status of various layer 3 and
    /// 4 protocols, types of NAT hole-punching available on the LAN, etc.
    pub net_info: Option<NetInfo<'a>>,

    /// The Tailscale node's SSH host public keys, if advertised. Wire key `sshHostKeys` —
    /// **lowerCamel**, the one HostInfo field with an EXPLICIT Go tag (`json:"sshHostKeys,omitempty"`)
    /// rather than an empty-name tag, so it is NOT PascalCase `SshHostKeys`.
    #[serde(rename = "sshHostKeys")]
    pub ssh_host_keys: Option<Vec<&'a str>>,

    /// If populated, the name of the cloud provider this Tailscale node is running in, such as
    /// "Amazon EC2", "DigitalOcean", etc. An empty string means the node isn't running in a cloud,
    /// or isn't able to determine if it's running in a cloud.
    pub cloud: &'a str,

    /// Indicates whether the Tailscale node is running in userspace (netstack) mode.
    pub userspace: Option<bool>,
    /// Indicates whether the Tailscale node's subnet router is running in userspace (netstack)
    /// mode.
    pub userspace_router: Option<bool>,

    /// Indicates whether the Tailscale node is running the app-connector service.
    pub app_connector: Option<bool>,

    /// Whether this node is willing to relay traffic for other peers as a **peer relay**
    /// (`Hostinfo.PeerRelay` in Go; the node runs a UDP relay server other peers can allocate
    /// endpoints on). This fork is a relay *client* only and never sets this true for itself, but
    /// parses it off peers so it can recognize which peers offer a relay.
    pub peer_relay: bool,
    /// Opaque hash of the most recent list of Tailnet services. A change in the hash value
    /// indicates the control server should fetch the new list of services from the Tailscale node
    /// via c2n (control-to-node).
    pub services_hash: &'a str,

    /// The Tailscale node's selected exit node. Empty when unselected. Wire key `ExitNodeID` (Go's
    /// `ID` acronym), not the `PascalCase` default `ExitNodeId`.
    #[serde(rename = "ExitNodeID")]
    pub exit_node_id: &'a str,
    /// Geographical location data about a Tailscale host. Location is optional and only set if
    /// explicitly declared by a node.
    pub location: Option<Location<'a>>,

    /// TPM device metadata, if available. Wire key `TPM` (acronym), not the `PascalCase` default
    /// `Tpm`.
    #[serde(rename = "TPM")]
    pub tpm: Option<TpmInfo<'a>>,
    /// Reports whether the node state is stored encrypted on-disk. The actual mechanism is platform-specific:
    /// * Apple nodes use the Keychain
    /// * Linux and Windows nodes use the TPM
    /// * Android apps use `EncryptedSharedPreferences`
    pub state_encrypted: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_relay_deserializes_pascalcase_true() {
        // Go encodes `Hostinfo.PeerRelay` PascalCase on the wire; a `true` must parse to `true`.
        let json = r#"{"PeerRelay":true}"#;
        let host_info: HostInfo = serde_json::from_str(json).unwrap();
        assert!(host_info.peer_relay);
    }

    #[test]
    fn hostname_with_escape_sequence_decodes() {
        // A user-set machine name can contain a JSON escape: `&` (Go's default `SetEscapeHTML`
        // marshals `&`→`&`), a literal `"`, or `\`. A borrowed `&str` could not decode the
        // escaped form and would fail the whole `HostInfo`/peer decode, silently dropping the peer.
        // `Cow` must decode it and yield the unescaped value.
        let json = r#"{"Hostname":"Tom & Jerry's \"Mac\\Book\""}"#;
        let host_info: HostInfo = serde_json::from_str(json).unwrap();
        assert_eq!(
            host_info.hostname.as_deref(),
            Some(r#"Tom & Jerry's "Mac\Book""#)
        );
    }

    #[test]
    fn hostname_without_escape_decodes() {
        // Fast path: a plain hostname decodes (borrows zero-copy, though that is not observable
        // from outside).
        let json = r#"{"Hostname":"my-host.local"}"#;
        let host_info: HostInfo = serde_json::from_str(json).unwrap();
        assert_eq!(host_info.hostname.as_deref(), Some("my-host.local"));
    }

    #[test]
    fn peer_relay_defaults_false_when_omitted() {
        // Omitting the field entirely must default to `false` (the `_ => #[serde(default)]`
        // apply-rule), not error or parse as anything else.
        let json = r#"{}"#;
        let host_info: HostInfo = serde_json::from_str(json).unwrap();
        assert!(!host_info.peer_relay);
    }

    #[test]
    fn acronym_fields_use_go_wire_keys_not_pascalcase_default() {
        // Go `tailcfg.Hostinfo` uses empty-name `json:",omitzero"` tags, so these marshal as the
        // PascalCase Go field name VERBATIM, preserving the acronym: `IPNVersion`, `OS`, `OSVersion`.
        // The struct's `rename_all = "PascalCase"` would instead lowercase the acronyms to
        // `IpnVersion`/`Os`/`OsVersion` — keys a strict Go decoder treats as unknown and DROPS, so the
        // advertised value would never land at control (and the wrong-cased key is itself a not-Go
        // tell). The per-field `#[serde(rename)]` overrides fix that. Distro* are regular words, so the
        // PascalCase default is already correct for them.
        let hi = HostInfo {
            ipn_version: "1.100.0",
            os: "linux",
            os_version: "6.8.0",
            distro: "ubuntu",
            distro_version: "24.04",
            distro_code_name: "noble",
            ..Default::default()
        };
        let v = serde_json::to_value(&hi).unwrap();
        // The acronym keys must be EXACTLY Go's, and the mangled PascalCase forms must be ABSENT.
        assert_eq!(
            v.get("IPNVersion").and_then(|x| x.as_str()),
            Some("1.100.0")
        );
        assert_eq!(v.get("OS").and_then(|x| x.as_str()), Some("linux"));
        assert_eq!(v.get("OSVersion").and_then(|x| x.as_str()), Some("6.8.0"));
        assert!(
            v.get("IpnVersion").is_none(),
            "wrong-cased IpnVersion must not appear"
        );
        assert!(v.get("Os").is_none(), "wrong-cased Os must not appear");
        assert!(
            v.get("OsVersion").is_none(),
            "wrong-cased OsVersion must not appear"
        );
        // Distro* (regular words) are correct under the PascalCase default.
        assert_eq!(v.get("Distro").and_then(|x| x.as_str()), Some("ubuntu"));
        assert_eq!(
            v.get("DistroVersion").and_then(|x| x.as_str()),
            Some("24.04")
        );
        assert_eq!(
            v.get("DistroCodeName").and_then(|x| x.as_str()),
            Some("noble")
        );

        // Decode side: control SENDS Go's keys, so we must also read them back (the rename governs
        // both directions). Round-trip through the real Go key names.
        let json = r#"{"IPNVersion":"1.100.0","OS":"linux","OSVersion":"6.8.0"}"#;
        let back: HostInfo = serde_json::from_str(json).unwrap();
        assert_eq!(back.ipn_version, "1.100.0");
        assert_eq!(back.os, "linux");
        assert_eq!(back.os_version, "6.8.0");
    }

    #[test]
    fn peer_relay_round_trips_and_skips_when_false() {
        // `true` serializes to include `"PeerRelay":true`.
        let mut host_info = HostInfo {
            peer_relay: true,
            ..Default::default()
        };
        let value = serde_json::to_value(&host_info).unwrap();
        assert_eq!(
            value.get("PeerRelay").and_then(serde_json::Value::as_bool),
            Some(true)
        );

        // `false` is omitted from the output (the crate's `bool => skip_serializing_if =
        // is_default` rule), matching the other bool fields' behavior.
        host_info.peer_relay = false;
        let value = serde_json::to_value(&host_info).unwrap();
        assert!(value.get("PeerRelay").is_none());
        // Sanity-check the shared bool behavior on a sibling bool field.
        assert!(value.get("ShieldsUp").is_none());
    }

    /// `Container` and `Env` wire-parity with Go `tailcfg.Hostinfo` (`Container opt.Bool` and
    /// `Env string`, both `json:",omitzero"`): a populated container marshals as the JSON bool
    /// `true`/`false` under the key `Container`, a known env as its short code under `Env`; and an
    /// unset container (`None`) / unknown env are BOTH omitted — Go's `omitzero` never sends
    /// `"Container":null` or `"Env":""`, and sending either would be a non-Go tell.
    #[test]
    fn container_and_env_wire_parity_with_go() {
        // Populated: Container=true (JSON bool), Env="k8s".
        let hi = HostInfo {
            container: Some(true),
            env: crate::EnvType::Kubernetes,
            ..Default::default()
        };
        let v = serde_json::to_value(&hi).unwrap();
        assert_eq!(
            v.get("Container").and_then(serde_json::Value::as_bool),
            Some(true),
            "Container is a JSON bool under the Go key `Container`"
        );
        assert_eq!(
            v.get("Env").and_then(|x| x.as_str()),
            Some("k8s"),
            "Env is the short code under the Go key `Env`"
        );

        // Container=false also serializes (it's a real, distinct signal, not the zero value).
        let hi_false = HostInfo {
            container: Some(false),
            ..Default::default()
        };
        let v = serde_json::to_value(&hi_false).unwrap();
        assert_eq!(
            v.get("Container").and_then(serde_json::Value::as_bool),
            Some(false)
        );

        // Unset: None container + Unknown env are BOTH omitted (Go `omitzero`), never `null`/`""`.
        let hi_unset = HostInfo::default();
        let v = serde_json::to_value(&hi_unset).unwrap();
        assert!(
            v.get("Container").is_none(),
            "an unset Container is omitted, not sent as null"
        );
        assert!(
            v.get("Env").is_none(),
            "an Unknown Env is omitted, not sent as an empty string"
        );

        // Decode side: control sends these keys; read them back.
        let back: HostInfo = serde_json::from_str(r#"{"Container":true,"Env":"k8s"}"#).unwrap();
        assert_eq!(back.container, Some(true));
        assert_eq!(back.env, crate::EnvType::Kubernetes);
    }
}
