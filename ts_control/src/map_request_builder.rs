use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{Endpoint, HostInfo, MapRequest, NetInfo, Service};

/// Builder type for [`MapRequest`]s; smooths over the annoying parts of creating a request.
#[derive(Debug, Clone)]
pub struct MapRequestBuilder<'a> {
    req: MapRequest<'a>,
}

impl<'a> MapRequestBuilder<'a> {
    /// Create a new [`MapRequestBuilder`]. By default:
    /// - [`MapRequest::keep_alive`] is `false`
    /// - [`MapRequest::omit_peers`] is `true`
    /// - [`MapRequest::stream`] is `false`
    /// - [`MapRequest::host_info`]:
    ///     - [`HostInfo::hostname`] is populated from [`TailnetPeerConfig::hostname`]
    ///     - [`HostInfo::net_info`] is `None`, therefore:
    ///         - [`NetInfo::derp_latency`][crate::types::NetInfo::derp_latency] is not populated
    ///         - [`NetInfo::preferred_derp`][crate::types::NetInfo::preferred_derp] is not populated
    pub fn new(key_state: &ts_keys::NodeState) -> Self {
        Self {
            req: MapRequest {
                version: CapabilityVersion::CURRENT,

                keep_alive: false,
                omit_peers: true,
                stream: false,

                node_key: key_state.node_keys.public,
                disco_key: key_state.disco_keys.public,

                host_info: Some(HostInfo::default()),
                ..Default::default()
            },
        }
    }

    /// Consumes this [`MapRequestBuilder`] and returns a [`MapRequest`] with the configured
    /// values.
    pub fn build(self) -> MapRequest<'a> {
        self.req
    }

    /// Set the [`MapRequest::keep_alive`] field.
    pub fn keep_alive(mut self, value: bool) -> Self {
        self.req.keep_alive = value;
        self
    }

    /// Set the [`MapRequest::omit_peers`] field.
    pub fn omit_peers(mut self, value: bool) -> Self {
        self.req.omit_peers = value;
        self
    }

    /// Set the [`MapRequest::stream`] field.
    pub fn stream(mut self, value: bool) -> Self {
        self.req.stream = value;
        self
    }

    /// Set the [`HostInfo::hostname`] field.
    pub fn hostname(mut self, hostname: &'a str) -> Self {
        self.host_info_mut().hostname = Some(hostname.into());
        self
    }

    /// Set the [`NetInfo::preferred_derp`] field (inside [`MapRequest::host_info`] ->
    /// [`HostInfo::net_info`]).
    pub fn preferred_derp(mut self, value: ts_derp::RegionId) -> Self {
        self.net_info_mut().preferred_derp = Some(value.0.into());
        self
    }

    /// Set the [`NetInfo::working_udp`] field (Go `NetInfo.WorkingUDP`): whether the node has UDP
    /// internet connectivity, i.e. a STUN reflexive address was learned. A real `tailscaled` reports
    /// this; omitting it leaves control's NAT picture blank.
    pub fn working_udp(mut self, value: bool) -> Self {
        self.net_info_mut().working_udp = Some(value);
        self
    }

    /// Set the [`NetInfo::mapping_varies_by_dest_ip`] field (Go `NetInfo.MappingVariesByDestIP`):
    /// whether the NAT maps the bound socket to different reflexive addr:ports per destination
    /// (symmetric NAT). Mirrors magicsock's `is_symmetric_nat` determination.
    pub fn mapping_varies_by_dest_ip(mut self, value: bool) -> Self {
        self.net_info_mut().mapping_varies_by_dest_ip = Some(value);
        self
    }

    /// Set the [`NetInfo::derp_latency`] field (inside [`MapRequest::host_info`] ->
    /// [`HostInfo::net_info`]).
    pub fn derp_latencies(mut self, value: impl IntoIterator<Item = (&'a str, f64)>) -> Self {
        self.net_info_mut().derp_latency = Some(value.into_iter().collect());

        self
    }

    /// Advertise the node's magicsock UDP endpoints (ip:port candidates) to the control
    /// server so peers can learn where to attempt direct connections.
    pub fn endpoints(mut self, endpoints: impl IntoIterator<Item = Endpoint>) -> Self {
        self.req.endpoints = endpoints.into_iter().collect();
        self
    }

    /// Advertise the set of IP prefixes this node can route (`HostInfo.RoutableIPs`), so the
    /// control server can grant it as a subnet router and/or exit node. When the iterator yields
    /// nothing, the field is left as `None` and omitted from the wire request (advertise nothing).
    pub fn routable_ips(mut self, routes: impl IntoIterator<Item = ipnet::IpNet>) -> Self {
        let routes: alloc::vec::Vec<ipnet::IpNet> = routes.into_iter().collect();
        self.host_info_mut().routable_ips = (!routes.is_empty()).then_some(routes);
        self
    }

    /// Request to reattach to a prior map session (`MapRequest::map_session_handle` +
    /// `map_session_seq`), so a reconnect resumes the delta stream instead of cold-restarting.
    ///
    /// `handle` is the opaque session handle echoed by control in the first `MapResponse` of the
    /// previous session; `seq` is the last sequence number this client processed in that session.
    /// Control may honor the request (sending only `seq`-greater deltas) or ignore it and start a
    /// fresh session with a full netmap — either is safe. Only meaningful when
    /// [`stream`](Self::stream) is `true`. An empty `handle` leaves both fields at their defaults
    /// (start a new session).
    pub fn map_session(mut self, handle: &'a str, seq: i64) -> Self {
        self.req.map_session_handle = handle;
        self.req.map_session_seq = if handle.is_empty() { 0 } else { seq };
        self
    }

    /// Set the client application name (`HostInfo.App`) and IPN version (`HostInfo.IPNVersion`)
    /// that this node reports to control, so the tailnet admin can identify the client build.
    pub fn client_info(mut self, app: &'a str, ipn_version: &'a str) -> Self {
        let host_info = self.host_info_mut();
        host_info.app = app;
        host_info.ipn_version = ipn_version;
        self
    }

    /// Overlay the detected host-environment facts (`HostInfo.OS`/`OSVersion`/`GoArch`/`Machine`,
    /// plus `Package`/`Userspace`) onto the map request, so every map poll advertises the same dense,
    /// genuine-looking Hostinfo a Tailscale/tsnet node sends — not an empty `OS` with a crate-version
    /// `IPNVersion`. `IPNVersion` is also taken from `host` (its `version.Long()`-shaped value)
    /// rather than the `client_info` arg, so the two stay consistent.
    pub fn host_environment(mut self, host: &'a crate::hostinfo::HostInfoData) -> Self {
        let host_info = self.host_info_mut();
        host_info.ipn_version = &host.ipn_version;
        host_info.os = &host.os;
        host_info.os_version = &host.os_version;
        host_info.go_arch = &host.go_arch;
        host_info.go_version = &host.go_version;
        host_info.machine = &host.machine;
        host_info.distro = &host.distro;
        host_info.distro_version = &host.distro_version;
        host_info.distro_code_name = &host.distro_code_name;
        host_info.container = host.container;
        host_info.env = host.env;
        host_info.package = crate::hostinfo::PACKAGE_TSNET;
        host_info.userspace = Some(true);
        self
    }

    /// Advertise the set of ACL tags this node wants to claim (`HostInfo.RequestTags`), so a
    /// tag-keyed control ACL (e.g. a self-hosted control plane's route auto-approver) can match it. When the
    /// iterator yields nothing, the field is left as `None` and omitted from the wire request
    /// (claim no tags).
    pub fn request_tags(mut self, tags: impl IntoIterator<Item = &'a str>) -> Self {
        let tags: alloc::vec::Vec<&'a str> = tags.into_iter().collect();
        self.host_info_mut().request_tags = (!tags.is_empty()).then_some(tags);
        self
    }

    /// Advertise the services this node runs (`HostInfo.Services`), so peers and control can
    /// discover this node's peerAPI port and whether it proxies DNS as an exit node. When the
    /// iterator yields nothing, the field is left as `None` and omitted from the wire request
    /// (advertise no services).
    pub fn services(mut self, services: impl IntoIterator<Item = Service<'a>>) -> Self {
        let services: alloc::vec::Vec<Service<'a>> = services.into_iter().collect();
        self.host_info_mut().services = (!services.is_empty()).then_some(services);
        self
    }

    /// Ask control to wire this node up server-side for Tailscale Funnel
    /// (`HostInfo.WireIngress`, capver 113), so the DNS/ingress records a Funnel node needs are
    /// provisioned even when no Funnel endpoint is currently live. Mirrors Go `tsnet`'s
    /// "would like to be wired up for Funnel" signal. `HostInfo.IngressEnabled` (endpoints actually
    /// active) is intentionally left unset: this fork's [`crate::listen_funnel`] is fail-closed, so
    /// no Funnel endpoint ever goes live.
    pub fn wire_ingress(mut self, value: bool) -> Self {
        self.host_info_mut().wire_ingress = value;
        self
    }

    /// Signal that this node currently has at least one live Tailscale Funnel endpoint
    /// (`HostInfo.IngressEnabled`), set while a [`crate::listen_funnel`] listener is active. Unlike
    /// [`wire_ingress`](Self::wire_ingress) (the "would like to be wired up" hint), this advertises
    /// that public ingress is *actually* being served, so control routes Funnel traffic to this node
    /// via its ingress relay. Per Go's optimization, `IngressEnabled` implies `WireIngress`, so the
    /// caller sends this *instead of* `WireIngress` when a Funnel listener is up. Defaults unset
    /// (no live endpoint) — fail-closed: a node only advertises ingress while it can serve it.
    pub fn ingress_enabled(mut self, value: bool) -> Self {
        self.host_info_mut().ingress_enabled = value;
        self
    }

    /// Set the opaque VIP-services hash this node advertises (`HostInfo.ServicesHash`), the
    /// advertise-side signal that tells control to (re)fetch the node's hosted VIP-service list via
    /// the c2n `GET /vip-services` endpoint when it changes. Compute it with
    /// [`crate::services_hash`] over [`Config::advertised_vip_services`](crate::Config::advertised_vip_services).
    /// An empty string (the default / no-services-advertised case) leaves the wire field omitted, so
    /// non-advertising nodes are byte-for-byte unchanged.
    pub fn services_hash(mut self, hash: &'a str) -> Self {
        self.host_info_mut().services_hash = hash;
        self
    }

    fn host_info_mut(&mut self) -> &mut HostInfo<'a> {
        self.req.host_info.get_or_insert_default()
    }

    fn net_info_mut(&mut self) -> &mut NetInfo<'a> {
        self.host_info_mut().net_info.get_or_insert_default()
    }
}

#[cfg(test)]
mod tests {
    use ts_control_serde::EndpointType;

    use super::*;

    #[test]
    fn endpoints_setter_populates_request() {
        let node_state = ts_keys::NodeState::generate();

        let endpoint = Endpoint {
            endpoint: "203.0.113.7:41641".parse().unwrap(),
            ty: EndpointType::Stun,
        };

        let req = MapRequestBuilder::new(&node_state)
            .endpoints([endpoint])
            .build();

        assert_eq!(req.endpoints.len(), 1);
        assert_eq!(req.endpoints[0], endpoint);
    }

    #[test]
    fn routable_ips_setter_populates_host_info() {
        let node_state = ts_keys::NodeState::generate();

        let route: ipnet::IpNet = "10.0.0.0/24".parse().unwrap();
        let req = MapRequestBuilder::new(&node_state)
            .routable_ips([route])
            .build();

        assert_eq!(
            req.host_info.unwrap().routable_ips,
            Some(alloc::vec![route])
        );
    }

    #[test]
    fn routable_ips_setter_empty_leaves_field_none() {
        let node_state = ts_keys::NodeState::generate();

        let req = MapRequestBuilder::new(&node_state).routable_ips([]).build();

        // Empty advertise set: the field stays None and is omitted from the wire request.
        assert_eq!(req.host_info.unwrap().routable_ips, None);
    }

    /// The `hostname` setter populates `HostInfo.hostname` — the mechanism a runtime
    /// `Device::set_hostname` relies on (its side-MapRequest carries the new name here).
    #[test]
    fn hostname_setter_populates_host_info() {
        let node_state = ts_keys::NodeState::generate();

        let req = MapRequestBuilder::new(&node_state)
            .hostname("my-new-host")
            .build();

        assert_eq!(
            req.host_info.unwrap().hostname.as_deref(),
            Some("my-new-host")
        );
    }

    #[test]
    fn request_tags_setter_populates_host_info() {
        let node_state = ts_keys::NodeState::generate();

        let req = MapRequestBuilder::new(&node_state)
            .request_tags(["tag:exit", "tag:server"])
            .build();

        assert_eq!(
            req.host_info.unwrap().request_tags,
            Some(alloc::vec!["tag:exit", "tag:server"])
        );
    }

    #[test]
    fn request_tags_setter_empty_leaves_field_none() {
        let node_state = ts_keys::NodeState::generate();

        let req = MapRequestBuilder::new(&node_state).request_tags([]).build();

        // Empty tag set: the field stays None and is omitted from the wire request.
        assert_eq!(req.host_info.unwrap().request_tags, None);
    }

    #[test]
    fn wire_ingress_setter_populates_host_info() {
        let node_state = ts_keys::NodeState::generate();

        let req = MapRequestBuilder::new(&node_state)
            .wire_ingress(true)
            .build();
        let hi = req.host_info.unwrap();
        // WireIngress is the capver-113 "wire me up for Funnel" signal; IngressEnabled (endpoints
        // actually live) must stay false — listen_funnel is fail-closed in this fork.
        assert!(hi.wire_ingress);
        assert!(!hi.ingress_enabled);
    }

    #[test]
    fn wire_ingress_setter_defaults_false() {
        let node_state = ts_keys::NodeState::generate();

        let req = MapRequestBuilder::new(&node_state).build();
        assert!(!req.host_info.unwrap().wire_ingress);
    }

    #[test]
    fn services_hash_setter_populates_host_info() {
        let node_state = ts_keys::NodeState::generate();

        let req = MapRequestBuilder::new(&node_state)
            .services_hash("deadbeef")
            .build();
        assert_eq!(req.host_info.unwrap().services_hash, "deadbeef");
    }

    #[test]
    fn services_hash_setter_defaults_empty() {
        let node_state = ts_keys::NodeState::generate();

        let req = MapRequestBuilder::new(&node_state).build();
        // Empty hash = no VIP services advertised; the field is omitted from the wire request.
        assert_eq!(req.host_info.unwrap().services_hash, "");
    }

    #[test]
    fn map_session_setter_populates_resume_fields() {
        let node_state = ts_keys::NodeState::generate();

        let req = MapRequestBuilder::new(&node_state)
            .map_session("sess-abc", 42)
            .build();

        assert_eq!(req.map_session_handle, "sess-abc");
        assert_eq!(req.map_session_seq, 42);
    }

    #[test]
    fn map_session_empty_handle_zeroes_seq() {
        let node_state = ts_keys::NodeState::generate();

        // No prior session: a stray seq must not be sent without a handle (control would ignore
        // it, but we keep the wire request clean and unambiguous).
        let req = MapRequestBuilder::new(&node_state)
            .map_session("", 99)
            .build();

        assert_eq!(req.map_session_handle, "");
        assert_eq!(req.map_session_seq, 0);
    }

    /// `host_environment` populates the loud identity fields (OS, IPNVersion, GoVersion, Machine,
    /// Package, Userspace). Every map request — including the side-command (SetDerpHomeRegion /
    /// SetEndpoints / SetRoutableIPs / SetHostname) requests, not just the streaming re-register —
    /// must carry these, mirroring Go attaching the full `hostInfoLocked()` to every `sendMapRequest`.
    /// A request built WITHOUT `host_environment` carries an empty Hostinfo (blank OS/IPNVersion),
    /// which is the regression this guards: the side arms now all call `.host_environment(&host)`.
    #[test]
    fn host_environment_populates_identity_fields() {
        let node_state = ts_keys::NodeState::generate();
        let host = crate::hostinfo::HostInfoData::detect();

        // With host_environment (what every arm now does): identity fields are populated.
        let with = MapRequestBuilder::new(&node_state)
            .host_environment(&host)
            .build();
        let hi = with.host_info.expect("host_info present");
        assert!(!hi.os.is_empty(), "OS must be populated");
        assert!(!hi.ipn_version.is_empty(), "IPNVersion must be populated");
        assert_eq!(hi.package, crate::hostinfo::PACKAGE_TSNET);
        assert_eq!(hi.userspace, Some(true));

        // Without it (the pre-fix side-arm behavior): the loud fields are empty — the tell this
        // fixes. (Asserted so the contrast is explicit and a future drop of host_environment from an
        // arm visibly regresses to this.)
        let without = MapRequestBuilder::new(&node_state).routable_ips([]).build();
        let bare = without.host_info.unwrap_or_default();
        assert!(bare.os.is_empty() && bare.ipn_version.is_empty());
    }
}
