use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{Endpoint, HostInfo, MapRequest, NetInfo};

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
        self.host_info_mut().hostname = Some(hostname);
        self
    }

    /// Set the [`NetInfo::preferred_derp`] field (inside [`MapRequest::host_info`] ->
    /// [`HostInfo::net_info`]).
    pub fn preferred_derp(mut self, value: ts_derp::RegionId) -> Self {
        self.net_info_mut().preferred_derp = Some(value.0.into());
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
}
