use std::ffi::c_char;

use crate::{keys::persisted_key_state, util};

// Note: `advertise_routes` parses CIDR strings into `ipnet::IpNet`. IPv6 prefixes are accepted by
// the parser but dropped by the native config to uphold the IPv6-off anti-leak posture (handled in
// `tailscale::Config`).

/// Tailscale configuration.
///
/// This struct is safe to zero-initialize, in which case default values will be used.
/// You _must_ actually zero-initialize this struct in this case (`struct ts_config config = {0};`);
/// an uninitialized declaration (`struct ts_config config;`) is insufficient and may invoke UB.
///
/// On the Rust side, the [`Default`] instance for this type is equivalent to a C-side zero-
/// init.
#[derive(Default)]
#[repr(C)]
pub struct config<'a> {
    /// The control server URL to use.
    ///
    /// May be `NULL` to use the default value.
    pub control_server_url: *const c_char,

    /// The hostname to use. This will be the device's MagicDNS name, if it's available.
    ///
    /// May be `NULL` to use the default (the OS-reported hostname).
    pub hostname: *const c_char,

    /// An array of tags to be requested.
    ///
    /// Use `NULL` as the sentinel for the end of the array.
    ///
    /// May be `NULL` to indicate that no tags are requested.
    pub tags: *const *const c_char,

    /// The client name to report to the control server. This is reported as `Hostinfo.App`.
    ///
    /// May be `NULL` to use the default (`ts_ffi`).
    pub client_name: *const c_char,

    /// The key state to use.
    ///
    /// If `NULL`, ephemeral key state is generated.
    pub key_state: Option<&'a mut persisted_key_state>,

    /// Whether to accept (and route to) subnet routes advertised by peers (`--accept-routes`).
    ///
    /// Defaults to `false`.
    pub accept_routes: bool,

    /// Exit-node selector string (`--exit-node`): a tailnet IP or MagicDNS name.
    ///
    /// May be `NULL` (the default) for no exit node. Parsing is infallible: a non-IP string is
    /// treated as a MagicDNS name.
    pub exit_node: *const c_char,

    /// Subnet routes to advertise (`--advertise-routes`), as a `NULL`-terminated array of CIDR
    /// strings (e.g. `"10.0.0.0/24"`).
    ///
    /// May be `NULL` for no advertised routes. IPv6 prefixes are dropped by the native config
    /// (IPv6-off posture).
    pub advertise_routes: *const *const c_char,

    /// Whether to advertise this node as an exit node (`--advertise-exit-node`).
    ///
    /// Defaults to `false`.
    pub advertise_exit_node: bool,

    /// TCP ports the inbound forwarder splices to real OS sockets, for every advertised route.
    ///
    /// Points to `forward_tcp_ports_len` `uint16_t` values. May be `NULL` (with len 0) for none.
    pub forward_tcp_ports: *const u16,
    /// Number of entries in [`forward_tcp_ports`](Self::forward_tcp_ports).
    pub forward_tcp_ports_len: usize,

    /// UDP ports the inbound forwarder splices to real OS sockets, for every advertised route.
    ///
    /// Points to `forward_udp_ports_len` `uint16_t` values. May be `NULL` (with len 0) for none.
    pub forward_udp_ports: *const u16,
    /// Number of entries in [`forward_udp_ports`](Self::forward_udp_ports).
    pub forward_udp_ports_len: usize,

    /// Forward **all** TCP/UDP ports on every advertised route (like a Go subnet router). When
    /// `true`, the explicit port sets are ignored. Defaults to `false`.
    pub forward_all_ports: bool,

    /// Whether exit-node (`0.0.0.0/0`) inbound flows actually egress via this host's real origin
    /// IP. Anti-leak opt-in, separate from `advertise_exit_node`; defaults to `false`
    /// (fail-closed).
    pub forward_exit_egress: bool,
}

impl config<'_> {
    /// Convert this config into a [`tailscale::Config`].
    ///
    /// # Safety
    ///
    /// All string fields (including elements of `tags`, if any) must be either null or
    /// NUL-terminated and valid for reads up to the nul-terminator.
    ///
    /// The `tags` field must be either null or a pointer to a contiguous array of valid,
    /// aligned, NUL-terminated strings, fully contained in a single
    /// [allocation](https://doc.rust-lang.org/std/ptr/index.html#allocation). A null
    /// pointer must be used to terminate the array.
    pub unsafe fn to_ts_config(&self) -> tailscale::Config {
        let mut cfg = tailscale::Config::default();

        // SAFETY: validity ensured by preconditions
        let ctrl_url = unsafe { util::str(self.control_server_url) }.and_then(|u| u.parse().ok());

        if let Some(u) = ctrl_url {
            cfg.control_server_url = u;
        }

        // SAFETY: validity ensured by preconditions
        if let Some(hostname) = unsafe { util::str(self.hostname) } {
            cfg.requested_hostname = Some(hostname.to_string());
        }

        // SAFETY: validity ensured by preconditions
        cfg.client_name = Some(
            unsafe { util::str(self.client_name) }
                .unwrap_or("ts_ffi")
                .to_owned(),
        );

        if let Some(key_state) = &self.key_state {
            cfg.key_state = (&**key_state).into();
        }

        // SAFETY: by preconditions and function termination on null tag
        cfg.requested_tags = unsafe {
            load_sentinel_array(self.tags, |&tag| {
                if tag.is_null() {
                    return None;
                };

                match util::str(tag) {
                    Some(tag_str) => Some(Some(tag_str.to_owned())),
                    None => {
                        tracing::error!("skipping invalid requested tag");
                        Some(None)
                    }
                }
            })
        }
        .collect();

        cfg.accept_routes = self.accept_routes;
        cfg.advertise_exit_node = self.advertise_exit_node;
        cfg.forward_all_ports = self.forward_all_ports;
        cfg.forward_exit_egress = self.forward_exit_egress;

        // SAFETY: validity ensured by preconditions
        cfg.exit_node = unsafe { util::str(self.exit_node) }
            // `ExitNodeSelector::from_str` is infallible.
            .and_then(|s| s.parse().ok());

        // SAFETY: by preconditions and termination on the null sentinel.
        cfg.advertise_routes = unsafe {
            load_sentinel_array(self.advertise_routes, |&route| {
                if route.is_null() {
                    return None;
                }

                match util::str(route).and_then(|s| s.parse().ok()) {
                    Some(net) => Some(Some(net)),
                    None => {
                        tracing::error!("skipping invalid advertised route");
                        Some(None)
                    }
                }
            })
        }
        .collect();

        // SAFETY: validity ensured by preconditions
        cfg.forward_tcp_ports =
            unsafe { load_ports(self.forward_tcp_ports, self.forward_tcp_ports_len) };
        // SAFETY: validity ensured by preconditions
        cfg.forward_udp_ports =
            unsafe { load_ports(self.forward_udp_ports, self.forward_udp_ports_len) };

        cfg
    }
}

/// Copy `len` `u16` port values starting at `ports` into a `Vec`.
///
/// # Safety
///
/// `ports` must be null (in which case an empty `Vec` is returned regardless of `len`), or valid
/// for reads of `len` `u16` values per [`core::slice::from_raw_parts`].
unsafe fn load_ports(ports: *const u16, len: usize) -> Vec<u16> {
    if ports.is_null() {
        return Vec::new();
    }

    // SAFETY: ensured by function precondition
    unsafe { core::slice::from_raw_parts(ports, len) }.to_vec()
}

/// Iterate a raw pointer `ary` as a C-style sentinel-terminated array.
///
/// Starting at `ary`, increment `ary` (strides of `size_of::<T>()`) until the pointee does
/// not satisfy `elem_txfm`, a `filter_map`-style simultaneous predicate-and-transform.
///
/// # Safety
///
/// `ary` must be either null or follow the rules for [`std::slice::from_raw_parts`], except
/// that it needn't have a definite length known before calling this function. The extents
/// of `ary` are defined by `elem_txfm`: the first element that returns `None` under
/// `elem_txfm` is the final (sentinel) element of the array (excluded here from the
/// returned iterated elements, but part of the memory extents).
///
/// The extents of `ary` must be contiguous and aligned, and its elements must be valid for
/// reads and properly-initialized. They must obey rust mutability rules -- no
/// mutations to the extents of `ary` are permitted for the lifetime of the returned
/// iterator.
///
/// Note that this definition implies a strong safety condition on the definition
/// of `elem_txfm`: it defines what memory is accessed by this function and must not permit
/// iteration beyond valid bounds.
unsafe fn load_sentinel_array<'t, T, It>(
    mut ary: *const T,
    elem_txfm: impl Fn(&T) -> Option<It> + 't,
) -> impl Iterator<Item = It::Item>
where
    T: 't,
    It: IntoIterator,
{
    std::iter::from_fn(move || {
        if ary.is_null() {
            return None;
        }

        // SAFETY: ref-validity ensured by preconditions, non-nullity by above check
        let it = match elem_txfm(unsafe { ary.as_ref().unwrap() }) {
            Some(u) => u,
            None => {
                return None;
            }
        };

        // SAFETY: ensured by preconditions
        ary = unsafe { ary.offset(1) };

        Some(it)
    })
    .flatten()
}

#[cfg(test)]
mod test {
    use std::{ffi::CString, ptr::null};

    use super::*;

    #[test]
    fn sentinel_array() {
        let mut v = unsafe { load_sentinel_array::<u8, _>(null(), |_| Option::<[u8; 1]>::None) };
        assert!(v.next().is_none());

        let ary = [0u8, 1, 2, 3, 4, 5, 6, 128, 32];

        let mut v =
            unsafe { load_sentinel_array(&ary as *const u8, |_elt| Option::<Option<u8>>::None) };
        assert!(v.next().is_none());

        let v = unsafe {
            load_sentinel_array(
                &ary as *const u8,
                |&elt| {
                    if elt < 10 { Some([elt]) } else { None }
                },
            )
        }
        .collect::<Vec<_>>();
        assert!(!v.is_empty());
        assert_eq!(v, ary[..=6].to_vec());
    }

    #[test]
    fn tags() {
        let tag_foo = CString::new("foo").unwrap();
        let tag_bar = CString::new("bar").unwrap();

        let config = config {
            tags: &[tag_foo.as_ptr(), tag_bar.as_ptr(), null()] as *const *const c_char,
            ..Default::default()
        };

        let cfg = unsafe { config.to_ts_config() };
        assert_eq!(cfg.requested_tags, vec!["foo", "bar"]);
    }

    #[test]
    fn forwarding_defaults() {
        let cfg = unsafe { config::default().to_ts_config() };
        assert!(!cfg.accept_routes);
        assert!(!cfg.advertise_exit_node);
        assert!(!cfg.forward_all_ports);
        assert!(!cfg.forward_exit_egress);
        assert!(cfg.exit_node.is_none());
        assert!(cfg.advertise_routes.is_empty());
        assert!(cfg.forward_tcp_ports.is_empty());
        assert!(cfg.forward_udp_ports.is_empty());
    }

    #[test]
    fn forwarding_fields() {
        let exit = CString::new("exit-host").unwrap();
        let r1 = CString::new("10.0.0.0/24").unwrap();
        let r2 = CString::new("192.168.1.0/24").unwrap();
        let tcp_ports = [80u16, 443];
        let udp_ports = [53u16];

        let config = config {
            accept_routes: true,
            advertise_exit_node: true,
            forward_all_ports: true,
            forward_exit_egress: true,
            exit_node: exit.as_ptr(),
            advertise_routes: &[r1.as_ptr(), r2.as_ptr(), null()] as *const *const c_char,
            forward_tcp_ports: tcp_ports.as_ptr(),
            forward_tcp_ports_len: tcp_ports.len(),
            forward_udp_ports: udp_ports.as_ptr(),
            forward_udp_ports_len: udp_ports.len(),
            ..Default::default()
        };

        let cfg = unsafe { config.to_ts_config() };
        assert!(cfg.accept_routes);
        assert!(cfg.advertise_exit_node);
        assert!(cfg.forward_all_ports);
        assert!(cfg.forward_exit_egress);
        assert_eq!(
            cfg.exit_node,
            Some(tailscale::ExitNodeSelector::Name("exit-host".into()))
        );
        assert_eq!(
            cfg.advertise_routes,
            vec![
                "10.0.0.0/24".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
            ]
        );
        assert_eq!(cfg.forward_tcp_ports, vec![80, 443]);
        assert_eq!(cfg.forward_udp_ports, vec![53]);
    }
}
