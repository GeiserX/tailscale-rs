use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::net::{IpAddr, SocketAddr};

/// A control-pushed static host record (Go `tailcfg.DNSConfig.ExtraRecords`). MagicDNS answers
/// these alongside tailnet peer names. Only `A`/`AAAA` records are kept; other record types are
/// dropped, since the responder only serves address records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraRecord {
    /// The record name, canonicalized: lowercased, no trailing dot.
    pub name: String,
    /// The address bound to `name`. `V4` answers `A`; `V6` answers `AAAA`.
    pub addr: IpAddr,
}

/// An upstream DNS resolver to forward non-overlay queries to (Go `tailcfg.DNSResolver`).
///
/// Only plaintext UDP resolvers (`IP:port`, default port 53) are supported today; encrypted
/// transports (DoH/DoT) are parsed off the wire but dropped here as a documented TODO seam —
/// adding them only requires extending [`from_serde`][DnsConfig::from_serde] and the magic_dns
/// forwarder, not the wire format.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Resolver {
    /// The transport/address of this resolver. Only [`ResolverTransport::Udp`] is supported.
    pub transport: ResolverTransport,
    /// Continue using this resolver even while an exit node is in use (Go `UseWithExitNode`).
    ///
    /// When an exit node is selected, recursive DNS is normally delegated to the exit node's
    /// peerAPI DoH server; a resolver with this flag set is kept locally instead (e.g. a split-DNS
    /// server reachable over the tailnet that the exit node can't see). See
    /// [`DnsConfig::resolvers_with_exit_node`].
    pub use_with_exit_node: bool,
}

/// The transport of a [`Resolver`]. Only plaintext UDP is forwarded today; encrypted transports are
/// dropped at parse time (see `Resolver::from_serde`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResolverTransport {
    /// Classic plaintext DNS over UDP at this address.
    Udp(SocketAddr),
}

impl Resolver {
    /// Build a UDP resolver from the borrowed serde view, or `None` for an encrypted transport
    /// (DoH/DoT/DoH-over-WireGuard) we do not yet forward to.
    pub(crate) fn from_serde(r: &ts_control_serde::DnsResolver<'_>) -> Option<Self> {
        match r.addr {
            ts_control_serde::DnsResolverAddr::Plaintext(addr) => Some(Resolver {
                transport: ResolverTransport::Udp(addr),
                use_with_exit_node: r.use_with_exit_node,
            }),
            // TODO: support DoH/DoT/HttpWireguard upstreams. Until then they are dropped so we
            // never silently treat an encrypted resolver as a plaintext one.
            _ => None,
        }
    }

    /// The plaintext UDP socket address of this resolver.
    pub fn udp_addr(&self) -> SocketAddr {
        match self.transport {
            ResolverTransport::Udp(addr) => addr,
        }
    }
}

/// Collect the supported (UDP) resolvers from a serde resolver list, dropping `None` entries and
/// unsupported transports.
fn resolvers_from_serde(list: &[Option<ts_control_serde::DnsResolver<'_>>]) -> Vec<Resolver> {
    list.iter()
        .filter_map(|r| r.as_ref())
        .filter_map(Resolver::from_serde)
        .collect()
}

/// Owned DNS configuration distilled from the control MapResponse for the MagicDNS responder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsConfig {
    /// MagicDNS enabled (Go `Proxied`). When false the responder serves nothing (fail closed).
    pub magic_dns: bool,
    /// Tailnet DNS suffix(es), lowercased, no trailing dot, e.g. "user.ts.net".
    pub search_domains: Vec<String>,
    /// Control-pushed static `A`/`AAAA` host records (Go `ExtraRecords`).
    pub extra_records: Vec<ExtraRecord>,
    /// Global upstream resolvers (Go `Resolvers`) used to recursively resolve non-overlay names
    /// when no split-DNS route and no fallback resolver matches.
    pub resolvers: Vec<Resolver>,
    /// Split-DNS routes (Go `Routes`): suffix (canonicalized, no leading/trailing dot) -> the
    /// upstreams that answer that suffix. An **empty** upstream list is a negative route: names
    /// under that suffix are not resolved (Go keeps them on the built-in resolver, which for us
    /// means fail-closed NXDOMAIN unless an overlay/extra record matches).
    pub routes: BTreeMap<String, Vec<Resolver>>,
    /// Fallback resolvers (Go `FallbackResolvers`) used for non-overlay names that match no route,
    /// preferred over [`resolvers`][DnsConfig::resolvers].
    pub fallback_resolvers: Vec<Resolver>,
    /// DNS suffixes this node, **when acting as an exit-node DNS proxy**, must not answer (Go
    /// `ExitNodeFilteredSet`). Entries are lowercased, no trailing dot. An entry starting with a
    /// period is a suffix match (but `.a.b` does NOT match `a.b` — a real prefix label is
    /// required); an entry without a leading period is an exact match. Matching is
    /// case-insensitive. A filtered name is answered with `REFUSED`. See
    /// [`DnsConfig::exit_node_filters`].
    pub exit_node_filtered_set: Vec<String>,
    /// DNS names control will assist provisioning TLS certs for (Go `tailcfg.DNSConfig.CertDomains`):
    /// the cert-eligible FQDNs for this node, without trailing dots or `_acme-challenge.` prefix.
    /// Surfaced verbatim (Go returns `slices.Clone(nm.DNS.CertDomains)`); empty when control sent none.
    pub cert_domains: Vec<String>,
}

impl DnsConfig {
    /// Build the owned config from the borrowed serde view parsed off the wire.
    pub fn from_serde(c: &ts_control_serde::DnsConfig<'_>) -> Self {
        DnsConfig {
            magic_dns: c.magic_dns,
            // Drop any search domain whose canonical suffix is empty (e.g. "" or ".").
            // An empty suffix used in `ends_with` matching matches every name, which would
            // silently turn the resolver into a match-all/block-all wildcard. Fail closed.
            search_domains: c
                .search_domains
                .iter()
                .map(|domain| canon(domain))
                .filter(|domain| !domain.is_empty())
                .collect(),
            extra_records: c
                .extra_records
                .iter()
                .filter_map(|rec| match rec {
                    ts_control_serde::DnsRecord::A { name, value } => Some(ExtraRecord {
                        name: canon(name),
                        addr: IpAddr::V4(*value),
                    }),
                    ts_control_serde::DnsRecord::AAAA { name, value } => Some(ExtraRecord {
                        name: canon(name),
                        addr: IpAddr::V6(*value),
                    }),
                    // The responder only serves address records; drop anything else.
                    ts_control_serde::DnsRecord::Other { .. } => None,
                })
                .collect(),
            resolvers: resolvers_from_serde(&c.resolvers),
            // Canonicalize route keys and drop any whose suffix is empty (e.g. "" or ".").
            // An empty route key used in `ends_with` matching matches every name, which would
            // silently capture all names as a route (match-all). Fail closed.
            routes: c
                .routes
                .iter()
                .map(|(suffix, upstreams)| {
                    let upstreams = upstreams
                        .as_deref()
                        .map(resolvers_from_serde)
                        .unwrap_or_default();
                    (canon(suffix), upstreams)
                })
                .filter(|(suffix, _)| !suffix.is_empty())
                .collect(),
            fallback_resolvers: resolvers_from_serde(&c.fallback_resolvers),
            // Canonicalize each filtered-set entry by lowercasing only. We deliberately do NOT
            // strip a leading period here: a leading period is semantically significant (it marks
            // a suffix-match entry, per `exit_node_filters`). Trailing dots are stripped so a
            // wire entry like "Example.com." matches our canonicalized query names.
            exit_node_filtered_set: c
                .exit_node_filtered_set
                .iter()
                .map(|e| e.strip_suffix('.').unwrap_or(e).to_ascii_lowercase())
                .filter(|e| !e.is_empty() && e != ".")
                .collect(),
            // Carried verbatim (Go `slices.Clone(nm.DNS.CertDomains)` — no canonicalization). These
            // are the names a `ListenTLS`/cert-issuance consumer requests, so they must match what
            // control issued exactly.
            cert_domains: c.cert_domains.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// Whether `name` (a canonical query name: lowercased, no trailing dot) is in this config's
    /// [`exit_node_filtered_set`][DnsConfig::exit_node_filtered_set] and so must be `REFUSED` when
    /// this node answers as an exit-node DNS proxy (Go `dnsConfigForNetmap`'s filtered-set check).
    ///
    /// An entry with a leading period is a suffix match requiring a real label before it (`.a.b`
    /// matches `x.a.b` but not `a.b`); an entry without a leading period is an exact match.
    /// Matching is case-insensitive (both sides are already lowercased).
    pub fn exit_node_filters(&self, name: &str) -> bool {
        self.exit_node_filtered_set.iter().any(|entry| {
            if let Some(suffix) = entry.strip_prefix('.') {
                // ".a.b" matches "x.a.b" (ends with ".a.b") but not "a.b" itself.
                name.len() > suffix.len() + 1 && name.ends_with(suffix) && {
                    let boundary = name.len() - suffix.len() - 1;
                    name.as_bytes()[boundary] == b'.'
                }
            } else {
                name == entry
            }
        })
    }

    /// The resolvers to keep when an exit node is active: those flagged
    /// [`use_with_exit_node`][Resolver::use_with_exit_node]. When an exit node is selected,
    /// recursive resolution is delegated to it, except for these explicitly-flagged resolvers (Go
    /// keeps `UseWithExitNode` resolvers in the local config).
    pub fn resolvers_with_exit_node(&self) -> impl Iterator<Item = &Resolver> {
        self.resolvers.iter().filter(|r| r.use_with_exit_node)
    }
}

/// Canonicalize a DNS name: strip a single trailing dot and ASCII-lowercase. ASCII-only to match
/// the rest of the DNS name handling (`Name::to_canon`, the peer index) and avoid surprising
/// Unicode case-folding on a wire-controlled string.
fn canon(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn from_serde_strips_trailing_dot_and_lowercases() {
        let serde_config = ts_control_serde::DnsConfig {
            magic_dns: true,
            search_domains: alloc::vec!["User.TS.net."],
            ..Default::default()
        };

        let config = DnsConfig::from_serde(&serde_config);

        assert!(config.magic_dns);
        assert_eq!(
            config.search_domains,
            alloc::vec!["user.ts.net".to_string()]
        );
    }

    #[test]
    fn from_serde_magic_dns_false_is_preserved() {
        let serde_config = ts_control_serde::DnsConfig::default();

        let config = DnsConfig::from_serde(&serde_config);

        assert!(!config.magic_dns);
        assert!(config.search_domains.is_empty());
        assert!(config.extra_records.is_empty());
    }

    #[test]
    fn from_serde_carries_cert_domains_verbatim() {
        // Go returns `slices.Clone(nm.DNS.CertDomains)` — verbatim, no canonicalization.
        let serde_config = ts_control_serde::DnsConfig {
            cert_domains: alloc::vec!["host.tail0123.ts.net", "other.tail0123.ts.net"],
            ..Default::default()
        };

        let config = DnsConfig::from_serde(&serde_config);

        assert_eq!(
            config.cert_domains,
            alloc::vec![
                "host.tail0123.ts.net".to_string(),
                "other.tail0123.ts.net".to_string()
            ]
        );
    }

    #[test]
    fn from_serde_cert_domains_empty_when_absent() {
        let config = DnsConfig::from_serde(&ts_control_serde::DnsConfig::default());
        assert!(config.cert_domains.is_empty());
    }

    #[test]
    fn from_serde_keeps_a_and_aaaa_extra_records_drops_other() {
        use core::net::{Ipv4Addr, Ipv6Addr};

        let serde_config = ts_control_serde::DnsConfig {
            magic_dns: true,
            extra_records: alloc::vec![
                ts_control_serde::DnsRecord::A {
                    name: "Foo.Example.com.",
                    value: Ipv4Addr::new(10, 0, 0, 1),
                },
                ts_control_serde::DnsRecord::AAAA {
                    name: "bar.example.com",
                    value: "fd00::5".parse::<Ipv6Addr>().unwrap(),
                },
                ts_control_serde::DnsRecord::Other {
                    name: "txt.example.com",
                    ty: "TXT",
                    value: "ignored",
                },
            ],
            ..Default::default()
        };

        let config = DnsConfig::from_serde(&serde_config);

        // Names are canonicalized (lowercased, trailing dot stripped); the TXT record is dropped.
        assert_eq!(config.extra_records.len(), 2);
        assert_eq!(config.extra_records[0].name, "foo.example.com".to_string());
        assert_eq!(
            config.extra_records[0].addr,
            core::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(config.extra_records[1].name, "bar.example.com".to_string());
        assert_eq!(
            config.extra_records[1].addr,
            "fd00::5".parse::<core::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn from_serde_drops_empty_route_keys_and_keeps_normal_suffix() {
        let mut routes = BTreeMap::new();
        // Both "" and "." canonicalize to "" and must be dropped so they never become a
        // match-all wildcard in `ends_with` route matching.
        routes.insert("", None);
        routes.insert(".", None);
        routes.insert("corp.ts.net", None);

        let serde_config = ts_control_serde::DnsConfig {
            magic_dns: true,
            routes,
            ..Default::default()
        };

        let config = DnsConfig::from_serde(&serde_config);

        assert!(!config.routes.contains_key(""));
        assert!(config.routes.contains_key("corp.ts.net"));
        assert_eq!(config.routes.len(), 1);
    }

    #[test]
    fn from_serde_drops_empty_search_domains_and_keeps_normal_suffix() {
        let serde_config = ts_control_serde::DnsConfig {
            magic_dns: true,
            // "" and "." both canonicalize to "" and must be dropped; "corp.ts.net" survives.
            search_domains: alloc::vec!["", ".", "corp.ts.net"],
            ..Default::default()
        };

        let config = DnsConfig::from_serde(&serde_config);

        assert_eq!(
            config.search_domains,
            alloc::vec!["corp.ts.net".to_string()]
        );
    }

    #[test]
    fn exit_node_filters_leading_period_is_suffix_match_requiring_a_label() {
        let serde_config = ts_control_serde::DnsConfig {
            magic_dns: true,
            // A leading period marks a suffix match: ".a.b" must match "x.a.b" but NOT "a.b".
            exit_node_filtered_set: alloc::vec![".a.b"],
            ..Default::default()
        };

        let config = DnsConfig::from_serde(&serde_config);

        assert!(config.exit_node_filters("x.a.b"));
        assert!(config.exit_node_filters("deep.x.a.b"));
        // The suffix itself is NOT matched by a leading-period entry (a real label is required).
        assert!(!config.exit_node_filters("a.b"));
        // A name merely ending in the bare letters but without the dot boundary is not matched.
        assert!(!config.exit_node_filters("xa.b"));
        assert!(!config.exit_node_filters("other.b"));
    }

    #[test]
    fn exit_node_filters_no_leading_period_is_exact_match() {
        let serde_config = ts_control_serde::DnsConfig {
            magic_dns: true,
            exit_node_filtered_set: alloc::vec!["a.b"],
            ..Default::default()
        };

        let config = DnsConfig::from_serde(&serde_config);

        assert!(config.exit_node_filters("a.b"));
        // An exact entry must not match a subdomain.
        assert!(!config.exit_node_filters("x.a.b"));
        assert!(!config.exit_node_filters("a.b.c"));
    }

    #[test]
    fn exit_node_filters_is_case_insensitive_and_trailing_dot_insensitive() {
        let serde_config = ts_control_serde::DnsConfig {
            magic_dns: true,
            // Wire entries may be mixed-case with a trailing dot; both are canonicalized.
            exit_node_filtered_set: alloc::vec!["Example.COM.", ".Internal.Corp."],
            ..Default::default()
        };

        let config = DnsConfig::from_serde(&serde_config);

        // Query names are already lowercased/no-trailing-dot canonical form.
        assert!(config.exit_node_filters("example.com"));
        assert!(config.exit_node_filters("host.internal.corp"));
        assert!(!config.exit_node_filters("internal.corp"));
    }

    #[test]
    fn resolvers_with_exit_node_keeps_only_flagged() {
        use core::net::Ipv4Addr;

        let kept = ts_control_serde::DnsResolver {
            addr: ts_control_serde::DnsResolverAddr::Plaintext(SocketAddr::from((
                Ipv4Addr::new(100, 64, 0, 1),
                53,
            ))),
            bootstrap_resolution: Vec::new(),
            use_with_exit_node: true,
        };
        let dropped = ts_control_serde::DnsResolver {
            addr: ts_control_serde::DnsResolverAddr::Plaintext(SocketAddr::from((
                Ipv4Addr::new(8, 8, 8, 8),
                53,
            ))),
            bootstrap_resolution: Vec::new(),
            use_with_exit_node: false,
        };

        let serde_config = ts_control_serde::DnsConfig {
            magic_dns: true,
            resolvers: alloc::vec![Some(kept), Some(dropped)],
            ..Default::default()
        };

        let config = DnsConfig::from_serde(&serde_config);

        let surviving: Vec<_> = config.resolvers_with_exit_node().collect();
        assert_eq!(surviving.len(), 1);
        assert_eq!(
            surviving[0].udp_addr(),
            SocketAddr::from((Ipv4Addr::new(100, 64, 0, 1), 53))
        );
    }
}
