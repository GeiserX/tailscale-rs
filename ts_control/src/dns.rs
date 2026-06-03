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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolver {
    /// Classic plaintext DNS over UDP at this address.
    Udp(SocketAddr),
}

impl Resolver {
    /// Build a UDP resolver from the borrowed serde view, or `None` for an encrypted transport
    /// (DoH/DoT/DoH-over-WireGuard) we do not yet forward to.
    fn from_serde(r: &ts_control_serde::DnsResolver<'_>) -> Option<Self> {
        match r.addr {
            ts_control_serde::DnsResolverAddr::Plaintext(addr) => Some(Resolver::Udp(addr)),
            // TODO: support DoH/DoT/HttpWireguard upstreams. Until then they are dropped so we
            // never silently treat an encrypted resolver as a plaintext one.
            _ => None,
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
}

impl DnsConfig {
    /// Build the owned config from the borrowed serde view parsed off the wire.
    pub fn from_serde(c: &ts_control_serde::DnsConfig<'_>) -> Self {
        DnsConfig {
            magic_dns: c.magic_dns,
            search_domains: c
                .search_domains
                .iter()
                .map(|domain| canon(domain))
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
                .collect(),
            fallback_resolvers: resolvers_from_serde(&c.fallback_resolvers),
        }
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
}
