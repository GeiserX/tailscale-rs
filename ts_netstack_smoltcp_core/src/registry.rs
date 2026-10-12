//! Socket metadata paired with SocketSet by the add/remove wrappers.
use smoltcp::socket::{AnySocket, icmp, raw, tcp, udp};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SocketKind {
    Tcp,
    Udp,
    Raw,
    Icmp,
}

pub(crate) trait RegisteredSocket: AnySocket<'static> {
    const KIND: SocketKind;
}

macro_rules! register_kind {
    ($ty:ty, $kind:ident) => {
        impl RegisteredSocket for $ty {
            const KIND: SocketKind = SocketKind::$kind;
        }
    };
}
register_kind!(tcp::Socket<'static>, Tcp);
register_kind!(udp::Socket<'static>, Udp);
register_kind!(raw::Socket<'static>, Raw);
register_kind!(icmp::Socket<'static>, Icmp);

pub(crate) struct SocketEntry {
    pub generation: u64,
    pub kind: SocketKind,
}

#[cfg(test)]
mod tests {
    use smoltcp::{
        time::Instant,
        wire::{IpProtocol, IpVersion},
    };

    use super::*;
    use crate::{Config, Netstack};

    #[test]
    fn wrappers_keep_kinds_and_generations_in_sync_on_slot_reuse() {
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);
        let tcp = tcp::Socket::new(
            tcp::SocketBuffer::new(alloc::vec![0; 64]),
            tcp::SocketBuffer::new(alloc::vec![0; 64]),
        );
        let handle = stack.add_socket(tcp);
        let generation = stack.handle_gen(handle).unwrap();
        assert!(stack.socket_matches::<tcp::Socket>(handle));
        assert!(!stack.socket_matches::<udp::Socket>(handle));
        stack.pending_tcp_closes.insert(handle);
        stack.remove_socket(handle);
        assert_eq!(stack.handle_gen(handle), None);
        assert!(!stack.socket_matches::<tcp::Socket>(handle));
        assert!(stack.pending_tcp_closes.is_empty());

        let udp = udp::Socket::new(
            udp::PacketBuffer::new(
                alloc::vec![udp::PacketMetadata::EMPTY; 1],
                alloc::vec![0; 64],
            ),
            udp::PacketBuffer::new(
                alloc::vec![udp::PacketMetadata::EMPTY; 1],
                alloc::vec![0; 64],
            ),
        );
        let recycled = stack.add_socket(udp);
        assert_eq!(recycled, handle);
        assert_ne!(stack.handle_gen(recycled), Some(generation));
        assert!(stack.socket_matches::<udp::Socket>(recycled));
        assert!(!stack.socket_matches::<tcp::Socket>(recycled));

        let raw = raw::Socket::new(
            Some(IpVersion::Ipv4),
            Some(IpProtocol::Icmp),
            raw::PacketBuffer::new(alloc::vec![], alloc::vec![]),
            raw::PacketBuffer::new(alloc::vec![], alloc::vec![]),
        );
        let raw = stack.add_socket(raw);
        assert!(stack.socket_matches::<raw::Socket>(raw));
        assert!(!stack.socket_matches::<icmp::Socket>(raw));
        let icmp = icmp::Socket::new(
            icmp::PacketBuffer::new(alloc::vec![], alloc::vec![]),
            icmp::PacketBuffer::new(alloc::vec![], alloc::vec![]),
        );
        let icmp = stack.add_socket(icmp);
        assert!(stack.socket_matches::<icmp::Socket>(icmp));
        assert!(!stack.socket_matches::<raw::Socket>(icmp));
    }
    #[test]
    fn many_socket_commands_and_closes_do_no_full_socket_visits() {
        use core::net::SocketAddr;

        use bytes::Bytes;

        use crate::command::{Response, tcp::stream::Command};
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);
        let handles: alloc::vec::Vec<_> = (0..512)
            .map(|_| {
                stack.add_socket(tcp::Socket::new(
                    tcp::SocketBuffer::new(alloc::vec![0; 64]),
                    tcp::SocketBuffer::new(alloc::vec![0; 64]),
                ))
            })
            .collect();
        for &h in &handles {
            for cmd in [
                Command::Send {
                    buf: Bytes::from_static(b"x"),
                },
                Command::Recv { max_len: None },
                Command::ShutdownWrite,
                Command::Close,
                Command::Connect {
                    local_endpoint: SocketAddr::from(([127, 0, 0, 1], 50000)),
                    remote_endpoint: SocketAddr::from(([127, 0, 0, 1], 80)),
                },
            ] {
                assert!(!matches!(
                    stack.process_tcp_stream(cmd, Some(h)),
                    Response::WouldBlock { .. }
                ));
            }
        }
        assert_eq!(stack.metrics.counts().validation_lookups, 512 * 5);
        assert_eq!(stack.pending_tcp_closes.len(), 512);
        assert_eq!(stack.metrics.counts().orphan_socket_visits, 0);
        assert!(stack.drain_tcp_closes(Instant::ZERO));
        assert_eq!(stack.metrics.counts().validation_lookups, 512 * 6);
        assert_eq!(stack.metrics.counts().orphan_socket_visits, 0);
        assert!(stack.socket_registry.is_empty());
        assert_eq!(stack.tcp_socket_count, 0);
        assert!(stack.pending_tcp_closes.is_empty());
    }

    #[test]
    fn stale_pending_close_uses_kind_registry() {
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);
        let udp = udp::Socket::new(
            udp::PacketBuffer::new(alloc::vec![], alloc::vec![]),
            udp::PacketBuffer::new(alloc::vec![], alloc::vec![]),
        );
        let h = stack.add_socket(udp);
        // Deliberately inject a stale close to exercise the defense beyond removal cleanup.
        stack.pending_tcp_closes.insert(h);
        assert!(!stack.drain_tcp_closes(Instant::ZERO));
        assert!(stack.socket_matches::<udp::Socket>(h));
        assert!(stack.pending_tcp_closes.is_empty());
        assert_eq!(stack.metrics.counts().orphan_socket_visits, 0);
    }
    #[test]
    fn orphan_sweep_visits_live_entries_after_socket_storage_churn() {
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);
        let handles: alloc::vec::Vec<_> = (0..512)
            .map(|_| {
                stack.add_socket(tcp::Socket::new(
                    tcp::SocketBuffer::new(alloc::vec![0; 64]),
                    tcp::SocketBuffer::new(alloc::vec![0; 64]),
                ))
            })
            .collect();
        for &h in &handles[..511] {
            stack.remove_socket(h);
        }
        stack
            .socket_set
            .get_mut::<tcp::Socket>(handles[511])
            .listen(8080)
            .unwrap();
        assert!(!stack.drain_tcp_closes(Instant::from_millis(100)));
        assert_eq!(stack.metrics.counts().orphan_sweeps, 1);
        assert_eq!(stack.metrics.counts().orphan_socket_visits, 1);
        assert_eq!(stack.tcp_socket_count, 1);
    }
}
