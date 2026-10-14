//! Stateless IPv6 rejection, for an already authenticated, source-checked, ACL-admitted
//! packet routed to the dedicated IPv4-only forwarder. Never creates a host socket.

use ts_netstack_smoltcp::netcore::smoltcp::{
    phy::{Checksum, ChecksumCapabilities},
    wire::{IpAddress, TcpPacket, TcpRepr, UdpPacket, UdpRepr},
};

/// Returns a TCP reset or ICMPv6 administrative prohibition. `None` means deterministic
/// discard (malformed/later-fragment packet, fragmented UDP, RST, other protocol,
/// or non-unicast endpoint).
/// The caller MUST consume every IPv6 packet, even when this returns `None`.
/// A leading first-fragment TCP SYN with a complete TCP header is reset immediately;
/// its full transport checksum cannot be verified without reassembly. Call only after ACLs.
pub fn reject_ipv6(bytes: &[u8]) -> Option<Vec<u8>> {
    let sliced = etherparse::SlicedPacket::from_ip(bytes).ok()?;
    let etherparse::NetSlice::Ipv6(ip) = sliced.net? else {
        return None;
    };
    let header = ip.header();
    let src = header.source_addr();
    let dst = header.destination_addr();
    if src.is_unspecified() || src.is_multicast() || dst.is_unspecified() || dst.is_multicast() {
        return None;
    }
    let fragmented = ip.is_payload_fragmented();
    if fragmented
        && (bytes.get(6) != Some(&44)
            || u16::from_be_bytes([*bytes.get(42)?, *bytes.get(43)?]) >> 3 != 0)
    {
        return None;
    }
    let src_ip = IpAddress::Ipv6(src);
    let dst_ip = IpAddress::Ipv6(dst);
    let mut checksums = ChecksumCapabilities::default();
    if fragmented {
        checksums.tcp = Checksum::Tx;
    }
    let payload = ip.payload().payload;
    let builder = etherparse::PacketBuilder::ipv6(dst.octets(), src.octets(), 64);
    match ip.payload().ip_number.0 {
        6 => {
            let packet = TcpPacket::new_checked(payload).ok()?;
            let repr = TcpRepr::parse(&packet, &src_ip, &dst_ip, &checksums).ok()?;
            if packet.rst() {
                return None;
            }
            let mut builder = builder
                .tcp(
                    repr.dst_port,
                    repr.src_port,
                    repr.ack_number.unwrap_or_default().0 as u32,
                    0,
                )
                .rst();
            if repr.ack_number.is_none() {
                let len =
                    repr.payload.len() as u32 + u32::from(packet.syn()) + u32::from(packet.fin());
                builder = builder.ack((repr.seq_number.0 as u32).wrapping_add(len));
            }
            let mut out = Vec::with_capacity(builder.size(0));
            builder.write(&mut out, &[]).ok()?;
            Some(out)
        }
        17 if !fragmented => {
            let packet = UdpPacket::new_checked(payload).ok()?;
            UdpRepr::parse(&packet, &src_ip, &dst_ip, &checksums).ok()?;
            // Type 1, code 1; quote the original packet verbatim within the IPv6 1280 MTU.
            let quote = &bytes[..bytes
                .len()
                .min(40 + usize::from(header.payload_length()))
                .min(1232)];
            let builder = builder.icmpv6_raw(1, 1, [0; 4]);
            let mut out = Vec::with_capacity(builder.size(quote.len()));
            builder.write(&mut out, quote).ok()?;
            Some(out)
        }
        _ => None,
    }
}
