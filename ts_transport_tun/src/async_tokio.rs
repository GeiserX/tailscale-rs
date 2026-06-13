use core::fmt;
use std::io::ErrorKind;

use bytes::BytesMut;
use ts_hexdump::{AsHexExt, Case};
use ts_packet::PacketMut;
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::Error;

/// Asynchronous TUN transport exposed as a network interface on the local machine.
pub struct AsyncTunTransport {
    /// The `tun-rs` device managing the TUN network interface.
    device: AsyncDevice,
    mtu: usize,
}

impl fmt::Debug for AsyncTunTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncTunTransport")
            .field("device", &self.device.name())
            .finish()
    }
}

impl AsyncTunTransport {
    /// Create a new async TUN transport on the local machine. Requires root permissions to call.
    pub fn new(config: &crate::Config) -> Result<Self, Error> {
        let mtu = config.mtu.get();

        let builder = DeviceBuilder::new()
            // Single-queue, no GRO/GSO offload: correct for the overlay data path; multi-queue is a throughput optimization we have not needed.
            .mtu(mtu)
            .name(&config.name);

        let configured = match config.prefix {
            ipnet::IpNet::V4(v4net) => builder.ipv4(v4net.addr(), v4net.prefix_len(), None),
            ipnet::IpNet::V6(v6net) => builder.ipv6(v6net.addr(), v6net.prefix_len()),
        };

        let tun = match configured.build_async() {
            Ok(d) => d,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return Err(Error::RootUserRequired);
            }
            Err(e) => return Err(Error::from(e)),
        };

        Ok(Self {
            device: tun,
            mtu: mtu as _,
        })
    }

    /// Reports the name of the TUN device.
    pub fn name(&self) -> String {
        self.device
            .name()
            .unwrap_or_else(|_| "<unnamed tun device>".to_string())
    }

    async fn recv_many(&self) -> impl Iterator<Item = Result<PacketMut, Error>> {
        let mut ret = Some(self.device.readable().await);
        let mtu = self.mtu;

        core::iter::from_fn(move || {
            if let Some(Err(e)) = ret.take() {
                return Some(Err(e.into()));
            }

            // The read must target a slice whose LENGTH is the MTU, not merely its capacity:
            // `BytesMut::as_mut` yields a slice of `len` (a `reserve`d-but-empty buffer is a
            // zero-length slice), so reading into a freshly `reserve`d buffer would read 0 bytes and
            // silently drop every inbound packet. Allocate an MTU-sized zeroed buffer per read, then
            // `split_to(n)` to return exactly the `n` bytes the device wrote — mirroring Go
            // `net/tstun`, which reads into a sized buffer and reslices to the returned length.
            let mut buf = BytesMut::zeroed(mtu);

            match self.device.try_recv(&mut buf[..]) {
                // A zero-length read carries no packet; end the batch rather than emit an empty one.
                Ok(0) => None,
                Ok(n) => {
                    let pkt = buf.split_to(n);
                    Some(Ok(pkt.into()))
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => None,
                Err(e) => Some(Err(e.into())),
            }
        })
        .fuse()
    }
}

impl ts_transport::OverlayTransport for AsyncTunTransport {
    type Error = Error;

    async fn recv(&self) -> impl IntoIterator<Item = Result<PacketMut, Self::Error>> {
        self.recv_many().await
    }

    async fn send<Iter>(&self, packets: Iter) -> Result<(), Self::Error>
    where
        Iter: IntoIterator<Item = PacketMut> + Send,
        Iter::IntoIter: Send,
    {
        for packet in packets {
            let bytes_sent = self.device.send(packet.as_ref()).await?;

            tracing::trace!(
                transport = self.name(),
                "sent {bytes_sent}-byte packet:\n{}",
                packet
                    .iter()
                    .hexdump(Case::Upper)
                    .flatten()
                    .collect::<String>()
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    /// Pins the buffer-sizing invariant the TUN read depends on, without a (privileged) device.
    ///
    /// The read targets `&mut buf[..]`, whose length is what the OS `read`/`readv` is allowed to
    /// fill. The fixed code allocates an MTU-sized **zeroed** buffer (length == MTU), so the device
    /// can write up to MTU bytes; `split_to(n)` then yields exactly the `n` written bytes. The prior
    /// code used `BytesMut::new()` + `reserve(mtu)`, which grows *capacity* but leaves *length* 0 —
    /// so the read slice was zero-length and every inbound packet was silently dropped. This test
    /// fails on the old pattern (asserts the read slice is full-length) and passes on the new one.
    #[test]
    fn recv_buffer_is_mtu_sized_then_split_to_n() {
        const MTU: usize = 1280;

        // The broken pattern: reserve only grows capacity, the readable slice stays zero-length.
        let mut reserved = BytesMut::new();
        reserved.reserve(MTU);
        assert_eq!(
            reserved.as_mut().len(),
            0,
            "reserve grows capacity, not length — a read into this slice would read 0 bytes"
        );

        // The fixed pattern: an MTU-sized zeroed buffer is a full-length read target.
        let mut buf = BytesMut::zeroed(MTU);
        assert_eq!(
            buf.len(),
            MTU,
            "the read target must be MTU bytes long, not merely MTU capacity"
        );

        // Simulate the device writing an `n`-byte packet into the head of the buffer, then split.
        let packet = [0x45u8, 0x00, 0x00, 0x1c, 0xde, 0xad, 0xbe, 0xef];
        let n = packet.len();
        buf[..n].copy_from_slice(&packet);
        let pkt = buf.split_to(n);

        assert_eq!(
            pkt.len(),
            n,
            "split_to(n) must return exactly the n written bytes"
        );
        assert_eq!(
            pkt.as_ref(),
            &packet,
            "the returned packet must preserve the written bytes"
        );
    }
}
