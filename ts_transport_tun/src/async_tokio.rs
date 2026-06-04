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
        let mut buf = BytesMut::new();

        core::iter::from_fn(move || {
            if let Some(Err(e)) = ret.take() {
                return Some(Err(e.into()));
            }

            buf.reserve(self.mtu.saturating_sub(buf.len()));

            match self.device.try_recv(buf.as_mut()) {
                Ok(n) => {
                    let pkt = buf.split_off(n);
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
