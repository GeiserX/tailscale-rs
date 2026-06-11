use core::fmt;

use crypto_box::aead::{Aead, AeadCore, AeadMutInPlace, OsRng};
use futures::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf},
    sync::Mutex,
};
use tokio_util::codec::{FramedRead, FramedWrite};
use ts_http_util::Client as _;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::PacketMut;
use ts_transport::{BatchRecvIter, BatchSendIter, UnderlayTransport};
use url::Url;

use crate::{
    Error, ServerConnInfo, frame,
    frame::{
        ClientInfo, FrameType, Health, PeerGone, Ping, RawFrame, Restarting, ServerInfo, ServerKey,
    },
};

type DefaultIo = ts_http_util::Upgraded;

/// Type alias for the default derp client over upgraded HTTP on a tokio executor.
pub type DefaultClient = Client<DefaultIo>;

/// Single-region DERP client.
pub struct Client<Io> {
    read_conn: Mutex<FramedRead<ReadHalf<Io>, frame::Codec>>,
    write_conn: Mutex<FramedWrite<WriteHalf<Io>, frame::Codec>>,
}

/// Establish and upgrade a http connection to the derp region.
#[tracing::instrument(skip_all, err)]
pub async fn connect<'c>(
    region: impl IntoIterator<Item = &'c ServerConnInfo>,
) -> Result<Option<DefaultIo>, Error> {
    // A TLS-setup failure is a transient (`dial::Error::Io`); propagate it as `Err` so the caller's
    // reconnect loop retries, rather than `.unwrap()`-panicking and killing the region task. A
    // reachable-but-unconnectable region is still `Ok(None)`.
    let Some((conn, _, addr)) = crate::dial::dial_region_tls(region).await? else {
        return Ok(None);
    };

    let url = Url::parse(&format!("https://{addr}/derp"))?;

    let client = ts_http_util::http1::connect(conn).await?;

    let resp = client
        .send(ts_http_util::make_upgrade_req(&url, "DERP", None)?)
        .await?;

    let upgraded = ts_http_util::do_upgrade(resp)
        .await
        .map_err(tokio::io::Error::other)
        .map_err(Error::from)?;

    Ok(Some(upgraded))
}

impl<Io> Client<Io>
where
    Io: AsyncRead + AsyncWrite,
{
    /// Perform a derp handshake over the given transport and return a [`Client`].
    #[tracing::instrument(skip_all)]
    pub async fn handshake(conn: Io, node_keypair: &NodeKeyPair) -> Result<Self, Error> {
        let (read_conn, write_conn) = tokio::io::split(conn);

        let mut fw = FramedWrite::new(write_conn, frame::Codec);
        let mut fr = FramedRead::new(read_conn, frame::Codec);

        let frame = fr.next().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream ended before server key",
            )
        })??;
        let (sk, _rest) = frame
            .get()
            .as_type::<ServerKey>()
            .ok_or_else(|| std::io::Error::other("initial message was not serverkey"))?;

        sk.validate()?;

        tracing::trace!(
            server_public_key = %sk.key,
            "derp server public key"
        );

        let (client_info, encrypted) = make_clientinfo(node_keypair, &sk.key)?;
        tracing::trace!(?client_info);

        fw.send((
            RawFrame::from_body(&client_info, encrypted.len())?,
            encrypted.as_ref(),
        ))
        .await?;

        tracing::trace!("sent client info");

        let frame = fr.next().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream ended before server info",
            )
        })??;
        let (si, payload) = frame
            .get()
            .as_type::<ServerInfo>()
            .ok_or_else(|| std::io::Error::other("frame was not serverinfo"))?;

        tracing::trace!(server_info = ?si, "got server info");

        let info = decrypt_server_info(node_keypair, sk, si, payload)?;
        tracing::trace!(server_info = ?info);

        Ok(Self {
            read_conn: Mutex::new(fr),
            write_conn: Mutex::new(fw),
        })
    }

    /// Send a message to a nodekey on the derp server.
    pub async fn send_one(&self, node_key: NodePublicKey, msg: &[u8]) -> Result<(), Error> {
        self.send_frame_with_extra(&frame::SendPacket { dest: node_key }, msg)
            .await
    }

    /// Send a frame to the derp server.
    pub async fn send_frame(
        &self,
        frame: &(impl frame::Body + zerocopy::IntoBytes + zerocopy::Immutable + Send),
    ) -> Result<(), Error> {
        self.send_frame_with_extra(frame, &[]).await
    }

    /// Send a frame to the derp server with the specified additional payload.
    pub async fn send_frame_with_extra(
        &self,
        frame: &(impl frame::Body + zerocopy::IntoBytes + zerocopy::Immutable + Send),
        additional_payload: &[u8],
    ) -> Result<(), Error> {
        let raw = RawFrame::from_body(frame, additional_payload.len())?;

        {
            let mut wr = self.write_conn.lock().await;
            wr.send((raw, additional_payload)).await?;
        }

        Ok(())
    }

    /// Waits for a single data packet from a peer to arrive via this DERP server and returns it.
    /// DERP control messages (KeepAlive, Ping, etc) are handled inline and are not returned.
    pub async fn recv_one(&self) -> Result<(NodePublicKey, PacketMut), Error> {
        // DERP exchanges control messages (KeepAlives, Pings, etc) in-band with data messages
        // (SendPacket, RecvPacket, etc). The caller only cares about the payloads of data
        // messages, so we recv_one_raw() in a loop to handle any control messages while waiting
        // for data messages.

        loop {
            let frame = {
                let mut r = self.read_conn.lock().await;
                r.next().await.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "derp stream ended")
                })??
            };
            let frame = frame.get();

            match frame.header.typ {
                // TODO (dylan): handle other control message types
                // TODO (dylan): handle other data message types (ForwardPacket, etc)
                #[allow(deprecated)]
                FrameType::KeepAlive => {
                    // TODO (dylan): do we need to do anything on KeepAlive other than reset a timer?
                    // TODO (dylan): handle KeepAlive timer
                    tracing::trace!("received KeepAlive frame");
                }
                FrameType::Ping => {
                    let Some((&ping, _)) = frame.as_type::<Ping>() else {
                        tracing::warn!("ping frame was not ping");
                        continue;
                    };

                    tracing::trace!(payload = ?ping.payload, "ping");

                    let pong: frame::Pong = ping.into();
                    self.send_frame(&pong).await?;

                    tracing::trace!(payload = ?pong.payload, "pong");
                }
                FrameType::PeerGone => {
                    let (gone, _rest) = frame.as_type::<PeerGone>().unwrap();

                    tracing::debug!(
                        peer = %gone.key,
                        reason = %gone.reason()?,
                        "peer gone from derp server"
                    );
                }
                FrameType::Health => {
                    // The server reports a connection-health problem; the whole trailing payload is
                    // a UTF-8 problem string (empty = healthy again). Informational, NOT a teardown
                    // signal — Go's client returns it as a `HealthMessage` and the engine forwards it
                    // to a health tracker, never disconnecting. Log it and keep reading.
                    let problem = frame
                        .as_type::<Health>()
                        .map(|(_health, payload)| String::from_utf8_lossy(payload))
                        .unwrap_or_default();
                    if problem.is_empty() {
                        tracing::debug!("derp server reports connection healthy again");
                    } else {
                        tracing::warn!(%problem, "derp server reports connection health problem");
                    }
                }
                FrameType::Restarting => {
                    // The server announces it is restarting, advising when / how long to reconnect
                    // (two big-endian u32 millisecond durations). Advisory only — Go's own clients
                    // parse but don't act on the timings, relying on the normal reconnect-with-backoff
                    // path once the connection drops; we do the same (log and keep reading — the loop
                    // ends naturally when the server closes the connection, then the caller reconnects
                    // with backoff). A short (<8-byte) frame is tolerated, not fatal.
                    match frame.as_type::<Restarting>() {
                        Some((restarting, _rest)) => tracing::info!(
                            reconnect_in_ms = restarting.reconnect.get(),
                            try_for_ms = restarting.total.get(),
                            "derp server is restarting"
                        ),
                        None => tracing::warn!("dropping short derp server-restarting frame"),
                    }
                }
                FrameType::RecvPacket => {
                    let (recv, payload) = frame.as_type::<frame::RecvPacket>().unwrap();

                    return Ok((recv.src, payload.into()));
                }
                t => {
                    // A known-but-not-yet-handled server frame type is SKIPPED, never fatal — like
                    // Go's DERP client (`recvTimeout` has a `default: continue`). Treating it as an
                    // error (the old behavior) tore down and reconnected the connection on benign
                    // control frames the server legitimately sends, flapping the home-DERP relay that
                    // DERP-only peers depend on. (A *truly unknown* wire byte never reaches here: the
                    // codec's `FrameType::try_from` rejects it at decode time — widening that to a
                    // skip too would be a separate codec change.)
                    tracing::debug!(frame_type = ?t, "ignoring unhandled derp frame type");
                }
            }
        }
    }
}

impl Client<DefaultIo> {
    /// Connect to and handshake with the derp server with the given URL over HTTP.
    pub async fn connect<'c>(
        region: impl IntoIterator<Item = &'c ServerConnInfo>,
        node_keypair: &NodeKeyPair,
    ) -> Result<Self, Error> {
        // `connect` returns `Ok(None)` when no server in the region was reachable. This method must
        // yield a `Client`, so a `None` is a (retryable) connection failure, not a success — surface
        // it as an `Err` for the caller's reconnect loop rather than `.unwrap()`-panicking.
        let conn = connect(region).await?.ok_or_else(|| {
            Error::IoFailure(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "no derp server in region was reachable",
            ))
        })?;

        Client::handshake(conn, node_keypair).await
    }
}

impl<Io> fmt::Debug for Client<Io> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<Io> fmt::Display for Client<Io> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Client").finish()
    }
}

fn make_clientinfo(
    node_keypair: &NodeKeyPair,
    server_key: &ts_keys::DerpServerPublicKey,
) -> Result<(ClientInfo, Vec<u8>), Error> {
    let cbox = crypto_box::SalsaBox::new(&server_key.into(), &(&node_keypair.private).into());
    let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);

    let json = serde_json::to_vec(&frame::ClientInfoPayload {
        can_ack_pings: false,
        is_prober: false,
        mesh_key: "none".to_string(),
        version: 2,
    })?;
    let encrypted = cbox
        .encrypt(&nonce, &json[..])
        .map_err(|_| frame::Error::EncryptionFailed)?;

    Ok((
        ClientInfo {
            key: node_keypair.public,
            nonce: nonce.into(),
        },
        encrypted,
    ))
}

fn decrypt_server_info(
    node_keypair: &NodeKeyPair,
    sk: &ServerKey,
    server_info: &ServerInfo,
    payload: &[u8],
) -> Result<frame::ServerInfoPayload, Error> {
    let mut payload = PacketMut::from(payload);

    let mut cbox = crypto_box::SalsaBox::new(&sk.key.into(), &(&node_keypair.private).into());
    cbox.decrypt_in_place(&server_info.nonce.into(), &[], &mut payload)
        .map_err(|e| frame::Error::DecryptionFailed(format!("err: {e}")))?;

    let sip = serde_json::from_slice::<frame::ServerInfoPayload>(payload.as_ref())?;
    if sip.version() != frame::PROTOCOL_VERSION {
        return Err(Error::UnsupportedProtocolVersion(
            sip.version(),
            frame::PROTOCOL_VERSION,
        ));
    }

    Ok(sip)
}

impl<Io> UnderlayTransport for Client<Io>
where
    Io: AsyncRead + AsyncWrite + Send,
{
    type PeerKey = NodePublicKey;
    type Error = Error;

    async fn send(
        &self,
        packet_batch: impl BatchSendIter<Self::PeerKey>,
    ) -> Result<(), Self::Error> {
        for (key, pkt) in packet_batch.batch_iter() {
            for pkt in pkt {
                self.send_one(key, pkt.as_ref()).await?;
            }
        }

        Ok(())
    }

    async fn recv(&self) -> impl BatchRecvIter<Self::PeerKey, Error = Self::Error> {
        [self.recv_one().await.map(|(k, pkt)| (k, [pkt]))]
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;
    use tokio_util::codec::{FramedRead, FramedWrite};

    use super::*;
    use crate::{
        Error, IpUsage, ServerConnInfo, TlsValidationConfig,
        frame::{self, Header, RawFrame},
    };

    /// Build a `Client` over an in-memory duplex whose server side has already been fed `frames`
    /// (each `(FrameType, body)`), then closed. Lets `recv_one` be driven against synthetic
    /// server→client frames without a real DERP server.
    async fn client_fed(frames: &[(FrameType, &[u8])]) -> Client<tokio::io::DuplexStream> {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

        // Encode each frame onto the server side using the wire Codec, then EOF. The body lives in
        // `raw_body`; pass it as the extra-payload tuple element (the `(RawFrame, &[u8])` encoder)
        // with an empty `RawFrame` body so the header length matches `raw_body.len()`.
        let mut enc = FramedWrite::new(&mut server_io, frame::Codec);
        for (typ, body) in frames {
            let header = Header::new(*typ, body.len() as u32).expect("valid header");
            let raw = RawFrame {
                header,
                raw_body: &[],
            };
            // `SinkExt::feed` with an explicit tuple item disambiguates the two `Encoder` impls.
            futures::SinkExt::<(RawFrame, &[u8])>::feed(&mut enc, (raw, *body))
                .await
                .expect("encode frame");
        }
        futures::SinkExt::<(RawFrame, &[u8])>::flush(&mut enc)
            .await
            .expect("flush");
        server_io.shutdown().await.expect("close server side");

        let (read_conn, write_conn) = tokio::io::split(client_io);
        Client {
            read_conn: Mutex::new(FramedRead::new(read_conn, frame::Codec)),
            write_conn: Mutex::new(FramedWrite::new(write_conn, frame::Codec)),
        }
    }

    /// Regression: a `Health` frame (0x14) must be consumed in-band, NOT treated as a fatal
    /// "unexpected frame type". Before the fix, `recv_one` returned `Err(UnexpectedRecvFrameType)`
    /// on any non-data control frame, tearing down + reconnecting the DERP connection on benign
    /// frames the server legitimately sends (flapping the home-DERP relay). Here we feed a Health
    /// frame then EOF: the loop must skip the Health frame and surface the EOF (`UnexpectedEof`),
    /// proving the Health frame itself was not the error.
    #[tokio::test]
    async fn health_frame_is_skipped_not_fatal() {
        let client = client_fed(&[(FrameType::Health, b"duplicate connection")]).await;
        let got = client.recv_one().await;
        match got {
            Err(Error::IoFailure(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            other => panic!("expected EOF after a skipped Health frame, got {other:?}"),
        }
    }

    /// Regression: a `Restarting` frame (0x15) — two big-endian u32 ms durations — is likewise
    /// skipped, not fatal.
    #[tokio::test]
    async fn restarting_frame_is_skipped_not_fatal() {
        // Restarting: reconnect_in = 1234ms, try_for = 5678ms (big-endian u32s).
        let mut body = Vec::new();
        body.extend_from_slice(&1234u32.to_be_bytes());
        body.extend_from_slice(&5678u32.to_be_bytes());
        let client = client_fed(&[(FrameType::Restarting, &body)]).await;
        let got = client.recv_one().await;
        match got {
            Err(Error::IoFailure(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            other => panic!("expected EOF after a skipped Restarting frame, got {other:?}"),
        }
    }

    /// Regression for the forward-compatible catch-all: a known-but-unhandled server frame type
    /// (here `Pong`, 0x13, which the client never special-cases) must hit the `t => skip` arm and be
    /// ignored, not tear down the connection. (A *truly unknown* wire byte is rejected earlier by the
    /// codec's `FrameType::try_from`, so it can't reach `recv_one`; a known-but-unhandled variant is
    /// what actually exercises the catch-all — the arm most likely to silently regress.)
    #[tokio::test]
    async fn unhandled_known_frame_type_is_skipped_not_fatal() {
        let client = client_fed(&[(FrameType::Pong, &[0u8; 8])]).await;
        match client.recv_one().await {
            Err(Error::IoFailure(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            other => panic!("expected EOF after a skipped Pong frame, got {other:?}"),
        }
    }

    /// The production scenario: a `Health` control frame interleaved *before* a real `RecvPacket`
    /// data frame. `recv_one` must skip the Health frame and then DELIVER the following data packet
    /// (src + payload) — proving the loop continues to useful data, not merely that the control
    /// frame wasn't fatal. A refactor that turned the Health arm into an early `return` would pass
    /// the skip-then-EOF tests but fail this one.
    #[tokio::test]
    async fn health_frame_is_skipped_then_following_data_packet_is_delivered() {
        let src: NodePublicKey = [7u8; 32].into();
        // RecvPacket wire body = src (32 bytes) followed by the data payload.
        let mut recv_body = Vec::new();
        recv_body.extend_from_slice(&src.to_bytes());
        recv_body.extend_from_slice(b"hello-derp");
        let client = client_fed(&[
            (FrameType::Health, b"duplicate connection"),
            (FrameType::RecvPacket, &recv_body),
        ])
        .await;
        let (got_src, pkt) = client
            .recv_one()
            .await
            .expect("data packet delivered after a skipped Health frame");
        assert_eq!(
            got_src, src,
            "delivered packet carries the original src key"
        );
        assert_eq!(
            pkt.as_ref(),
            b"hello-derp",
            "delivered packet carries the payload"
        );
    }

    /// A region whose only server has both IP families disabled: `dial_region_tls` returns
    /// `Ok(None)` (unreachable) synchronously, with no network I/O.
    fn unreachable_region() -> Vec<ServerConnInfo> {
        vec![ServerConnInfo {
            hostname: "derp.invalid".to_owned(),
            ipv4: IpUsage::Disable,
            ipv6: IpUsage::Disable,
            // Both IP families are disabled, so the dial returns `Ok(None)` before TLS is ever
            // attempted — the validation variant is irrelevant here (just pick a non-feature-gated
            // one).
            tls_validation_config: TlsValidationConfig::CommonName {
                common_name: "derp.invalid".to_owned(),
            },
            https_port: 443,
            stun_port: None,
            stun_only: false,
            supports_port_80: false,
        }]
    }

    /// Regression for `tsr-u6i`: the free `connect` must report an unreachable region as `Ok(None)`,
    /// never `.unwrap()`-panic. (The bug `.unwrap()`'d the `dial_region_tls` result, which panics on
    /// a TLS-setup `Err`; this also pins that the no-reachable-server path stays a clean `Ok(None)`.)
    #[tokio::test]
    async fn connect_unreachable_region_is_none_not_panic() {
        let region = unreachable_region();
        let got = super::connect(&region).await;
        assert!(
            matches!(got, Ok(None)),
            "an unreachable region must be Ok(None), got {got:?}"
        );
    }

    /// Regression for `tsr-u6i`: `Client::connect` must yield an `Err` for an unreachable region
    /// rather than `.unwrap()`-panicking on the `Ok(None)`. A panic here unwinds the spawned region
    /// task past its reconnect loop and is silently absorbed by the `JoinSet`, permanently killing
    /// the region; an `Err` lets the loop retry.
    #[tokio::test]
    async fn client_connect_unreachable_region_is_err_not_panic() {
        let region = unreachable_region();
        let keys = ts_keys::NodeKeyPair::new();
        let got = super::Client::connect(&region, &keys).await;
        assert!(
            got.is_err(),
            "Client::connect on an unreachable region must be Err, not a panic or Ok"
        );
    }
}
