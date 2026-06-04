use alloc::vec::Vec;
use core::net::SocketAddr;

use netcore::{Command, HasChannel, raw, smoltcp::wire, tcp, udp};

use crate::{RawSocket, TcpListener, TcpStream, UdpSocket};

/// API for creating sockets over a [`HasChannel`].
pub trait CreateSocket {
    /// Create and bind a new [`UdpSocket`] to the given local endpoint.
    fn udp_bind_blocking(&self, endpoint: SocketAddr) -> Result<UdpSocket, netcore::Error>;
    /// Asynchronously create and bind a new [`UdpSocket`] to the given local endpoint.
    fn udp_bind(
        &self,
        endpoint: SocketAddr,
    ) -> impl Future<Output = Result<UdpSocket, netcore::Error>> + Send;

    /// Create a new [`TcpListener`] on the given endpoint.
    fn tcp_listen_blocking(
        &self,
        local_endpoint: SocketAddr,
    ) -> Result<TcpListener, netcore::Error>;
    /// Asynchronously create a new [`TcpListener`] on the given endpoint.
    fn tcp_listen(
        &self,
        local_endpoint: SocketAddr,
    ) -> impl Future<Output = Result<TcpListener, netcore::Error>> + Send;

    /// Snapshot the set of local ports that currently have an explicit TCP listener.
    ///
    /// Read-only: answered from the listener registry without touching the packet ingress /
    /// accept path. The fallback-TCP-handler manager uses this to avoid binding a competing
    /// any-IP listener on a port the embedder is already serving with an explicit `tcp_listen`.
    fn bound_tcp_ports_blocking(&self) -> Result<Vec<u16>, netcore::Error>;
    /// Asynchronously snapshot the set of local ports that currently have an explicit TCP
    /// listener. See [`CreateSocket::bound_tcp_ports_blocking`].
    fn bound_tcp_ports(&self) -> impl Future<Output = Result<Vec<u16>, netcore::Error>> + Send;

    /// Create a new [`TcpStream`] bound to the given `local` address and connected to
    /// the given `remote`.
    ///
    /// Waits for the handshake to complete before returning.
    fn tcp_connect_blocking(
        &self,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Result<TcpStream, netcore::Error>;
    /// Asynchronously create a new [`TcpStream`] bound to the given `local` address and
    /// connected to the given `remote`.
    ///
    /// Waits for the handshake to complete before returning.
    fn tcp_connect(
        &self,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, netcore::Error>> + Send;

    /// Create a new [`RawSocket`] on the selected ip version and protocol.
    ///
    /// NB: this will intercept _all_ matching traffic, even if you have other sockets open.
    fn raw_open_blocking(
        &self,
        ipv4: bool,
        ip_protocol: wire::IpProtocol,
    ) -> Result<RawSocket, netcore::Error>;
    /// Asynchronously create a new [`RawSocket`] on the selected ip version and protocol.
    ///
    /// NB: this will intercept _all_ matching traffic, even if you have other sockets open.
    fn raw_open(
        &self,
        ipv4: bool,
        ip_protocol: wire::IpProtocol,
    ) -> impl Future<Output = Result<RawSocket, netcore::Error>> + Send;
}

impl<T> CreateSocket for T
where
    T: HasChannel + Sync,
{
    fn udp_bind_blocking(&self, endpoint: SocketAddr) -> Result<UdpSocket, netcore::Error> {
        let resp = self.request_blocking(None, udp::Command::Bind { endpoint })?;

        netcore::try_response_as!(resp, udp::Response::Bound { local, handle });

        Ok(UdpSocket {
            sender: self.command_channel(),
            local,
            handle,
        })
    }

    async fn udp_bind(&self, endpoint: SocketAddr) -> Result<UdpSocket, netcore::Error> {
        let resp = self.request(None, udp::Command::Bind { endpoint }).await?;

        netcore::try_response_as!(resp, udp::Response::Bound { local, handle });

        Ok(UdpSocket {
            sender: self.command_channel(),
            local,
            handle,
        })
    }

    fn tcp_listen_blocking(
        &self,
        local_endpoint: SocketAddr,
    ) -> Result<TcpListener, netcore::Error> {
        let resp = self.request_blocking(None, tcp::listen::Command::Listen { local_endpoint })?;

        netcore::try_response_as!(resp, tcp::listen::Response::Listening { handle });

        Ok(TcpListener {
            sender: self.command_channel(),
            handle,
            endpoint: local_endpoint,
        })
    }

    async fn tcp_listen(&self, local_endpoint: SocketAddr) -> Result<TcpListener, netcore::Error> {
        let resp = self
            .request(None, tcp::listen::Command::Listen { local_endpoint })
            .await?;

        netcore::try_response_as!(resp, tcp::listen::Response::Listening { handle });

        Ok(TcpListener {
            sender: self.command_channel(),
            handle,
            endpoint: local_endpoint,
        })
    }

    fn bound_tcp_ports_blocking(&self) -> Result<Vec<u16>, netcore::Error> {
        let resp = self.request_blocking(None, tcp::listen::Command::BoundPorts)?;

        netcore::try_response_as!(resp, tcp::listen::Response::BoundPorts { ports });

        Ok(ports)
    }

    async fn bound_tcp_ports(&self) -> Result<Vec<u16>, netcore::Error> {
        let resp = self.request(None, tcp::listen::Command::BoundPorts).await?;

        netcore::try_response_as!(resp, tcp::listen::Response::BoundPorts { ports });

        Ok(ports)
    }

    fn tcp_connect_blocking(
        &self,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Result<TcpStream, netcore::Error> {
        let resp = self.request_blocking(
            None,
            tcp::stream::Command::Connect {
                remote_endpoint,
                local_endpoint,
            },
        )?;

        netcore::try_response_as!(resp, tcp::stream::Response::Connected { handle });

        Ok(TcpStream::new(
            self.command_channel(),
            handle,
            remote_endpoint,
            local_endpoint,
        ))
    }

    async fn tcp_connect(
        &self,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Result<TcpStream, netcore::Error> {
        let resp = self
            .request(
                None,
                tcp::stream::Command::Connect {
                    remote_endpoint,
                    local_endpoint,
                },
            )
            .await?;

        netcore::try_response_as!(resp, tcp::stream::Response::Connected { handle });

        Ok(TcpStream::new(
            self.command_channel(),
            handle,
            remote_endpoint,
            local_endpoint,
        ))
    }

    fn raw_open_blocking(
        &self,
        ipv4: bool,
        ip_protocol: wire::IpProtocol,
    ) -> Result<RawSocket, netcore::Error> {
        let ip_version = if ipv4 {
            wire::IpVersion::Ipv4
        } else {
            wire::IpVersion::Ipv6
        };

        let resp = self.request_blocking(
            None,
            Command::Raw(raw::Command::Open {
                ip_version,
                protocol: ip_protocol,
            }),
        )?;

        netcore::try_response_as!(resp, raw::Response::Opened { handle });

        Ok(RawSocket::new(
            self.command_channel(),
            handle,
            ip_protocol,
            ip_version,
        ))
    }

    async fn raw_open(
        &self,
        ipv4: bool,
        ip_protocol: wire::IpProtocol,
    ) -> Result<RawSocket, netcore::Error> {
        let ip_version = if ipv4 {
            wire::IpVersion::Ipv4
        } else {
            wire::IpVersion::Ipv6
        };

        let resp = self
            .request(
                None,
                Command::Raw(raw::Command::Open {
                    ip_version,
                    protocol: ip_protocol,
                }),
            )
            .await?;

        netcore::try_response_as!(resp, raw::Response::Opened { handle });

        Ok(RawSocket::new(
            self.command_channel(),
            handle,
            ip_protocol,
            ip_version,
        ))
    }
}
