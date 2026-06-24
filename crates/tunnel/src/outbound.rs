use std::{io, net::SocketAddr, sync::Arc};

use gotatun::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
};
use rustylink_outbound::Dialer;
pub use rustylink_outbound::OutboundInterface;
use tokio::net::UdpSocket;

#[derive(Clone, Debug)]
pub struct BoundUdpSocketFactory {
    dialer: Dialer,
}

#[derive(Clone)]
pub struct BoundUdpSocket {
    inner: Arc<UdpSocket>,
}

impl BoundUdpSocketFactory {
    #[must_use]
    pub fn new(dialer: Dialer) -> Self {
        Self { dialer }
    }
}

impl UdpTransportFactory for BoundUdpSocketFactory {
    type SendV4 = BoundUdpSocket;
    type SendV6 = BoundUdpSocket;
    type RecvV4 = BoundUdpSocket;
    type RecvV6 = BoundUdpSocket;

    async fn bind(
        &mut self, params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::SendV4, Self::RecvV4), (Self::SendV6, Self::RecvV6))> {
        let (udp_v4, udp_v6) = self
            .dialer
            .bind_udp_pair(params.addr_v4, params.addr_v6, params.port)
            .map_err(io::Error::other)?;
        let udp_v4 = BoundUdpSocket {
            inner: Arc::new(udp_v4),
        };
        let udp_v6 = BoundUdpSocket {
            inner: Arc::new(udp_v6),
        };
        Ok(((udp_v4.clone(), udp_v4), (udp_v6.clone(), udp_v6)))
    }
}

impl UdpSend for BoundUdpSocket {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        self.inner.send_to(&packet, destination).await?;
        Ok(())
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr().map(Some)
    }
}

impl UdpRecv for BoundUdpSocket {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buf = vec![0_u8; u16::MAX as usize];
        let (len, source) = self.inner.recv_from(&mut buf).await?;
        let mut packet = pool.get();
        packet.buf_mut().clear();
        packet.buf_mut().extend_from_slice(&buf[..len]);
        Ok((packet, source))
    }
}
