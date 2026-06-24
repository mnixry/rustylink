use std::{io, net::SocketAddr, sync::Arc};

use gotatun::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
};
use rustylink_outbound::Dialer;
use snafu::prelude::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{Mutex, mpsc},
};

const MAX_FEILIAN_TCP_FRAME: u32 = 65_535;

/// Errors on the `WireGuard` data path (UDP datagrams and the `FeiLian` TCP
/// transport). gotatun's transport traits require [`std::io::Error`], so these
/// are converted via [`From`] — which is also the single place they are
/// **logged automatically** (once, with the full cause chain, since every
/// variant's `Display` ends in `: {source}`). `warn` for real failures, `debug`
/// for benign teardown.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub(crate) enum TunnelTransportError {
    #[snafu(display("failed to dial {transport} transport to {destination}: {source}"))]
    Dial {
        transport: &'static str,
        destination: SocketAddr,
        source: rustylink_outbound::DialerError,
    },
    #[snafu(display("failed to send {len}-byte datagram to {destination}: {source}"))]
    Send {
        destination: SocketAddr,
        len: usize,
        source: io::Error,
    },
    #[snafu(display("failed to receive from {transport} transport: {source}"))]
    Recv {
        transport: &'static str,
        source: io::Error,
    },
    #[snafu(display("{transport} receive channel closed"))]
    RecvClosed { transport: &'static str },
    #[snafu(display("invalid {transport} frame length {frame_len} for peer {peer}"))]
    InvalidFrame {
        transport: &'static str,
        frame_len: usize,
        peer: SocketAddr,
    },
}

impl TunnelTransportError {
    fn io_kind(&self) -> io::ErrorKind {
        match self {
            Self::Dial { .. } => io::ErrorKind::Other,
            Self::Send { source, .. } | Self::Recv { source, .. } => source.kind(),
            Self::RecvClosed { .. } => io::ErrorKind::ConnectionAborted,
            Self::InvalidFrame { .. } => io::ErrorKind::InvalidData,
        }
    }
}

impl From<TunnelTransportError> for io::Error {
    fn from(error: TunnelTransportError) -> Self {
        if matches!(error, TunnelTransportError::RecvClosed { .. }) {
            tracing::debug!(%error, "tunnel transport closed");
        } else {
            tracing::warn!(%error, "tunnel transport error");
        }
        let kind = error.io_kind();
        Self::new(kind, error)
    }
}

#[derive(Clone, Debug)]
pub struct FeilianTcpTransportFactory {
    dialer: Dialer,
}

#[derive(Clone)]
pub struct FeilianTcpSend {
    local_addr: SocketAddr,
    incoming: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    state: Arc<Mutex<Option<TcpWriterState>>>,
    dialer: Dialer,
}

pub struct FeilianTcpRecv {
    incoming: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
}

struct TcpWriterState {
    destination: SocketAddr,
    writer: OwnedWriteHalf,
}

impl FeilianTcpTransportFactory {
    #[must_use]
    pub fn new(dialer: Dialer) -> Self {
        Self { dialer }
    }
}

impl UdpTransportFactory for FeilianTcpTransportFactory {
    type SendV4 = FeilianTcpSend;
    type SendV6 = FeilianTcpSend;
    type RecvV4 = FeilianTcpRecv;
    type RecvV6 = FeilianTcpRecv;

    async fn bind(
        &mut self, params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::SendV4, Self::RecvV4), (Self::SendV6, Self::RecvV6))> {
        let v4 = tcp_pair(
            SocketAddr::from((params.addr_v4, params.port)),
            self.dialer.clone(),
        );
        let v6 = tcp_pair(
            SocketAddr::from((params.addr_v6, params.port)),
            self.dialer.clone(),
        );
        Ok((v4, v6))
    }
}

impl UdpSend for FeilianTcpSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let payload = packet.to_vec();
        let frame_len = u32::try_from(payload.len())
            .ok()
            .filter(|len| *len != 0 && *len <= MAX_FEILIAN_TCP_FRAME)
            .context(InvalidFrameSnafu {
                transport: "FeiLian TCP",
                frame_len: payload.len(),
                peer: destination,
            })?;

        let mut state = self.state.lock().await;
        let should_connect = state
            .as_ref()
            .is_none_or(|current| current.destination != destination);
        if should_connect {
            tracing::info!(
                %destination,
                outbound_interface = self
                    .dialer
                    .interface()
                    .map_or("<default>", |i| i.name.as_str()),
                "dialing FeiLian TCP WireGuard transport"
            );
            let stream = self
                .dialer
                .connect_tcp(destination)
                .await
                .context(DialSnafu {
                    transport: "FeiLian TCP",
                    destination,
                })?;
            let (reader, writer) = stream.into_split();
            tokio::spawn(read_feilian_tcp_frames(
                reader,
                destination,
                self.incoming.clone(),
            ));
            *state = Some(TcpWriterState {
                destination,
                writer,
            });
        }

        let writer = &mut state
            .as_mut()
            .expect("state exists after successful FeiLian TCP dial")
            .writer;
        let write_result = async {
            writer.write_all(&frame_len.to_le_bytes()).await?;
            writer.write_all(&payload).await
        }
        .await;
        if write_result.is_err() {
            // Drop the connection so the next datagram re-dials.
            *state = None;
        }
        drop(state);
        write_result.context(SendSnafu {
            destination,
            len: payload.len(),
        })?;
        tracing::trace!(%destination, frame_len, "feilian tcp tx");
        Ok(())
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(Some(self.local_addr))
    }
}

impl UdpRecv for FeilianTcpRecv {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let (payload, source) = self.incoming.recv().await.context(RecvClosedSnafu {
            transport: "FeiLian TCP",
        })?;
        let mut packet = pool.get();
        packet.buf_mut().clear();
        packet.buf_mut().extend_from_slice(&payload);
        Ok((packet, source))
    }
}

fn tcp_pair(local_addr: SocketAddr, dialer: Dialer) -> (FeilianTcpSend, FeilianTcpRecv) {
    let (tx, rx) = mpsc::channel(256);
    (
        FeilianTcpSend {
            local_addr,
            incoming: tx,
            state: Arc::new(Mutex::new(None)),
            dialer,
        },
        FeilianTcpRecv { incoming: rx },
    )
}

async fn read_feilian_tcp_frames(
    mut reader: OwnedReadHalf, source: SocketAddr, incoming: mpsc::Sender<(Vec<u8>, SocketAddr)>,
) {
    loop {
        let mut frame_len = [0_u8; 4];
        if let Err(error) = reader.read_exact(&mut frame_len).await.context(RecvSnafu {
            transport: "FeiLian TCP",
        }) {
            tracing::warn!(%source, %error, "FeiLian TCP frame reader stopped");
            return;
        }
        let frame_len = u32::from_le_bytes(frame_len);
        if frame_len == 0 || frame_len > MAX_FEILIAN_TCP_FRAME {
            tracing::warn!(%source, frame_len, "invalid FeiLian TCP frame length");
            return;
        }
        let mut payload = vec![0_u8; frame_len as usize];
        if let Err(error) = reader.read_exact(&mut payload).await.context(RecvSnafu {
            transport: "FeiLian TCP",
        }) {
            tracing::warn!(%source, %error, "failed to read FeiLian TCP frame payload");
            return;
        }
        tracing::trace!(%source, frame_len, "feilian tcp rx");
        if incoming.send((payload, source)).await.is_err() {
            return;
        }
    }
}
