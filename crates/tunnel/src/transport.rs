use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use gotatun::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{Mutex, mpsc},
};

const TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_FEILIAN_TCP_FRAME: u32 = 65_535;

#[derive(Clone, Debug, Default)]
pub struct FeilianTcpTransportFactory;

#[derive(Clone)]
pub struct FeilianTcpSend {
    local_addr: SocketAddr,
    incoming: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    state: Arc<Mutex<Option<TcpWriterState>>>,
}

pub struct FeilianTcpRecv {
    incoming: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
}

struct TcpWriterState {
    destination: SocketAddr,
    writer: OwnedWriteHalf,
}

impl UdpTransportFactory for FeilianTcpTransportFactory {
    type SendV4 = FeilianTcpSend;
    type SendV6 = FeilianTcpSend;
    type RecvV4 = FeilianTcpRecv;
    type RecvV6 = FeilianTcpRecv;

    async fn bind(
        &mut self, params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::SendV4, Self::RecvV4), (Self::SendV6, Self::RecvV6))> {
        let v4 = tcp_pair(SocketAddr::from((params.addr_v4, params.port)));
        let v6 = tcp_pair(SocketAddr::from((params.addr_v6, params.port)));
        Ok((v4, v6))
    }
}

impl UdpSend for FeilianTcpSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let payload = packet.to_vec();
        let frame_len = u32::try_from(payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "FeiLian TCP frame is larger than u32",
            )
        })?;
        if frame_len == 0 || frame_len > MAX_FEILIAN_TCP_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid FeiLian TCP frame length {frame_len}"),
            ));
        }

        {
            let mut state = self.state.lock().await;
            let should_connect = state
                .as_ref()
                .is_none_or(|current| current.destination != destination);
            if should_connect {
                tracing::info!(%destination, "dialing FeiLian TCP WireGuard transport");
                let stream = tokio::time::timeout(
                    TCP_DIAL_TIMEOUT,
                    tokio::net::TcpStream::connect(destination),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "FeiLian TCP dial timed out")
                })??;
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
            let result = match writer.write_all(&frame_len.to_le_bytes()).await {
                Ok(()) => writer.write_all(&payload).await,
                Err(error) => Err(error),
            };
            if result.is_err() {
                *state = None;
            }
            result
        }
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(Some(self.local_addr))
    }
}

impl UdpRecv for FeilianTcpRecv {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let (payload, source) = self.incoming.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "FeiLian TCP receive channel closed",
            )
        })?;
        let mut packet = pool.get();
        packet.buf_mut().clear();
        packet.buf_mut().extend_from_slice(&payload);
        Ok((packet, source))
    }
}

fn tcp_pair(local_addr: SocketAddr) -> (FeilianTcpSend, FeilianTcpRecv) {
    let (tx, rx) = mpsc::channel(256);
    (
        FeilianTcpSend {
            local_addr,
            incoming: tx,
            state: Arc::new(Mutex::new(None)),
        },
        FeilianTcpRecv { incoming: rx },
    )
}

async fn read_feilian_tcp_frames(
    mut reader: OwnedReadHalf, source: SocketAddr, incoming: mpsc::Sender<(Vec<u8>, SocketAddr)>,
) {
    loop {
        let mut frame_len = [0_u8; 4];
        if let Err(error) = reader.read_exact(&mut frame_len).await {
            tracing::warn!(%source, %error, "FeiLian TCP frame reader stopped");
            return;
        }
        let frame_len = u32::from_le_bytes(frame_len);
        if frame_len == 0 || frame_len > MAX_FEILIAN_TCP_FRAME {
            tracing::warn!(%source, frame_len, "invalid FeiLian TCP frame length");
            return;
        }
        let mut payload = vec![0_u8; frame_len as usize];
        if let Err(error) = reader.read_exact(&mut payload).await {
            tracing::warn!(%source, %error, "failed to read FeiLian TCP frame payload");
            return;
        }
        if incoming.send((payload, source)).await.is_err() {
            return;
        }
    }
}
