use std::{io, iter, sync::Arc};

use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};

#[derive(Clone)]
pub struct IpTun {
    device: Arc<tun_rs::AsyncDevice>,
    name: String,
    mtu: MtuWatcher,
}

impl IpTun {
    pub fn new(device: tun_rs::AsyncDevice) -> io::Result<Self> {
        let name = device.name()?;
        let mtu = MtuWatcher::new(device.mtu()?);
        Ok(Self {
            device: Arc::new(device),
            name,
            mtu,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl IpSend for IpTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.device.send(&packet.into_bytes()).await?;
        Ok(())
    }
}

impl IpRecv for IpTun {
    async fn recv<'a>(
        &'a mut self, pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let mut packet = pool.get();
        let len = self.device.recv(&mut packet).await?;
        packet.truncate(len);
        let packet = match packet.try_into_ip() {
            Ok(packet) => packet,
            Err(error) => return Err(io::Error::other(error.to_string())),
        };
        Ok(iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}
