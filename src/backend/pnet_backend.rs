use std::{error::Error, time::Duration};

use pnet_datalink::{channel, Channel, Config, DataLinkReceiver, DataLinkSender, NetworkInterface};

use super::{BackendConfig, BackendFactory, PacketSink, PacketSource};

/// Packet source implementation using pnet
pub struct PnetPacketSource {
    receiver: Box<dyn DataLinkReceiver>,
}

impl PacketSource for PnetPacketSource {
    fn next_packet(&mut self) -> Option<Vec<u8>> {
        match self.receiver.next() {
            Ok(buf) => Some(buf.to_vec()),
            Err(_) => None,
        }
    }
}

/// Packet sink implementation using pnet
pub struct PnetPacketSink {
    sender: Box<dyn DataLinkSender>,
    interface: NetworkInterface,
}

impl PacketSink for PnetPacketSink {
    fn send_packet(&mut self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        match self.sender.send_to(data, Some(self.interface.clone())) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(format!("Send failed: {}", e).into()),
            None => Err("Failed to send packet".into()),
        }
    }
}

/// Factory for creating pnet-based packet source/sink pairs
pub struct PnetBackendFactory;

impl BackendFactory for PnetBackendFactory {
    type Source = PnetPacketSource;
    type Sink = PnetPacketSink;

    fn create(
        &self,
        config: BackendConfig,
    ) -> Result<(Self::Source, Self::Sink), Box<dyn Error + Send + Sync>> {
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .rev()
            .find(|n| {
                n.is_up()
                    && n.is_running()
                    && !n.is_loopback()
                    && n.name
                        .to_lowercase()
                        .contains(&config.interface_name.to_lowercase())
            })
            .ok_or_else(|| format!("Interface not found: {}", config.interface_name))?;

        let channel_config = Config {
            read_timeout: config.read_timeout_ms.map(Duration::from_millis),
            ..Config::default()
        };

        match channel(&interface, channel_config) {
            Ok(Channel::Ethernet(tx, rx)) => Ok((
                PnetPacketSource { receiver: rx },
                PnetPacketSink {
                    sender: tx,
                    interface,
                },
            )),
            Ok(_) => Err("Unsupported channel type".into()),
            Err(e) => Err(format!("Channel creation failed: {}", e).into()),
        }
    }

    fn name(&self) -> &'static str {
        "pnet"
    }
}
