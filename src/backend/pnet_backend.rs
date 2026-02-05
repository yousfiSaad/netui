use std::{error::Error, time::Duration};

use pnet_datalink::{channel, Channel, Config, DataLinkReceiver, DataLinkSender, NetworkInterface};

use super::{BackendConfig, BackendFactory, PacketSink, PacketSource, PacketWithContext};
use crate::interface_utils;

/// Packet source implementation using pnet
pub struct PnetPacketSource {
    receiver: Box<dyn DataLinkReceiver>,
}

impl PacketSource for PnetPacketSource {
    fn next_packet(&mut self) -> Option<PacketWithContext> {
        match self.receiver.next() {
            Ok(buf) => Some(PacketWithContext {
                data: buf.to_vec(),
                hook_source: None,  // pnet doesn't have hook source info
                original_len: None, // pnet: use parsed packet length
                direct_event: None, // pnet doesn't have pre-extracted data
                timestamp_ns: None, // pnet doesn't have kernel timestamps
            }),
            Err(e) => {
                tracing::error!("Failed to receive packet from interface: {}", e);
                // Prevent busy loop on persistent errors
                std::thread::sleep(Duration::from_millis(250));
                None
            }
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
    fn create(
        &self,
        config: BackendConfig,
    ) -> Result<(Box<dyn PacketSource>, Box<dyn PacketSink>), Box<dyn Error + Send + Sync>> {
        let interface = interface_utils::find_interface(&config.interface_name)
            .ok_or_else(|| format!("Interface not found: {}", config.interface_name))?;

        let channel_config = Config {
            read_timeout: config.read_timeout_ms.map(Duration::from_millis),
            ..Config::default()
        };

        match channel(&interface, channel_config) {
            Ok(Channel::Ethernet(tx, rx)) => Ok((
                Box::new(PnetPacketSource { receiver: rx }),
                Box::new(PnetPacketSink {
                    sender: tx,
                    interface,
                }),
            )),
            Ok(_) => Err("Unsupported channel type".into()),
            Err(e) => Err(format!("Channel creation failed: {}", e).into()),
        }
    }

    fn name(&self) -> &'static str {
        "pnet"
    }
}
