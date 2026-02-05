//! eBPF packet source and sink implementations.
//!
//! This module provides the concrete implementations of PacketSource and PacketSink
//! for the eBPF backend, using the helper modules for packet parsing, reader spawning,
//! and program loading.

use std::error::Error;

use aya::programs::{tc::SchedClassifierLinkId, xdp::XdpLinkId};
use aya::{maps::perf::AsyncPerfEventArray, maps::MapData};
use tokio::sync::mpsc;

use crate::backend::{BackendConfig, BackendFactory, PacketSink, PacketSource, PacketWithContext};
use crate::interface_utils;

#[cfg(feature = "pnet-backend")]
use pnet_datalink::{self, Channel, Config, DataLinkSender, NetworkInterface};

use super::loader::{load_and_attach_programs, EbpfAttachment};
use super::perf_reader::spawn_packet_readers;

/// Packet source that reads from eBPF PerfEventArray via a bounded channel.
///
/// Packets are delivered to this source through a channel that's populated by
/// async tasks reading from the per-CPU perf event buffers.
/// The bounded channel prevents unbounded memory growth during packet floods.
pub struct EbpfPacketSource {
    /// Channel receiver for packets from the async readers
    packet_rx: mpsc::Receiver<PacketWithContext>,
    /// Keep the BPF object alive to prevent program detachment
    _bpf: aya::Ebpf,
    /// Keep the XDP link alive to prevent program detachment
    _xdp_link_id: Option<XdpLinkId>,
    /// Keep the TC egress link alive to prevent program detachment
    _tc_egress_link_id: Option<SchedClassifierLinkId>,
}

impl EbpfPacketSource {
    /// Create a new EbpfPacketSource from loaded eBPF programs.
    ///
    /// # Arguments
    /// * `attachment` - The loaded eBPF programs and link IDs
    /// * `perf_array` - The PerfEventArray map for reading packets
    pub fn from_loaded_programs(
        attachment: EbpfAttachment,
        perf_array: AsyncPerfEventArray<MapData>,
    ) -> Self {
        // Spawn packet readers (this is synchronous, just spawns background tasks)
        let packet_rx = spawn_packet_readers(&mut perf_array.into());

        Self {
            packet_rx,
            _bpf: attachment.bpf,
            _xdp_link_id: attachment.xdp_link_id,
            _tc_egress_link_id: attachment.tc_egress_link_id,
        }
    }
}

impl PacketSource for EbpfPacketSource {
    fn next_packet(&mut self) -> Option<PacketWithContext> {
        // Try to receive a packet from the channel without blocking
        // The channel is populated by async tasks reading from PerfEventArray
        self.packet_rx.try_recv().ok()
    }
}

/// Packet sink - eBPF XDP is receive-only, so we use pnet for sending.
///
/// This hybrid approach allows us to:
/// - Use eBPF XDP for efficient packet capture
/// - Use pnet for sending packets (ARP scanning, etc.)
#[cfg(feature = "pnet-backend")]
pub struct EbpfPacketSink {
    sender: Option<Box<dyn DataLinkSender>>,
    interface: Option<NetworkInterface>,
}

#[cfg(feature = "pnet-backend")]
impl EbpfPacketSink {
    /// Create a new packet sink using pnet for sending.
    ///
    /// # Arguments
    /// * `interface_name` - Name of the network interface
    pub fn new(interface_name: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Find the network interface
        let interface = interface_utils::find_interface(interface_name)
            .ok_or_else(|| format!("Interface not found: {}", interface_name))?;

        // Create a pnet channel for sending only
        match pnet_datalink::channel(&interface, Config::default()) {
            Ok(Channel::Ethernet(tx, _rx)) => Ok(Self {
                sender: Some(tx),
                interface: Some(interface),
            }),
            Ok(_) => Err("Unsupported channel type".into()),
            Err(e) => Err(format!("Channel creation failed: {}", e).into()),
        }
    }
}

#[cfg(feature = "pnet-backend")]
impl PacketSink for EbpfPacketSink {
    fn send_packet(&mut self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(sender) = &mut self.sender {
            match sender.send_to(data, self.interface.clone()) {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(format!("Send failed: {}", e).into()),
                None => Err("Failed to send packet".into()),
            }
        } else {
            Err("Packet sink not initialized".into())
        }
    }
}

/// Fallback implementation when pnet-backend is not available.
#[cfg(not(feature = "pnet-backend"))]
pub struct EbpfPacketSink;

#[cfg(not(feature = "pnet-backend"))]
impl EbpfPacketSink {
    /// Create a new (non-functional) packet sink.
    ///
    /// Always returns an error since sending is not available without pnet.
    pub fn new(_interface_name: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Err("eBPF packet sending requires the 'pnet-backend' feature to be enabled".into())
    }
}

#[cfg(not(feature = "pnet-backend"))]
impl PacketSink for EbpfPacketSink {
    fn send_packet(&mut self, _data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        Err("eBPF packet sending requires the 'pnet-backend' feature to be enabled".into())
    }
}

/// Factory for creating eBPF backend instances.
pub struct EbpfBackendFactory;

impl BackendFactory for EbpfBackendFactory {
    fn create(
        &self,
        config: BackendConfig,
    ) -> Result<(Box<dyn PacketSource>, Box<dyn PacketSink>), Box<dyn Error + Send + Sync>> {
        tracing::info!(
            "Initializing eBPF backend for interface: {}",
            config.interface_name
        );

        // Load and attach eBPF programs using the loader module
        let mut attachment = load_and_attach_programs(&config)?;

        // Take the PerfEventArray map from the BPF object and convert to async
        let perf_map = attachment
            .bpf
            .take_map("EVENTS")
            .ok_or("PerfEventArray 'EVENTS' not found in eBPF bytecode")?;

        let async_perf = AsyncPerfEventArray::try_from(perf_map)
            .map_err(|e| format!("Failed to create async perf array: {}", e))?;

        // Create packet source with link IDs to keep programs attached
        let packet_source = Box::new(EbpfPacketSource::from_loaded_programs(
            attachment, async_perf,
        ));

        // Create packet sink (hybrid: eBPF for receive, pnet for send)
        #[cfg(feature = "pnet-backend")]
        let packet_sink: Box<dyn PacketSink> = {
            tracing::info!("Initializing pnet-based packet sink for sending");
            Box::new(EbpfPacketSink::new(&config.interface_name)?)
        };

        #[cfg(not(feature = "pnet-backend"))]
        let packet_sink: Box<dyn PacketSink> = {
            tracing::warn!("Packet sending disabled (pnet-backend feature not enabled)");
            Box::new(EbpfPacketSink)
        };

        tracing::info!("eBPF backend initialization complete");
        Ok((packet_source, packet_sink))
    }

    fn name(&self) -> &'static str {
        "ebpf"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_backend_factory_name() {
        let factory = EbpfBackendFactory;
        assert_eq!(factory.name(), "ebpf");
    }

    #[cfg(feature = "pnet-backend")]
    #[test]
    fn test_ebpf_packet_sink_creation_fails_without_interface() {
        let result = EbpfPacketSink::new("nonexistent_interface_12345");
        assert!(result.is_err());
    }
}
