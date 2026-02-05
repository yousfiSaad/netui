//! eBPF backend implementation modules.
//!
//! This module provides the eBPF-based packet capture backend, which uses
//! XDP and TC programs for efficient kernel-space packet filtering.

pub mod backend;
pub mod loader;
pub mod packet;
pub mod perf_reader;

pub use backend::{EbpfBackendFactory, EbpfPacketSink, EbpfPacketSource};
pub use loader::{
    attach_tc_egress, attach_xdp, find_ebpf_binary, load_and_attach_programs, EbpfAttachment,
};
pub use packet::{parse_packet_event, reconstruct_ethernet_packet, PacketEvent};
pub use perf_reader::spawn_packet_readers;
