//! PerfEventArray reader for eBPF packet capture.
//!
//! This module handles spawning async tasks to read packets from the
//! per-CPU perf event buffers populated by the eBPF programs.

use aya::{maps::perf::AsyncPerfEventArray, maps::MapData};
use bytes::BytesMut;
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::{self, Duration};

use super::packet::{parse_packet_event, reconstruct_ethernet_packet, PacketEvent};
use crate::backend::{DirectEventData, PacketWithContext};
use crate::constants::{buffer, ebpf, timing};

/// Spawns async tasks to read packets from the PerfEventArray.
///
/// This function spawns one task per CPU to read from that CPU's perf event buffer.
/// Each task continuously reads packets and sends them to the channel.
///
/// # Arguments
/// * `perf_array` - The PerfEventArray map to read from
///
/// # Returns
/// A receiver that can be used to get packets with context from all CPU buffers
///
/// # Behavior
/// - Spawns one async task per online CPU
/// - Each task reads from that CPU's perf event buffer
/// - Packets are sent through a channel to the receiver
/// - Tasks handle errors gracefully with retry logic
pub fn spawn_packet_readers(
    perf_array: &mut AsyncPerfEventArray<MapData>,
) -> mpsc::Receiver<PacketWithContext> {
    // Bounded channel to prevent unbounded memory growth during packet floods
    const PACKET_CHANNEL_CAPACITY: usize = 1000;
    let (tx, rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);

    // Get the number of online CPUs
    let cpus = match aya::util::online_cpus() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to get online CPUs: {:?}", e);
            // Return empty receiver if we can't get CPUs
            return rx;
        }
    };

    let mut spawned_count = 0;

    for cpu_id in cpus {
        // Open the perf buffer for this CPU
        let buf = match perf_array.open(cpu_id, None) {
            Ok(b) => b,
            Err(_e) => {
                // Silently skip CPUs that fail to open (reduces flickering)
                continue;
            }
        };

        spawned_count += 1;
        let tx = tx.clone();

        // Spawn a task to read from this CPU's buffer
        task::spawn(async move {
            let mut buf = buf;
            let mut packets = vec![
                BytesMut::with_capacity(std::mem::size_of::<PacketEvent>());
                buffer::PERF_PACKET_BUFFER_CAPACITY
            ];
            let mut error_count = 0;
            let cpu_id_usize = cpu_id as usize;

            loop {
                match buf.read_events(&mut packets).await {
                    Ok(events) => {
                        error_count = 0;

                        for packet_buf in packets.iter_mut().take(events.read) {
                            if let Some(event) = parse_packet_event(packet_buf) {
                                let hook_name = match event.hook_source {
                                    ebpf::HOOK_XDP => "XDP",
                                    ebpf::HOOK_TC_INGRESS => "TC_INGRESS",
                                    ebpf::HOOK_TC_EGRESS => "TC_EGRESS",
                                    _ => "UNKNOWN",
                                };
                                tracing::debug!(
                                    "CPU {}: Packet from {}: src_ip={:?} dst_ip={:?} len={}",
                                    cpu_id_usize,
                                    hook_name,
                                    event.src_ip,
                                    event.dst_ip,
                                    event.len
                                );

                                // For TCP/UDP, use direct processing from PacketEvent
                                // For ARP, reconstruct packet for host discovery
                                let is_tcp_udp = event.protocol == 6 || event.protocol == 17;
                                let packet_ctx = if is_tcp_udp {
                                    // Direct processing path for TCP/UDP
                                    let direct_event = DirectEventData {
                                        src_ip: event.src_ip,
                                        dst_ip: event.dst_ip,
                                        src_port: event.src_port,
                                        dst_port: event.dst_port,
                                        protocol: event.protocol,
                                        tcp_flags: event.tcp_flags,
                                        tcp_seq: event.tcp_seq,
                                        tcp_ack: event.tcp_ack,
                                    };
                                    PacketWithContext {
                                        data: Vec::new(), // Not used for direct processing
                                        hook_source: Some(event.hook_source),
                                        original_len: Some(event.len),
                                        direct_event: Some(direct_event),
                                        timestamp_ns: Some(event.timestamp_ns),
                                    }
                                } else {
                                    // Reconstruct packet for ARP or other protocols
                                    let packet = reconstruct_ethernet_packet(event);
                                    PacketWithContext {
                                        data: packet,
                                        hook_source: Some(event.hook_source),
                                        original_len: Some(event.len),
                                        direct_event: None,
                                        timestamp_ns: Some(event.timestamp_ns),
                                    }
                                };

                                if tx.send(packet_ctx).await.is_err() {
                                    tracing::debug!(
                                        "CPU {}: Channel closed, stopping reader",
                                        cpu_id_usize
                                    );
                                    return;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error_count += 1;
                        if error_count >= buffer::MAX_CONSECUTIVE_ERRORS {
                            tracing::error!(
                                "CPU {}: Too many consecutive errors ({}), stopping reader: {:?}",
                                cpu_id_usize,
                                error_count,
                                e
                            );
                            return;
                        }
                        time::sleep(Duration::from_millis(timing::READER_ERROR_RETRY_DELAY_MS))
                            .await;
                    }
                }
            }
        });
    }

    // Drop the original tx - the cloned ones are held by the tasks
    drop(tx);

    if spawned_count == 0 {
        tracing::warn!("No packet reader tasks were spawned successfully");
    }

    rx
}

#[cfg(test)]
mod tests {
    // Note: Full integration tests require actual eBPF programs loaded,
    // which is difficult to unit test. The module is primarily
    // tested through integration testing with the actual backend.
}
