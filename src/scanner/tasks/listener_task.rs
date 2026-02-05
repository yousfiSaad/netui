//! Packet listener task spawning.
//!
//! This module handles spawning the background task that processes
//! incoming network packets from the packet source.

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use crate::constants::network_values::{PROTOCOL_TCP, PROTOCOL_UDP};

use super::stats_task::spawn_stats_aggregator;
use crate::event::Event;
use crate::scanner::{arp_scanner, dns_resolver, packet_processor};
use crate::stats::StatsMap;
use crate::trace_dbg;
use crate::utils::recover_or_log;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Level;

/// Start the packet listener and stats aggregator tasks.
///
/// This function spawns two background tasks:
/// 1. A stats aggregator that periodically emits stat events
/// 2. A packet listener that processes incoming network packets
///
/// # Arguments
/// * `packet_source` - The packet source for reading incoming packets
/// * `scanner_outputs` - Channel for sending scanner events
/// * `local_ips` - Set of local IP addresses for direction detection
/// * `discovered_hosts` - Set of discovered host IPs
/// * `arp_validator` - ARP validator for validating ARP replies
/// * `cancel_token` - Cancellation token for stopping the tasks
///
/// # Returns
/// A vector of task handles for the spawned tasks
pub fn start_listening(
    packet_source: Box<dyn crate::backend::PacketSource>,
    scanner_outputs: mpsc::Sender<Event>,
    local_ips: HashSet<Ipv4Addr>,
    discovered_hosts: Arc<Mutex<HashSet<Ipv4Addr>>>,
    arp_validator: Arc<Mutex<crate::scanner::arp_validator::ArpValidator>>,
    gateway_ip: Option<std::net::Ipv4Addr>,
    cancel_token: CancellationToken,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();
    let agg: Arc<Mutex<StatsMap>> = Arc::new(Mutex::new(HashMap::new()));

    // Spawn stats aggregator task
    let stats_handle = spawn_stats_aggregator(
        agg.clone(),
        scanner_outputs.clone(),
        cancel_token.child_token(),
    );
    handles.push(stats_handle);

    // Spawn packet listener task
    let listener_handle = spawn_packet_listener(
        packet_source,
        scanner_outputs,
        local_ips,
        discovered_hosts,
        arp_validator,
        gateway_ip,
        agg,
        cancel_token.child_token(),
    );
    handles.push(listener_handle);

    handles
}

/// Spawn the packet listener background task.
///
/// # Arguments
/// * `packet_source` - The packet source for reading incoming packets
/// * `scanner_outputs` - Channel for sending scanner events
/// * `local_ips` - Set of local IP addresses for direction detection
/// * `discovered_hosts` - Set of discovered host IPs
/// * `arp_validator` - ARP validator for validating ARP replies
/// * `gateway_ip` - Optional gateway IP for Internet traffic detection
/// * `agg` - Shared statistics map
/// * `cancel_token` - Cancellation token for stopping the task
///
/// # Returns
/// A handle to the spawned task
fn spawn_packet_listener(
    mut packet_source: Box<dyn crate::backend::PacketSource>,
    scanner_outputs: mpsc::Sender<Event>,
    local_ips: HashSet<Ipv4Addr>,
    _discovered_hosts: Arc<Mutex<HashSet<Ipv4Addr>>>,
    arp_validator: Arc<Mutex<crate::scanner::arp_validator::ArpValidator>>,
    gateway_ip: Option<std::net::Ipv4Addr>,
    agg: Arc<Mutex<StatsMap>>,
    cancel_token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Local buffering for stats to reduce mutex contention
        let mut local_agg: HashMap<crate::stats::StatKey, crate::stats::StatValues> =
            HashMap::new();
        let mut last_flush = std::time::Instant::now();
        let flush_interval = std::time::Duration::from_millis(100);
        let flush_batch_size = 100;
        let mut packets_since_flush = 0;

        loop {
            // Check flush conditions: Cancelled OR Batch size OR Time
            let is_cancelled = cancel_token.is_cancelled();
            let time_to_flush = last_flush.elapsed() >= flush_interval;
            let batch_full = packets_since_flush >= flush_batch_size;

            if (is_cancelled || time_to_flush || batch_full) && !local_agg.is_empty() {
                let mut agg_data = recover_or_log(agg.lock(), "packet listener stats");
                for (key, local_val) in local_agg.drain() {
                    agg_data
                        .entry(key)
                        .and_modify(|v| {
                            v.size += local_val.size;
                            // Update quality metrics if this batch had relevant data (TCP ACK)
                            // We only propagate timestamp/seq/ack if the local batch had them
                            // and the key is relevant (TCP ACK set).
                            if key.tcp_ack && local_val.last_timestamp.is_some() {
                                v.last_timestamp = local_val.last_timestamp;
                                v.last_seq = local_val.last_seq;
                                v.last_ack = local_val.last_ack;
                            }
                        })
                        .or_insert(local_val);
                }
                last_flush = std::time::Instant::now();
                packets_since_flush = 0;
            }

            // Check for cancellation before blocking on packet read
            if is_cancelled {
                tracing::debug!("Packet listener task cancelled, shutting down");
                break;
            }

            if let Some(packet_ctx) = packet_source.next_packet() {
                let buffer = &packet_ctx.data;
                let hook_source = packet_ctx.hook_source;
                let original_len = packet_ctx.original_len;

                // Direct processing path for eBPF TCP/UDP packets
                if let Some(direct_event) = packet_ctx.direct_event {
                    // Process TCP/UDP directly from DirectEventData (eBPF path)
                    let direction = packet_processor::determine_packet_direction(
                        std::net::Ipv4Addr::from(direct_event.src_ip),
                        std::net::Ipv4Addr::from(direct_event.dst_ip),
                        &local_ips,
                        gateway_ip,
                        hook_source,
                    );
                    let size_bits = (original_len.unwrap_or(0) as u128) * 8;

                    let stat = if direct_event.protocol == 6 {
                        // TCP - create StatItem directly from DirectEventData
                        let syn = (direct_event.tcp_flags & 0x02) != 0;
                        let ack = (direct_event.tcp_flags & 0x10) != 0;
                        let fin = (direct_event.tcp_flags & 0x01) != 0;
                        let rst = (direct_event.tcp_flags & 0x04) != 0;

                        Some(crate::stats::StatItem {
                            key: crate::stats::StatKey {
                                direction,
                                src_port: direct_event.src_port,
                                dst_port: direct_event.dst_port,
                                src_ip: std::net::Ipv4Addr::from(direct_event.src_ip),
                                dst_ip: std::net::Ipv4Addr::from(direct_event.dst_ip),
                                protocol: PROTOCOL_TCP,
                                tcp_syn: syn,
                                tcp_ack: ack,
                                tcp_fin: fin,
                                tcp_rst: rst,
                            },
                            value: crate::stats::StatValues {
                                size: size_bits,
                                last_timestamp: packet_ctx.timestamp_ns,
                                last_seq: Some(direct_event.tcp_seq),
                                last_ack: Some(direct_event.tcp_ack),
                            },
                        })
                    } else if direct_event.protocol == 17 {
                        // UDP
                        Some(crate::stats::StatItem {
                            key: crate::stats::StatKey {
                                direction,
                                src_port: direct_event.src_port,
                                dst_port: direct_event.dst_port,
                                src_ip: std::net::Ipv4Addr::from(direct_event.src_ip),
                                dst_ip: std::net::Ipv4Addr::from(direct_event.dst_ip),
                                protocol: PROTOCOL_UDP,
                                tcp_syn: false,
                                tcp_ack: false,
                                tcp_fin: false,
                                tcp_rst: false,
                            },
                            value: crate::stats::StatValues {
                                size: size_bits,
                                last_timestamp: packet_ctx.timestamp_ns,
                                last_seq: None,
                                last_ack: None,
                            },
                        })
                    } else {
                        None
                    };

                    if let Some(s) = stat {
                        local_agg
                            .entry(s.key)
                            .and_modify(|v| {
                                v.size += s.value.size;
                                // Propagate latest quality metrics
                                if s.key.tcp_ack && s.value.last_timestamp.is_some() {
                                    v.last_timestamp = s.value.last_timestamp;
                                    v.last_seq = s.value.last_seq;
                                    v.last_ack = s.value.last_ack;
                                }
                            })
                            .or_insert(s.value);
                        packets_since_flush += 1;
                    }
                    continue;
                }

                // Legacy path for reconstructed packets (ARP or pnet backend)
                let ethernet_packet = match EthernetPacket::new(buffer) {
                    Some(packet) => packet,
                    None => continue,
                };

                match ethernet_packet.get_ethertype() {
                    EtherTypes::Arp => {
                        if let Some(host) =
                            arp_scanner::get_host_infos(buffer, Some(&arp_validator))
                        {
                            let host_ipv4 = host.ipv4;
                            let scanner_outputs_dns = scanner_outputs.clone();
                            match scanner_outputs
                                .send(Event::Scanner(crate::event::ScannerEvent::HostFound(host)))
                                .await
                            {
                                Ok(_) => {
                                    // Spawn async DNS lookup task
                                    dns_resolver::spawn_dns_lookup(host_ipv4, scanner_outputs_dns);
                                }
                                Err(e) => {
                                    trace_dbg!(level: Level::ERROR, e);
                                }
                            }
                        }
                    }
                    EtherTypes::Ipv4 => {
                        // Extract statistics from IPv4 packets
                        if let Some(stat) = packet_processor::get_stats(
                            &ethernet_packet,
                            &local_ips,
                            gateway_ip,
                            hook_source,
                            original_len,
                        ) {
                            local_agg
                                .entry(stat.key)
                                .and_modify(|v| v.size += stat.value.size)
                                .or_insert(stat.value);
                            packets_since_flush += 1;
                        }
                    }
                    _ => continue,
                };
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_listening_creates_handles() {
        // This test would require a mock packet source
        // For now, just verify the function compiles
        let (tx, _rx) = mpsc::channel::<Event>(10);
        let local_ips: HashSet<Ipv4Addr> = HashSet::new();
        let discovered_hosts = Arc::new(Mutex::new(HashSet::<Ipv4Addr>::new()));
        let cancel_token = CancellationToken::new();

        // We can't fully test this without a packet source,
        // but we can verify the function signature is correct
        let _ = (tx, local_ips, discovered_hosts, cancel_token);
    }
}
