use pnet::packet::{
    ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, MutablePacket,
    Packet,
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Level;

use pnet::{
    ipnetwork,
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    },
};
use pnet_datalink::{MacAddr as PnetMacAddr, NetworkInterface};
use tokio::{
    sync::mpsc::{self, unbounded_channel, UnboundedReceiver, UnboundedSender},
    time::{self, sleep},
};

use crate::{
    app::{AppResult, Host},
    backend::{BackendConfig, BackendFactory, BackendType, PacketSink, PacketSource, PnetBackendFactory},
    event::{Event, ScannerEvent},
    stats_aggregator::{self, StatsMap},
    trace_dbg,
    types::MacAddr,
};

#[cfg(feature = "ebpf-backend")]
use crate::backend::EbpfBackendFactory;




enum ScannerInputEvent {
    StartScanning,
}

pub struct Scanner {
    scanner_input_tx: UnboundedSender<ScannerInputEvent>,
    scanner_outputs: UnboundedSender<Event>,
    interface_name: String,
    cancel_token: CancellationToken,
    task_handles: Vec<JoinHandle<()>>,
    local_ips: HashSet<Ipv4Addr>,
    discovered_hosts: Arc<Mutex<HashSet<Ipv4Addr>>>,
}

impl Scanner {
    /// Creates a new [`Scanner`].
    pub fn new(
        scanner_outputs: mpsc::UnboundedSender<Event>,
        interface_name: String,
        backend_type: BackendType,
    ) -> AppResult<Self> {
        let backend_factory: Box<dyn BackendFactory> = match backend_type {
            BackendType::Pnet => Box::new(PnetBackendFactory),
            #[cfg(feature = "ebpf-backend")]
            BackendType::Ebpf => Box::new(EbpfBackendFactory),
            #[cfg(not(feature = "ebpf-backend"))]
            BackendType::Ebpf => panic!("eBPF backend not compiled in. Enable 'ebpf-backend' feature."),
        };
        let backend_config = BackendConfig::new(interface_name.clone());
        let (packet_source, packet_sink) = backend_factory
            .create(backend_config)
            .map_err(|e| format!("Failed to create backend: {}", e))?;

        scanner_outputs
            .send(Event::Scanner(ScannerEvent::InterfaceName(
                interface_name.clone(),
            )))
            .unwrap();

        let (scanner_input_tx, scanner_input_rx) = unbounded_channel::<ScannerInputEvent>();
        let cancel_token = CancellationToken::new();

        // Get local IPs from the interface for direction detection
        let interfaces = pnet_datalink::interfaces();
        let local_ips: HashSet<Ipv4Addr> = interfaces
            .iter()
            .filter(|nif| {
                nif.is_up()
                    && nif.is_running()
                    && !nif.is_loopback()
                    && nif.name
                        .to_lowercase()
                        .contains(&interface_name.to_lowercase())
            })
            .flat_map(|nif| {
                nif.ips
                    .iter()
                    .filter_map(|ip_network| match ip_network.ip() {
                        IpAddr::V4(ipv4) => Some(ipv4),
                        _ => None,
                    })
            })
            .collect();

        let mut scanner = Self {
            scanner_outputs,
            scanner_input_tx,
            interface_name,
            cancel_token,
            task_handles: Vec::new(),
            local_ips,
            discovered_hosts: Arc::new(Mutex::new(HashSet::new())),
        };

        scanner.start_listening(packet_source)?;
        scanner.start_tx_worker(scanner_input_rx, packet_sink)?;

        Ok(scanner)
    }

    fn start_listening(
        &mut self,
        mut packet_source: Box<dyn PacketSource>,
    ) -> AppResult<()> {
        let scanner_outputs: UnboundedSender<Event> = self.scanner_outputs.clone();
        let scanner_outputs_clone = scanner_outputs.clone();
        let agg: Arc<Mutex<StatsMap>> = Arc::new(Mutex::new(HashMap::new()));
        let agg_clone = agg.clone();
        let local_ips = self.local_ips.clone();
        let discovered_hosts = self.discovered_hosts.clone();

        // Stats aggregator task
        let stats_cancel_token = self.cancel_token.child_token();
        let stats_handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = stats_cancel_token.cancelled() => {
                        tracing::debug!("Stats aggregator task cancelled, shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        let data_clone;
                        {
                            let mut data = agg_clone.lock().unwrap();
                            data_clone = data.clone();
                            *data = HashMap::new();
                        }
                        scanner_outputs_clone
                            .send(Event::Scanner(ScannerEvent::StatTick(data_clone)))
                            .unwrap();
                    }
                }
            }
        });

        // Packet listener task
        let listener_cancel_token = self.cancel_token.child_token();
        let listener_handle = tokio::spawn(async move {
            loop {
                // Check for cancellation before blocking on packet read
                if listener_cancel_token.is_cancelled() {
                    tracing::debug!("Packet listener task cancelled, shutting down");
                    break;
                }

                if let Some(packet_ctx) = packet_source.next_packet() {
                    let buffer = &packet_ctx.data;
                    let hook_source = packet_ctx.hook_source;
                    let original_len = packet_ctx.original_len;

                    let ethernet_packet = match EthernetPacket::new(buffer) {
                        Some(packet) => packet,
                        None => continue,
                    };

                    match ethernet_packet.get_ethertype() {
                        EtherTypes::Arp => {
                            if let Some(host) = Self::get_host_infos(buffer) {
                                match scanner_outputs.send(Event::Scanner(
                                    crate::event::ScannerEvent::HostFound(host),
                                )) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        trace_dbg!(level: Level::ERROR, e);
                                    }
                                }
                            }
                        }
                        EtherTypes::Ipv4 => {
                            // Extract statistics from IPv4 packets
                            // Pass hook_source for authoritative direction detection (eBPF)
                            // Pass original_len for accurate bandwidth calculation (eBPF)
                            if let Some(stat) = Self::get_stats(&ethernet_packet, &local_ips, hook_source, original_len) {
                                let mut agg_data = agg.lock().unwrap();

                                agg_data
                                    .entry(stat.key.clone())
                                    .and_modify(|v| v.size += stat.value.size)
                                    .or_insert(stats_aggregator::StatValues { size: 0 });
                            }

                            // Also discover hosts from incoming IPv4 packets
                            if let Some(host) = Self::get_host_from_ipv4(ethernet_packet, &local_ips) {
                                // Check if this is a new host before sending event
                                let is_new_host = {
                                    let mut discovered = discovered_hosts.lock().unwrap();
                                    discovered.insert(host.ipv4)
                                };

                                if is_new_host {
                                    match scanner_outputs.send(Event::Scanner(
                                        crate::event::ScannerEvent::HostFound(host),
                                    )) {
                                        Ok(_) => {}
                                        Err(e) => {
                                            trace_dbg!(level: Level::ERROR, e);
                                        }
                                    }
                                }
                            }
                        }
                        _ => continue,
                    };
                }
            }
        });

        self.task_handles.push(stats_handle);
        self.task_handles.push(listener_handle);
        Ok(())
    }

    fn start_tx_worker(
        &mut self,
        mut scanner_input_rx: UnboundedReceiver<ScannerInputEvent>,
        mut packet_sink: Box<dyn PacketSink>,
    ) -> AppResult<()> {
        let scanner_outputs_clone = self.scanner_outputs.clone();
        let interface_name = self.interface_name.clone();
        let tx_cancel_token = self.cancel_token.child_token();
        let tx_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tx_cancel_token.cancelled() => {
                        tracing::debug!("TX worker task cancelled, shutting down");
                        break;
                    }
                    event = scanner_input_rx.recv() => {
                        match event {
                            Some(ScannerInputEvent::StartScanning) => {
                                // Get interface for current backend
                                let interfaces = pnet_datalink::interfaces();
                                let nif = interfaces
                                    .into_iter()
                                    .rev()
                                    .find(|nif| {
                                        nif.is_up()
                                            && nif.is_running()
                                            && !nif.is_loopback()
                                            && nif.name
                                                .to_lowercase()
                                                .contains(&interface_name.to_lowercase())
                                    })
                                    .unwrap(); // Should exist since backend was created successfully

                                for ip_network in nif
                                    .clone()
                                    .ips
                                    .into_iter()
                                    .filter(|&ip_network| ip_network.is_ipv4())
                                {
                                    Self::scan_range(
                                        &nif,
                                        ip_network,
                                        scanner_outputs_clone.clone(),
                                        &mut packet_sink,
                                    )
                                    .await;
                                }
                            }
                            None => break, // Channel closed
                        }
                    }
                }
            }
        });

        self.task_handles.push(tx_handle);
        Ok(())
    }
    async fn scan_range(
        nif: &NetworkInterface,
        ip_network: ipnetwork::IpNetwork,
        scanner_outputs: mpsc::UnboundedSender<Event>,
        packet_sink: &mut Box<dyn PacketSink>,
    ) {
        scanner_outputs
            .send(Event::Scanner(crate::event::ScannerEvent::BeginScan))
            .unwrap();
        let sender_clone = scanner_outputs.clone();
        let sender = sender_clone;
        for ip_addr in ip_network.iter() {
            if let IpAddr::V4(ipv4_address) = ip_addr {
                sleep(Duration::from_millis(37)).await;
                let _ = Self::send_arp_request(packet_sink, nif, ipv4_address);
            }
        }
        sender
            .send(Event::Scanner(crate::event::ScannerEvent::Complete))
            .unwrap();
    }

    fn send_arp_request(
        packet_sink: &mut Box<dyn PacketSink>,
        interface: &NetworkInterface,
        target_ip: Ipv4Addr,
    ) -> AppResult<()> {
        let mut ethernet_buffer = vec![0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
            .ok_or("Failed to create Ethernet packet from buffer")?;

        let target_mac_broadcast = PnetMacAddr::broadcast();
        let source_mac = interface.mac.ok_or("Interface missing MAC address")?;

        ethernet_packet.set_destination(target_mac_broadcast);
        ethernet_packet.set_source(source_mac);

        let selected_ethertype = EtherTypes::Arp;
        ethernet_packet.set_ethertype(selected_ethertype);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)
            .ok_or("Failed to create ARP packet from buffer")?;

        let source_ip = Self::find_source_ip(interface)?;

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(target_mac_broadcast);
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet_mut());

        packet_sink
            .send_packet(ethernet_packet.to_immutable().packet())
            .map_err(|e| format!("Failed to send ARP request: {}", e))?;
        Ok(())
    }

    fn find_source_ip(network_interface: &NetworkInterface) -> AppResult<Ipv4Addr> {
        let potential_network = network_interface
            .ips
            .iter()
            .find(|network| network.is_ipv4());
        match potential_network.map(|network| network.ip()) {
            Some(IpAddr::V4(ipv4_addr)) => Ok(ipv4_addr),
            Some(other) => Err(format!("Expected IPv4, found: {}", other).into()),
            None => Err("No IPv4 address found on interface".into()),
        }
    }

    pub fn send_arp_packets(&self) {
        self.scanner_input_tx
            .send(ScannerInputEvent::StartScanning)
            .unwrap();
    }

    /// Remove hosts from the discovered set, allowing them to be re-discovered.
    /// This should be called when hosts are cleared/deleted from the UI.
    pub fn remove_discovered_hosts(&self, ips: &[Ipv4Addr]) {
        let mut discovered = self.discovered_hosts.lock().unwrap();
        for ip in ips {
            discovered.remove(ip);
        }
    }

    fn get_host_infos(buffer: &[u8]) -> Option<Host> {
        let arp_packet = ArpPacket::new(&buffer[MutableEthernetPacket::minimum_packet_size()..]);
        if let Some(arp) = arp_packet {
            let sender_ipv4 = arp.get_sender_proto_addr();
            let sender_mac_raw = arp.get_sender_hw_addr();
            let sender_mac: MacAddr = sender_mac_raw.into();

            let host = Host {
                hostname: None,
                time: chrono::Local::now(),
                mac: sender_mac,
                ipv4: sender_ipv4,
                is_my_device_mac: false, // TODO: Fix when implementing eBPF
                speed: None,
            };
            Some(host)
        } else {
            None
        }
    }

    /// Extract host information from an IPv4 packet.
    /// Only extracts hosts from incoming packets (dst is local, src is remote)
    /// to ensure we have reliable MAC addresses from the Ethernet frame.
    fn get_host_from_ipv4(
        ethernet_packet: EthernetPacket,
        local_ips: &HashSet<Ipv4Addr>,
    ) -> Option<Host> {
        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
        let src_ip = ipv4_packet.get_source();
        let dst_ip = ipv4_packet.get_destination();

        // Only extract remote hosts from incoming packets
        // (where dst is local and src is not)
        let src_is_local = local_ips.contains(&src_ip);
        let dst_is_local = local_ips.contains(&dst_ip);

        if !dst_is_local || src_is_local {
            return None;
        }

        // Extract source MAC from Ethernet frame
        let src_mac_raw = ethernet_packet.get_source();
        let src_mac: MacAddr = src_mac_raw.into();

        let host = Host {
            hostname: None,
            time: chrono::Local::now(),
            mac: src_mac,
            ipv4: src_ip,
            is_my_device_mac: false,
            speed: None,
        };
        Some(host)
    }

    /// Extract statistics from an IPv4 packet.
    ///
    /// # Arguments
    /// * `ethernet_packet` - The Ethernet packet containing IPv4 data
    /// * `local_ips` - Set of local IP addresses for direction detection
    /// * `hook_source` - Optional hook source from eBPF:
    ///   - Some(0) = XDP (ingress) → Download
    ///   - Some(2) = TC egress → Upload
    ///   - None = pnet backend (use IP-based direction detection)
    /// * `original_len` - Original packet length from wire (eBPF provides this from kernel)
    fn get_stats(
        ethernet_packet: &EthernetPacket,
        local_ips: &HashSet<Ipv4Addr>,
        hook_source: Option<u8>,
        original_len: Option<u32>,
    ) -> Option<stats_aggregator::StatItem> {
        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
        let src_ip = ipv4_packet.get_source();
        let dst_ip = ipv4_packet.get_destination();
        let next_level_protocol = ipv4_packet.get_next_level_protocol();

        // Determine direction based on hook source (authoritative for eBPF)
        // or fall back to IP-based detection (for pnet backend)
        let direction = match hook_source {
            // XDP captures ingress (packets coming INTO the interface) = Download
            Some(0) => {
                tracing::debug!("Direction: DOWNLOAD (XDP hook) src={} dst={}", src_ip, dst_ip);
                stats_aggregator::Direction::Incomming
            }
            // TC egress captures egress (packets leaving the interface) = Upload
            Some(2) => {
                tracing::debug!("Direction: UPLOAD (TC egress hook) src={} dst={}", src_ip, dst_ip);
                stats_aggregator::Direction::Outgoing
            }
            // Fallback to IP-based detection for pnet backend or unknown hooks
            _ => {
                let src_is_local = local_ips.contains(&src_ip);
                let dst_is_local = local_ips.contains(&dst_ip);

                if src_is_local && dst_is_local {
                    tracing::debug!("LOCAL: src_ip={} (local) -> dst_ip={} (local)", src_ip, dst_ip);
                    stats_aggregator::Direction::Local
                } else if src_is_local {
                    tracing::debug!("UPLOAD (IP-based): src_ip={} (local) -> dst_ip={} (remote)", src_ip, dst_ip);
                    stats_aggregator::Direction::Outgoing
                } else if dst_is_local {
                    tracing::debug!("DOWNLOAD (IP-based): src_ip={} (remote) -> dst_ip={} (local)", src_ip, dst_ip);
                    stats_aggregator::Direction::Incomming
                } else {
                    stats_aggregator::Direction::None
                }
            }
        };

        // Calculate packet size in bits for bandwidth
        // For eBPF: use original_len from kernel (accurate wire length)
        // For pnet: parse from packet payload (TCP/UDP payload only)
        let size_bits: u128 = if let Some(len) = original_len {
            // eBPF path: use the accurate packet length from kernel
            // This is the full packet size as seen on the wire
            let bits = 8 * len as u128;
            tracing::info!("BANDWIDTH: original_len={} bytes -> {} bits ({} bytes) direction={:?}",
                len, bits, len, direction);
            bits
        } else {
            // pnet path: calculate from parsed payload
            // Use IPv4 total length (includes IP header + data) plus Ethernet header (14 bytes)
            // This ensures we count the full packet size on wire, matching eBPF behavior
            let len = (ipv4_packet.get_total_length() as u128) + 14;
            len * 8
        };

        // Only create stat for TCP/UDP (need ports for the key)
        let stat = match next_level_protocol {
            IpNextHeaderProtocols::Tcp => {
                let message = TcpPacket::new(ipv4_packet.payload())?;
                Some(stats_aggregator::StatItem {
                    key: stats_aggregator::StatKey {
                        direction,
                        src_port: message.get_source(),
                        sdt_port: message.get_destination(),
                        src_ip,
                        dst_ip,
                    },
                    value: stats_aggregator::StatValues {
                        size: size_bits,
                    },
                })
            }
            IpNextHeaderProtocols::Udp => {
                let datagram = UdpPacket::new(ipv4_packet.payload())?;
                Some(stats_aggregator::StatItem {
                    key: stats_aggregator::StatKey {
                        direction,
                        src_port: datagram.get_source(),
                        sdt_port: datagram.get_destination(),
                        src_ip,
                        dst_ip,
                    },
                    value: stats_aggregator::StatValues {
                        size: size_bits,
                    },
                })
            }
            _ => None,
        };

        stat
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        tracing::debug!("Scanner::drop() called, cancelling background tasks");
        self.cancel_token.cancel();
        // Abort handles for immediate cleanup
        for handle in self.task_handles.drain(..) {
            handle.abort();
        }
    }
}
