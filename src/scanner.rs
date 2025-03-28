use pnet::packet::{
    ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, MutablePacket,
    Packet,
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    process,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::Level;

use pnet::{
    ipnetwork,
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    },
};
use pnet_datalink::{DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use tokio::{
    sync::mpsc::{self, unbounded_channel, UnboundedReceiver, UnboundedSender},
    time::{self, sleep},
};

use crate::{
    app::{AppResult, Host},
    event::{Event, ScannerEvent},
    stats_aggregator::{self, StatsMap},
    trace_dbg,
};

enum ScannerInputEvent {
    StartScanning,
}

pub struct Scanner {
    scanner_input_tx: UnboundedSender<ScannerInputEvent>,
    scanner_outputs: UnboundedSender<Event>,
}

impl Scanner {
    /// Creates a new [`Scanner`].
    pub fn new(
        scanner_outputs: mpsc::UnboundedSender<Event>,
        interface_name: String,
    ) -> AppResult<Self> {
        let nif = Self::find_interface_or_get_default(interface_name)?;
        scanner_outputs
            .send(Event::Scanner(ScannerEvent::InterfaceName(
                nif.name.clone(),
            )))
            .unwrap();

        let (scanner_input_tx, scanner_input_rx) = unbounded_channel::<ScannerInputEvent>();

        let mut scanner = Self {
            scanner_outputs,
            scanner_input_tx,
        };

        let (datalink_tx, datalink_rx) = Self::create_datalink_channel(nif.clone())?;
        scanner.start_listening(datalink_rx, nif.clone())?;
        scanner.start_tx_worker(scanner_input_rx, datalink_tx, nif)?;

        Ok(scanner)
    }

    fn create_datalink_channel(
        nif: NetworkInterface,
    ) -> AppResult<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
        let channel_config = pnet_datalink::Config {
            read_timeout: Some(Duration::from_millis(500)),
            ..pnet_datalink::Config::default()
        };
        let pair = match pnet_datalink::channel(&nif, channel_config) {
            Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                process::exit(1);
            }
            Err(_error) => {
                process::exit(1);
            }
        };
        Ok(pair)
    }

    fn start_listening(
        &self,
        mut datalink_rx: Box<dyn DataLinkReceiver>,
        def_nif: NetworkInterface,
    ) -> AppResult<()> {
        let scanner_outputs: UnboundedSender<Event> = self.scanner_outputs.clone();
        let scanner_outputs_clone = scanner_outputs.clone();
        let agg: Arc<Mutex<StatsMap>> = Arc::new(Mutex::new(HashMap::new()));
        let agg_clone = agg.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
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
        });

        tokio::spawn(async move {
            loop {
                if let Ok(buffer) = datalink_rx.next() {
                    let ethernet_packet = match EthernetPacket::new(buffer) {
                        Some(packet) => packet,
                        None => continue,
                    };

                    match ethernet_packet.get_ethertype() {
                        EtherTypes::Arp => {
                            if let Some(host) = Self::get_host_infos(buffer, &def_nif) {
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
                            if let Some(stat) = Self::get_stats(ethernet_packet, &def_nif) {
                                {
                                    let mut agg_data = agg.lock().unwrap();

                                    agg_data
                                        .entry(stat.key.clone())
                                        .and_modify(|v| v.size += stat.value.size)
                                        .or_insert(stats_aggregator::StatValues { size: 0 });
                                }
                            }
                        }
                        _ => continue,
                    };
                }
            }
        });
        Ok(())
    }

    fn start_tx_worker(
        &mut self,
        mut scanner_input_rx: UnboundedReceiver<ScannerInputEvent>,
        mut datalink_channel_tx: Box<dyn DataLinkSender>,
        nif: NetworkInterface,
    ) -> AppResult<()> {
        let scanner_outputs_clone = self.scanner_outputs.clone();
        tokio::spawn(async move {
            while let Some(event) = scanner_input_rx.recv().await {
                if !matches!(event, ScannerInputEvent::StartScanning) {
                    continue;
                }

                let nif = nif.clone();
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
                        &mut datalink_channel_tx,
                    )
                    .await;
                }
            }
        });
        Ok(())
    }
    async fn scan_range(
        nif: &NetworkInterface,
        ip_network: ipnetwork::IpNetwork,
        scanner_outputs: mpsc::UnboundedSender<Event>,
        datalink_channel_tx: &mut Box<dyn DataLinkSender>,
    ) {
        scanner_outputs
            .send(Event::Scanner(crate::event::ScannerEvent::BeginScan))
            .unwrap();
        let sender_clone = scanner_outputs.clone();
        let sender = sender_clone;
        for ip_addr in ip_network.iter() {
            if let IpAddr::V4(ipv4_address) = ip_addr {
                sleep(Duration::from_millis(37)).await;
                Self::send_arp_request(datalink_channel_tx, nif, ipv4_address);
            }
        }
        sender
            .send(Event::Scanner(crate::event::ScannerEvent::Complete))
            .unwrap();
    }

    fn find_interface(interface_name: String) -> AppResult<pnet_datalink::NetworkInterface> {
        let interfaces = pnet_datalink::interfaces();

        Ok(interfaces
            .into_iter()
            .rev()
            .find(|nif| {
                nif.is_up()
                    && nif.is_running()
                    && !nif.is_loopback()
                    && nif.name.to_lowercase().contains(&interface_name)
                // && nif.name.to_lowercase().contains("utun3")
            })
            .ok_or("interface not found")?)
    }

    fn find_interface_or_get_default(
        interface_name: String,
    ) -> AppResult<pnet_datalink::NetworkInterface> {
        let interfaces = pnet_datalink::interfaces();

        let nif = if let Ok(c_nif) = Self::find_interface(interface_name) {
            c_nif
        } else {
            interfaces
                .into_iter()
                .rev()
                .find(|nif| nif.is_up() && nif.is_running() && !nif.is_loopback())
                .ok_or("interface not found")?
        };
        Ok(nif)
    }

    fn send_arp_request(
        tx: &mut Box<dyn DataLinkSender>,
        interface: &NetworkInterface,
        target_ip: Ipv4Addr,
    ) {
        let mut ethernet_buffer = vec![0u8; 42];
        let mut ethernet_packet =
            MutableEthernetPacket::new(&mut ethernet_buffer).unwrap_or_else(|| {
                // eprintln!("Could not build Ethernet packet");
                process::exit(1);
            });

        let target_mac_broadcast = MacAddr::broadcast();
        let source_mac = interface.mac.unwrap_or_else(|| {
            // eprintln!("Interface should have a MAC address");
            process::exit(1);
        });

        ethernet_packet.set_destination(target_mac_broadcast);
        ethernet_packet.set_source(source_mac);

        let selected_ethertype = EtherTypes::Arp;
        ethernet_packet.set_ethertype(selected_ethertype);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap_or_else(|| {
            // eprintln!("Could not build ARP packet");
            process::exit(1);
        });

        let source_ip = Self::find_source_ip(interface);

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

        tx.send_to(
            ethernet_packet.to_immutable().packet(),
            Some(interface.clone()),
        );
    }

    fn find_source_ip(network_interface: &NetworkInterface) -> Ipv4Addr {
        let potential_network = network_interface
            .ips
            .iter()
            .find(|network| network.is_ipv4());
        match potential_network.map(|network| network.ip()) {
            Some(IpAddr::V4(ipv4_addr)) => ipv4_addr,
            _ => {
                // eprintln!("Expected IPv4 address on network interface");
                process::exit(1);
            }
        }
    }

    pub fn send_arp_packets(&self) {
        self.scanner_input_tx
            .send(ScannerInputEvent::StartScanning)
            .unwrap();
    }

    fn get_host_infos(buffer: &[u8], def_nif: &NetworkInterface) -> Option<Host> {
        let arp_packet = ArpPacket::new(&buffer[MutableEthernetPacket::minimum_packet_size()..]);
        if let Some(arp) = arp_packet {
            let sender_ipv4 = arp.get_sender_proto_addr();
            let sender_mac = arp.get_sender_hw_addr();

            let host = Host {
                hostname: None,
                time: chrono::Local::now(),
                mac: sender_mac,
                ipv4: sender_ipv4,
                is_my_device_mac: sender_mac == def_nif.mac.unwrap_or_default(),
                speed: None,
            };
            Some(host)
        } else {
            None
        }
    }

    fn get_stats(
        ethernet_packet: EthernetPacket,
        def_nif: &NetworkInterface,
    ) -> Option<stats_aggregator::StatItem> {
        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
        let src_ip = ipv4_packet.get_source();
        let dst_ip = ipv4_packet.get_destination();
        let next_level_protocol = ipv4_packet.get_next_level_protocol();
        let ips: Vec<IpAddr> = def_nif
            .ips
            .iter()
            .filter(|ipn| ipn.is_ipv4())
            .flatten()
            .collect();

        let direction = match (
            ips.contains(&IpAddr::from(src_ip)),
            ips.contains(&IpAddr::from(dst_ip)),
        ) {
            (true, true) => stats_aggregator::Direction::Local,
            (true, false) => stats_aggregator::Direction::Outgoing,
            (false, true) => stats_aggregator::Direction::Incomming,
            (false, false) => stats_aggregator::Direction::None,
        };

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
                        size: 8 * message.payload().len() as u128,
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
                        size: 8 * datagram.payload().len() as u128,
                    },
                })
            }
            _ => None,
        };

        stat
    }
}
