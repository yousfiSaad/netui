//! ARP scanning logic for network discovery.
//!
//! This module handles ARP packet construction and sending for
//! active network host discovery.

use crate::error::AppResult;
use pnet::ipnetwork;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet_datalink::{MacAddr as PnetMacAddr, NetworkInterface};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::backend::PacketSink;
use crate::constants::{network, timing};
use crate::event::{Event, ScannerEvent};
use crate::scanner::arp_validator::ArpValidation;
use crate::types::MacAddr;

/// Sanitize an IPv4 address for logging by showing only the first 3 octets.
///
/// This prevents information disclosure in logs while preserving enough
/// context for security event analysis.
///
/// # Example
/// ```
/// use std::net::Ipv4Addr;
/// // Function is private, so we can't test it directly in doctests unless we expose it
/// // or mock the behavior. Since this is an internal utility, we'll document it but not
/// // run the test in a way that fails public API checks.
/// let _ = "192.168.1.x";
/// ```
fn sanitize_ip(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    format!("{}.{}.{}.x", octets[0], octets[1], octets[2])
}

/// Sanitize a MAC address for logging by showing only "xx:xx:xx:xx:xx:xx".
///
/// MAC addresses should never be logged in plaintext as they uniquely
/// identify hardware devices.
fn sanitize_mac(_mac: MacAddr) -> &'static str {
    "xx:xx:xx:xx:xx:xx"
}

/// Find a source IPv4 address for the given network interface.
///
/// # Arguments
/// * `network_interface` - The network interface to query
///
/// # Returns
/// The first IPv4 address found on the interface, or an error
pub fn find_source_ip(network_interface: &NetworkInterface) -> AppResult<Ipv4Addr> {
    let potential_network = network_interface
        .ips
        .iter()
        .find(|network| network.is_ipv4());
    match potential_network.map(|network| network.ip()) {
        Some(std::net::IpAddr::V4(ipv4_addr)) => Ok(ipv4_addr),
        Some(other) => Err(format!("Expected IPv4, found: {}", other).into()),
        None => Err("No IPv4 address found on interface".into()),
    }
}

/// Send an ARP request packet for a specific target IP.
///
/// # Arguments
/// * `packet_sink` - The packet sink for sending the ARP request
/// * `interface` - The network interface to send from
/// * `target_ip` - The target IP address to query
/// * `arp_validator` - Optional validator for tracking the request
///
/// # Returns
/// Ok(()) if the packet was sent successfully, or an error
pub fn send_arp_request(
    packet_sink: &mut Box<dyn PacketSink>,
    interface: &NetworkInterface,
    target_ip: Ipv4Addr,
    arp_validator: Option<&Arc<Mutex<crate::scanner::arp_validator::ArpValidator>>>,
) -> AppResult<()> {
    let mut ethernet_buffer = vec![0u8; network::ETHERNET_ARP_BUFFER_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
        .ok_or("Failed to create Ethernet packet from buffer")?;

    let target_mac_broadcast = PnetMacAddr::broadcast();
    let source_mac = interface.mac.ok_or("Interface missing MAC address")?;

    ethernet_packet.set_destination(target_mac_broadcast);
    ethernet_packet.set_source(source_mac);

    let selected_ethertype = EtherTypes::Arp;
    ethernet_packet.set_ethertype(selected_ethertype);

    let mut arp_buffer = [0u8; network::ARP_PACKET_SIZE];
    let mut arp_packet =
        MutableArpPacket::new(&mut arp_buffer).ok_or("Failed to create ARP packet from buffer")?;

    let source_ip = find_source_ip(interface)?;

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

    // Record the request before sending (if validator provided)
    if let Some(validator) = arp_validator {
        if let Ok(mut validator) = validator.try_lock() {
            validator.record_request(target_ip);
        }
    }

    packet_sink
        .send_packet(ethernet_packet.to_immutable().packet())
        .map_err(|e| format!("Failed to send ARP request: {}", e))?;
    Ok(())
}

/// Scan a range of IP addresses by sending ARP requests.
///
/// # Arguments
/// * `nif` - The network interface to use for scanning
/// * `ip_network` - The IP network range to scan
/// * `scanner_outputs` - Channel for sending scan events
/// * `packet_sink` - The packet sink for sending ARP requests
/// * `arp_validator` - Optional validator for tracking ARP requests
pub async fn scan_range(
    nif: &NetworkInterface,
    ip_network: ipnetwork::IpNetwork,
    scanner_outputs: mpsc::Sender<Event>,
    packet_sink: &mut Box<dyn PacketSink>,
    arp_validator: Option<&Arc<Mutex<crate::scanner::arp_validator::ArpValidator>>>,
) {
    use std::net::IpAddr;

    if let Err(e) = scanner_outputs
        .send(Event::Scanner(ScannerEvent::BeginScan))
        .await
    {
        tracing::error!("Failed to send BeginScan event: {}", e);
        return;
    }
    let sender_clone = scanner_outputs.clone();
    let sender = sender_clone;
    for ip_addr in ip_network.iter() {
        if let IpAddr::V4(ipv4_address) = ip_addr {
            sleep(Duration::from_millis(timing::ARP_SCAN_DELAY_MS)).await;
            let _ = send_arp_request(packet_sink, nif, ipv4_address, arp_validator);
        }
    }
    if let Err(e) = sender.send(Event::Scanner(ScannerEvent::Complete)).await {
        tracing::error!("Failed to send Complete event: {}", e);
    }
}

/// Extract host information from an ARP packet.
///
/// This function only processes ARP replies (not requests). If an arp_validator
/// is provided, it will validate that the reply corresponds to a request we sent.
/// Unsolicited replies are rejected as potential ARP poisoning attempts.
///
/// # Arguments
/// * `buffer` - The raw packet buffer starting at Ethernet frame
/// * `arp_validator` - Optional validator for checking ARP replies
///
/// # Returns
/// Some(Host) if the ARP packet is a valid reply with host information, None otherwise
pub fn get_host_infos(
    buffer: &[u8],
    arp_validator: Option<&Arc<Mutex<crate::scanner::arp_validator::ArpValidator>>>,
) -> Option<crate::host::Host> {
    use crate::types::MacAddr;
    use chrono::Local;
    use pnet::packet::arp::{ArpOperations, ArpPacket};
    use pnet::packet::ethernet::MutableEthernetPacket;

    let arp_packet = ArpPacket::new(&buffer[MutableEthernetPacket::minimum_packet_size()..]);
    if let Some(arp) = arp_packet {
        let operation = arp.get_operation();

        // Only process ARP replies (opcode 2), not requests (opcode 1)
        if operation != ArpOperations::Reply {
            return None;
        }

        let sender_ipv4 = arp.get_sender_proto_addr();
        let sender_mac_raw = arp.get_sender_hw_addr();
        let sender_mac: MacAddr = sender_mac_raw.into();

        // Validate the reply if a validator is provided
        if let Some(validator) = arp_validator {
            let validation = if let Ok(mut validator) = validator.try_lock() {
                validator.validate_reply(sender_ipv4)
            } else {
                // If we can't lock the validator, reject the packet for safety
                ArpValidation::Unsolicited
            };

            match validation {
                ArpValidation::Valid => {
                    // Reply is valid, proceed to process
                }
                ArpValidation::Unsolicited => {
                    tracing::warn!(
                        "Rejected unsolicited ARP reply for {} from {} (potential ARP poisoning)",
                        sanitize_ip(sender_ipv4),
                        sanitize_mac(sender_mac)
                    );
                    return None;
                }
                ArpValidation::Expired => {
                    tracing::debug!(
                        "Rejected expired ARP reply for {} from {}",
                        sanitize_ip(sender_ipv4),
                        sanitize_mac(sender_mac)
                    );
                    return None;
                }
            }
        }

        let host = crate::host::Host {
            hostname: None,
            time: Local::now(),
            mac: sender_mac,
            ipv4: sender_ipv4,
            speed: None,
        };
        Some(host)
    } else {
        None
    }
}
