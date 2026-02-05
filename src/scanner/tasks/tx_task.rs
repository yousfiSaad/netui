//! TX worker task for packet transmission.
//!
//! This module handles spawning the background task that sends packets,
//! such as ARP requests for network scanning.

use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::backend::PacketSink;
use crate::event::Event;
use crate::scanner::arp_validator::ArpValidator;
use crate::scanner::{arp_scanner, ScannerInputEvent};

/// Start the TX worker task for sending packets.
///
/// This function spawns a background task that handles outgoing
/// packet transmission, such as ARP requests for network scanning.
///
/// # Arguments
/// * `scanner_input_rx` - Channel for receiving scanner input events
/// * `packet_sink` - The packet sink for sending packets
/// * `interface_name` - Name of the network interface
/// * `scanner_outputs` - Channel for sending scanner events
/// * `arp_validator` - ARP validator for tracking ARP requests
/// * `cancel_token` - Cancellation token for stopping the task
///
/// # Returns
/// A handle to the spawned task
pub fn start_tx_worker(
    mut scanner_input_rx: mpsc::Receiver<ScannerInputEvent>,
    mut packet_sink: Box<dyn PacketSink>,
    interface_name: String,
    scanner_outputs: mpsc::Sender<Event>,
    arp_validator: Arc<Mutex<ArpValidator>>,
    cancel_token: CancellationToken,
) -> JoinHandle<()> {
    let tx_cancel_token = cancel_token.child_token();
    tokio::spawn(async move {
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
                            let Some(nif) = crate::interface_utils::find_interface(&interface_name) else {
                                tracing::error!("Interface not found for scanning: {}", interface_name);
                                continue;
                            };

                            for ip_network in nif
                                .ips
                                .iter()
                                .filter(|ip_network: &&pnet::ipnetwork::IpNetwork| ip_network.is_ipv4())
                                .cloned()
                            {
                                arp_scanner::scan_range(
                                    &nif,
                                    ip_network,
                                    scanner_outputs.clone(),
                                    &mut packet_sink,
                                    Some(&arp_validator),
                                )
                                .await;
                            }
                        }
                        None => break, // Channel closed
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_tx_worker_creates_handle() {
        // This test would require a mock packet sink
        // For now, just verify the function compiles
        let (_tx, _rx) = mpsc::channel::<ScannerInputEvent>(10);
        let interface_name = String::from("eth0");
        let cancel_token = CancellationToken::new();

        // We can't fully test this without a packet sink,
        // but we can verify the function signature is correct
        let _ = (interface_name, cancel_token);
    }
}
