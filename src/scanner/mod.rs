//! Network scanner module for host discovery and packet capture.
//!
//! This module provides the main [`Scanner`] struct that coordinates
//! network scanning operations using a backend-agnostic architecture.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::{self, channel, Sender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::backend::{BackendConfig, BackendFactory, BackendType};
use crate::error::AppResult;
use crate::event::Event;
use crate::event::ScannerEvent;
use crate::interface_utils;
use crate::utils::recover_or_log;

#[cfg(feature = "ebpf-backend")]
use crate::backend::EbpfBackendFactory;
use crate::backend::PnetBackendFactory;

// Private sub-modules
mod arp_scanner;
pub mod arp_validator;
mod dns_resolver;
mod gateway;
// Public for benchmarking
pub mod packet_processor;
pub mod tasks;

// Enum for scanner input events (public for use in tasks)
pub enum ScannerInputEvent {
    StartScanning,
}

/// Main network scanner struct.
///
/// The scanner coordinates network discovery and monitoring operations
/// including ARP scanning, packet capture, and host detection.
pub struct Scanner {
    scanner_input_tx: Sender<ScannerInputEvent>,
    scanner_outputs: Sender<Event>,
    interface_name: String,
    cancel_token: CancellationToken,
    task_handles: Vec<JoinHandle<()>>,
    local_ips: HashSet<Ipv4Addr>,
    discovered_hosts: Arc<Mutex<HashSet<Ipv4Addr>>>,
    /// ARP validator for rejecting unsolicited ARP replies
    arp_validator: Arc<Mutex<arp_validator::ArpValidator>>,
    /// Default gateway IP for Internet traffic detection
    gateway_ip: Option<Ipv4Addr>,
}

impl Scanner {
    /// Creates a new [`Scanner`] with the specified configuration.
    ///
    /// # Arguments
    /// * `scanner_outputs` - Channel for sending scanner events
    /// * `interface_name` - Name of the network interface to use
    /// * `backend_type` - Type of backend to use (pnet or eBPF)
    ///
    /// # Returns
    /// A new Scanner instance, or an error if initialization fails
    pub fn new(
        scanner_outputs: mpsc::Sender<Event>,
        interface_name: String,
        backend_type: BackendType,
    ) -> AppResult<Self> {
        let backend_factory: Box<dyn BackendFactory> = match backend_type {
            BackendType::Pnet => Box::new(PnetBackendFactory),
            #[cfg(feature = "ebpf-backend")]
            BackendType::Ebpf => Box::new(EbpfBackendFactory),
            #[cfg(not(feature = "ebpf-backend"))]
            BackendType::Ebpf => {
                return Err("eBPF backend not compiled in. Enable 'ebpf-backend' feature.".into())
            }
        };
        let backend_config = BackendConfig::new(interface_name.clone());
        let (packet_source, packet_sink) = backend_factory
            .create(backend_config)
            .map_err(|e| format!("Failed to create backend: {}", e))?;

        if let Err(e) = scanner_outputs.try_send(Event::Scanner(
            crate::event::ScannerEvent::InterfaceName(interface_name.clone()),
        )) {
            return Err(format!("Failed to send interface name event: {}", e).into());
        }

        const SCANNER_INPUT_CAPACITY: usize = 100;
        let (scanner_input_tx, scanner_input_rx) =
            channel::<ScannerInputEvent>(SCANNER_INPUT_CAPACITY);
        let cancel_token = CancellationToken::new();

        // Get local IPs and MAC from the interface for direction detection
        let local_ips: HashSet<Ipv4Addr> = pnet_datalink::interfaces()
            .iter()
            .filter(|nif| {
                interface_utils::is_interface_active(nif)
                    && interface_utils::interface_matches(nif, &interface_name)
            })
            .flat_map(interface_utils::get_interface_ipv4_addrs)
            .collect();

        let mut scanner = Self {
            scanner_outputs,
            scanner_input_tx,
            interface_name,
            cancel_token,
            task_handles: Vec::new(),
            local_ips,
            discovered_hosts: Arc::new(Mutex::new(HashSet::new())),
            // Create ARP validator with a 15-second timeout
            // This accommodates full ARP scans on /24 networks (~9.5s for 256 hosts)
            // while still protecting against delayed unsolicited ARP replies
            arp_validator: Arc::new(Mutex::new(arp_validator::ArpValidator::new(
                Duration::from_secs(15),
            ))),
            // Detect default gateway for Internet traffic identification
            gateway_ip: gateway::detect_default_gateway(),
        };

        // Log detected gateway (if any)
        if let Some(gw) = scanner.gateway_ip {
            tracing::info!("Detected default gateway: {}", gw);
        } else {
            tracing::info!("No default gateway detected (may be expected in some environments)");
        }

        // Add local device to hosts list immediately
        // This ensures that local machine appears in the "Devices" tab
        for local_ip in &scanner.local_ips {
            let local_host = crate::host::Host {
                ipv4: *local_ip,
                mac: crate::types::MacAddr::default(),
                hostname: None,
                time: chrono::Local::now(),
                speed: None,
            };
            if let Err(e) = scanner
                .scanner_outputs
                .try_send(Event::Scanner(ScannerEvent::HostFound(local_host)))
            {
                tracing::warn!(
                    "Failed to send HostFound event for local IP {}: {}",
                    local_ip,
                    e
                );
            }
        }

        // Start background tasks
        let listener_handles = tasks::start_listening(
            packet_source,
            scanner.scanner_outputs.clone(),
            scanner.local_ips.clone(),
            scanner.discovered_hosts.clone(),
            Arc::clone(&scanner.arp_validator),
            scanner.gateway_ip,
            scanner.cancel_token.clone(),
        );
        scanner.task_handles.extend(listener_handles);

        let tx_handle = tasks::start_tx_worker(
            scanner_input_rx,
            packet_sink,
            scanner.interface_name.clone(),
            scanner.scanner_outputs.clone(),
            Arc::clone(&scanner.arp_validator),
            scanner.cancel_token.clone(),
        );
        scanner.task_handles.push(tx_handle);

        Ok(scanner)
    }

    /// Send ARP packets to discover hosts on the network.
    ///
    /// This triggers an ARP scan of the network range(s) configured
    /// on the selected interface.
    pub fn send_arp_packets(&self) {
        if let Err(e) = self
            .scanner_input_tx
            .try_send(ScannerInputEvent::StartScanning)
        {
            tracing::error!("Failed to send StartScanning event: {}", e);
        }
    }

    /// Get the detected default gateway IP address.
    ///
    /// Returns None if no gateway was detected or if detection failed.
    pub fn gateway_ip(&self) -> Option<Ipv4Addr> {
        self.gateway_ip
    }

    /// Get the set of detected local IP addresses.
    ///
    /// Returns the set of IPs on the local interfaces that were detected during startup.
    pub fn local_ips(&self) -> &HashSet<Ipv4Addr> {
        &self.local_ips
    }

    /// Remove hosts from the discovered set, allowing them to be re-discovered.
    ///
    /// This should be called when hosts are cleared/deleted from the UI.
    ///
    /// # Arguments
    /// * `ips` - Slice of IP addresses to remove from the discovered set
    pub fn remove_discovered_hosts(&self, ips: &[Ipv4Addr]) {
        let mut discovered =
            recover_or_log(self.discovered_hosts.lock(), "remove_discovered_hosts");
        for ip in ips {
            discovered.remove(ip);
        }
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
