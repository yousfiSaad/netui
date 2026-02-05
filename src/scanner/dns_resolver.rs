//! DNS resolution logic for hostname lookup.
//!
//! This module handles asynchronous DNS resolution for discovered hosts.

use crate::event::{Event, ScannerEvent};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

/// Spawn an async DNS lookup task for the given host IP.
///
/// This function spawns a background task that resolves the hostname
/// for the given IP address and sends the result via the event channel.
///
/// # Arguments
/// * `host_ipv4` - The IP address to resolve
/// * `scanner_outputs` - Channel for sending hostname resolution events
pub fn spawn_dns_lookup(host_ipv4: Ipv4Addr, scanner_outputs: mpsc::Sender<Event>) {
    tokio::spawn(async move {
        if let Some(hostname) = crate::resolver::resolve_hostname(host_ipv4).await {
            let _ = scanner_outputs.send(Event::Scanner(ScannerEvent::HostnameFound(
                host_ipv4, hostname,
            )));
        }
    });
}
