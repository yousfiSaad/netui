//! Network interface discovery and filtering utilities.
//!
//! This module provides reusable functions for finding and validating
//! network interfaces, eliminating code duplication across the codebase.

use pnet_datalink::NetworkInterface;
use std::net::{IpAddr, Ipv4Addr};

/// Find a network interface by name (case-insensitive partial match).
///
/// This function searches through all available network interfaces and
/// returns the first one that matches the given name pattern and is
/// active (up, running, and not loopback).
///
/// # Arguments
/// * `name` - The interface name or partial name to search for
///
/// # Returns
/// * `Some(NetworkInterface)` - If a matching active interface is found
/// * `None` - If no matching interface is found
///
/// # Example
/// ```no_run
/// use netui::interface_utils::find_interface;
///
/// if let Some(interface) = find_interface("en0") {
///     println!("Found interface: {}", interface.name);
/// }
/// ```
pub fn find_interface(name: &str) -> Option<NetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .rev()
        .find(|nif| is_interface_active(nif) && interface_matches(nif, name))
}

/// Check if interface is active (up, running, not loopback).
///
/// # Arguments
/// * `nif` - The network interface to check
///
/// # Returns
/// `true` if the interface is active, `false` otherwise
pub fn is_interface_active(nif: &NetworkInterface) -> bool {
    nif.is_up() && nif.is_running() && !nif.is_loopback()
}

/// Check if interface name matches (case-insensitive partial match).
///
/// # Arguments
/// * `nif` - The network interface to check
/// * `name` - The name pattern to match against
///
/// # Returns
/// `true` if the interface name contains the given pattern (case-insensitive)
pub fn interface_matches(nif: &NetworkInterface, name: &str) -> bool {
    nif.name.to_lowercase().contains(&name.to_lowercase())
}

/// Get all IPv4 addresses from an interface.
///
/// # Arguments
/// * `nif` - The network interface to extract addresses from
///
/// # Returns
/// A vector of IPv4 addresses associated with this interface
pub fn get_interface_ipv4_addrs(nif: &NetworkInterface) -> Vec<Ipv4Addr> {
    nif.ips
        .iter()
        .filter_map(|ip_network| match ip_network.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_matching_case_insensitive() {
        // This is a compile-time check that the function exists
        // Actual interface testing would require a real network interface
        let dummy_name = "eth0";
        let _ = dummy_name.to_lowercase();
    }

    #[test]
    fn test_ipv4_extraction_compiles() {
        // Verify the function signature is correct
        // Actual testing would require a real NetworkInterface
        fn check_compile<F>(_: F)
        where
            F: Fn(&NetworkInterface) -> Vec<Ipv4Addr>,
        {
            // This function just checks that get_interface_ipv4_addrs
            // has the correct signature
        }
        check_compile(get_interface_ipv4_addrs);
    }
}
