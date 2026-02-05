//! Host management operations.
//!
//! This module contains all CRUD operations for hosts, including
//! adding, updating, and removing hosts with proper index management.

use std::net::Ipv4Addr;

use crate::tui_mod::app::events::SpeedDisplayMode;
use crate::tui_mod::app::state::App;
use netui::{error::AppResult, event::SecurityAlertType, host::Host, types::MacAddr};

impl App {
    /// Handle a newly discovered or updated host.
    pub fn handle_host_found(&mut self, host: Host) -> AppResult<()> {
        let ipv4 = host.ipv4;
        let mac = host.mac;

        // Dual-index lookup: First check MAC (for device re-identification), then IP
        if let Some(&existing_index) = self.host_index_by_mac.get(&mac) {
            self.update_host_by_mac(host, existing_index, ipv4);
        } else if let Some(&index) = self.host_index_by_ip.get(&ipv4) {
            self.update_host_by_ip(host, ipv4, mac, index);
        } else {
            self.add_new_host(host, ipv4, mac);
        }
        Ok(())
    }

    /// Update an existing host when found by MAC address.
    fn update_host_by_mac(&mut self, host: Host, existing_index: usize, ipv4: Ipv4Addr) {
        let existing_host = &self.hosts[existing_index];

        // Device with this MAC already exists - check if IP changed
        if existing_host.ipv4 != ipv4 {
            // Device got a new IP via DHCP - update existing entry
            tracing::info!(
                "Device {} changed IP: {} -> {}",
                host.mac,
                existing_host.ipv4,
                ipv4
            );

            // Remove old IP mapping
            self.host_index_by_ip.remove(&existing_host.ipv4);

            // Update with new IP and preserve existing data
            // Note: speed is NOT preserved here - StatTick events handle speed updates
            let mut updated_host = host;
            updated_host.hostname = existing_host.hostname.clone();
            self.hosts[existing_index] = updated_host;

            // Add new IP mapping
            self.host_index_by_ip.insert(ipv4, existing_index);
        } else {
            // Same IP and MAC - just update timestamp and preserve hostname
            // Note: speed is NOT preserved here - StatTick events handle speed updates
            let mut updated_host = host;
            updated_host.hostname = existing_host.hostname.clone();
            self.hosts[existing_index] = updated_host;
        }
    }

    /// Update an existing host when found by IP but MAC differs (security concern).
    fn update_host_by_ip(&mut self, host: Host, ipv4: Ipv4Addr, mac: MacAddr, index: usize) {
        let existing_host = &self.hosts[index];
        let old_mac = existing_host.mac; // Copy to avoid borrow issues

        tracing::warn!(
            "MAC change detected for IP {}: {} -> {}",
            ipv4,
            old_mac,
            mac
        );

        // Track this IP as having a MAC change
        self.mac_changed_hosts.insert(ipv4);

        // Create and store security alert
        self.add_security_alert(
            ipv4,
            SecurityAlertType::MacChanged {
                old_mac,
                new_mac: mac,
            },
        );

        // Remove old MAC mapping
        self.host_index_by_mac.remove(&old_mac);

        // Update host and add new MAC mapping
        // Note: speed is NOT preserved here - StatTick events handle speed updates
        self.hosts[index] = host;
        self.host_index_by_mac.insert(mac, index);
    }

    /// Add a completely new host (neither IP nor MAC seen before).
    fn add_new_host(&mut self, host: Host, ipv4: Ipv4Addr, mac: MacAddr) {
        let index = self.hosts.len();
        self.host_index_by_ip.insert(ipv4, index);
        self.host_index_by_mac.insert(mac, index);
        self.hosts.push(host);
        self.scroll_state = self
            .scroll_state
            .content_length((self.hosts.len().saturating_sub(1)) * 4);
    }

    /// Handle periodic statistics updates.
    pub fn handle_stat_tick(&mut self, hash_map: netui::stats::StatsMap) -> AppResult<()> {
        self.stats_aggregator.tick(hash_map);

        let speeds = match self.speed_mode {
            #[allow(deprecated)]
            SpeedDisplayMode::Average => self.stats_aggregator.speed_per_host(),
            SpeedDisplayMode::Instant => self.stats_aggregator.speed_per_host_instant(),
            SpeedDisplayMode::Peak => self.stats_aggregator.speed_per_host_peak(),
        };

        self.hosts.iter_mut().for_each(|host| {
            if let Some(speed) = speeds.get(&host.ipv4) {
                host.speed = Some(*speed);
            } else {
                // For instant mode, we might want to clear speed if no traffic this tick
                if self.speed_mode == SpeedDisplayMode::Instant {
                    host.speed = None;
                }
            }
        });
        Ok(())
    }

    /// Handle hostname discovery for a host.
    pub fn handle_hostname_found(&mut self, ipv4: Ipv4Addr, hostname: String) -> AppResult<()> {
        if let Some(&index) = self.host_index_by_ip.get(&ipv4) {
            self.hosts[index].hostname = Some(hostname);
        }
        Ok(())
    }

    /// Called when a scan completes to track new hosts.
    /// Compares current hosts with previous scan to identify newly discovered hosts.
    pub fn on_scan_complete(&mut self) {
        let current_hosts: std::collections::HashSet<Ipv4Addr> =
            self.hosts.iter().map(|host| host.ipv4).collect();

        // Find new hosts (in current but not in previous)
        self.new_hosts = current_hosts
            .difference(&self.previous_hosts)
            .copied()
            .collect();

        // Update previous for next scan
        self.previous_hosts = current_hosts;
    }
}
