//! Resource cleanup operations.
//!
//! This module contains methods for cleaning up hosts and rebuilding indexes.

use chrono::{DateTime, Local};
use std::net::Ipv4Addr;

use crate::tui_mod::app::state::App;

impl App {
    pub(crate) fn clean_host_and_olders(&mut self) -> Option<()> {
        let (time, removed_ips) = self.collect_hosts_to_remove()?;
        self.remove_hosts_and_rebuild_indexes(time, removed_ips)
    }

    /// Collect the timestamp and IPs of hosts to be removed.
    ///
    /// Returns None if no host is selected.
    pub(crate) fn collect_hosts_to_remove(&self) -> Option<(DateTime<Local>, Vec<Ipv4Addr>)> {
        let selected_host = self.hosts.get(self.table_state.selected()?)?;
        let time = selected_host.time;

        // Collect IPs of hosts that will be removed
        let removed_ips: Vec<Ipv4Addr> = self
            .hosts
            .iter()
            .filter(|host| host.time <= time)
            .map(|host| host.ipv4)
            .collect();

        Some((time, removed_ips))
    }

    /// Remove hosts from the collection and rebuild all indexes.
    pub(crate) fn remove_hosts_and_rebuild_indexes(
        &mut self,
        time: DateTime<Local>,
        removed_ips: Vec<Ipv4Addr>,
    ) -> Option<()> {
        self.hosts.retain(|host| host.time > time);
        self.rebuild_indexes();
        self.cleanup_tracking_data(&removed_ips);
        Some(())
    }

    /// Rebuild the IP and MAC indexes after hosts list changes.
    pub(crate) fn rebuild_indexes(&mut self) {
        self.host_index_by_ip = self
            .hosts
            .iter()
            .enumerate()
            .map(|(i, host)| (host.ipv4, i))
            .collect();
        self.host_index_by_mac = self
            .hosts
            .iter()
            .enumerate()
            .map(|(i, host)| (host.mac, i))
            .collect();
    }

    /// Clean up tracking data for removed hosts.
    pub(crate) fn cleanup_tracking_data(&mut self, removed_ips: &[Ipv4Addr]) {
        // Remove MAC change tracking for cleaned hosts
        for ip in removed_ips {
            self.mac_changed_hosts.remove(ip);
        }

        // Remove hosts from scanner's discovered set so they can be re-discovered
        self.scanner.remove_discovered_hosts(removed_ips);
    }
}
