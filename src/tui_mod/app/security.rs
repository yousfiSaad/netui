//! Security alert handling.
//!
//! This module contains all security-related functionality, including
//! MAC change detection, alert management, and new device tracking.

use std::net::Ipv4Addr;

use crate::tui_mod::app::state::App;
use netui::{error::AppResult, event::SecurityAlertType, types::MacAddr};

impl App {
    /// Add a security alert to the alerts buffer, evicting oldest if at capacity.
    pub(crate) fn add_security_alert(&mut self, ipv4: Ipv4Addr, alert_type: SecurityAlertType) {
        use netui::constants::security;
        use netui::event::SecurityAlert;

        let alert = SecurityAlert {
            alert_type,
            ipv4,
            timestamp: chrono::Local::now(),
        };

        if self.security_alerts.len() >= security::MAX_ALERTS {
            self.security_alerts.pop_front();
        }
        self.security_alerts.push_back(alert);
    }

    /// Handle MAC change event forwarded from scanner.
    pub fn handle_mac_changed_event(
        &mut self,
        ipv4: Ipv4Addr,
        old_mac: MacAddr,
        new_mac: MacAddr,
    ) -> AppResult<()> {
        tracing::warn!(
            "MAC change event received for IP {}: {} -> {}",
            ipv4,
            old_mac,
            new_mac
        );
        self.mac_changed_hosts.insert(ipv4);

        self.add_security_alert(ipv4, SecurityAlertType::MacChanged { old_mac, new_mac });
        Ok(())
    }
}
