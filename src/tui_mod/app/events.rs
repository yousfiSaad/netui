//! Event handling for the application.
//!
//! This module contains the ViewMode enum and event handling methods.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;

use crate::tui_mod::app::state::App;
use netui::constants::CONFIRMATION_TIMEOUT_SECS;
use netui::{error::AppResult, event::ScannerEvent};

/// View mode for toggling between different data displays.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ViewMode {
    /// Display hosts table
    Hosts,
    /// Display connections view
    Connections,
    /// Display applications by bandwidth
    Apps,
}

/// Mode for displaying network speeds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpeedDisplayMode {
    /// Average speed over the sliding window (default)
    Average,
    /// Instantaneous speed (last tick)
    Instant,
    /// Peak speed observed in the sliding window
    Peak,
}

impl std::fmt::Display for SpeedDisplayMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpeedDisplayMode::Average => write!(f, "Average"),
            SpeedDisplayMode::Instant => write!(f, "Instant"),
            SpeedDisplayMode::Peak => write!(f, "Peak"),
        }
    }
}

impl App {
    /// Handles the tick event of the terminal.
    pub fn tick(&mut self) {
        if let Some(timestamp) = self.pending_deletion {
            if timestamp.elapsed() > Duration::from_secs(CONFIRMATION_TIMEOUT_SECS) {
                self.pending_deletion = None;
                self.status_message = None;
            }
        }
    }

    /// Set running to false to quit the application.
    pub fn quit(&mut self) {
        self.running = false;
    }

    pub fn handle_worker_events(&mut self, worker_event: ScannerEvent) -> AppResult<()> {
        match worker_event {
            ScannerEvent::HostFound(host) => self.handle_host_found(host),
            ScannerEvent::Complete => {
                self.sending_arps = false;
                self.on_scan_complete();
                Ok(())
            }
            ScannerEvent::BeginScan => {
                self.sending_arps = true;
                Ok(())
            }
            ScannerEvent::InterfaceName(interface_name) => {
                self.interface = interface_name;
                Ok(())
            }
            ScannerEvent::StatTick(hash_map) => self.handle_stat_tick(hash_map),
            ScannerEvent::HostnameFound(ipv4, hostname) => {
                self.handle_hostname_found(ipv4, hostname)
            }
            ScannerEvent::MacChanged(ipv4, old_mac, new_mac) => {
                self.handle_mac_changed_event(ipv4, old_mac, new_mac)
            }
        }
    }

    pub fn handle_key_events(&mut self, key_event: KeyEvent) -> AppResult<()> {
        if self.help_visible {
            match key_event.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => {
                    self.help_visible = false;
                }
                _ => {}
            }
            return Ok(());
        }

        match key_event.code {
            // Exit application on `ESC` or `q`
            KeyCode::Esc | KeyCode::Char('q') => {
                self.quit();
            }
            // Exit application on `Ctrl-C`
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if key_event.modifiers == KeyModifiers::CONTROL {
                    self.quit();
                } else {
                    // Handle 'c' key with double-press confirmation
                    self.handle_cleanup_keypress();
                }
            }
            // Row navigation (Vim-style j/k + arrow keys)
            KeyCode::Char('j') | KeyCode::Down => {
                self.next_row();
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.previous_row();
            }
            // Jump to first/last row
            KeyCode::Home => {
                self.table_state.select(Some(0));
            }
            KeyCode::End => {
                let count = match self.view_mode {
                    ViewMode::Hosts => self.hosts.len(),
                    ViewMode::Connections => self.stats_aggregator.connections_with_details().len(),
                    ViewMode::Apps => self.stats_aggregator.apps_stats().len(),
                };
                self.table_state.select(Some(count.saturating_sub(1)));
            }
            // View cycling with lowercase l/h (replaces Tab/BackTab)
            KeyCode::Char('l') => {
                self.view_mode = match self.view_mode {
                    ViewMode::Hosts => ViewMode::Connections,
                    ViewMode::Connections => ViewMode::Apps,
                    ViewMode::Apps => ViewMode::Hosts,
                };
                self.table_state.select(None);
            }
            KeyCode::Char('h') => {
                // Reverse cycle: Hosts → Apps → Connections → Hosts
                self.view_mode = match self.view_mode {
                    ViewMode::Hosts => ViewMode::Apps,
                    ViewMode::Connections => ViewMode::Hosts,
                    ViewMode::Apps => ViewMode::Connections,
                };
                self.table_state.select(None);
            }
            // Toggle speed display mode
            KeyCode::Char('t') => {
                self.speed_mode = match self.speed_mode {
                    SpeedDisplayMode::Average => SpeedDisplayMode::Instant,
                    SpeedDisplayMode::Instant => SpeedDisplayMode::Peak,
                    SpeedDisplayMode::Peak => SpeedDisplayMode::Average,
                };
            }
            KeyCode::Char('s') => {
                if !self.sending_arps {
                    self.scanner.send_arp_packets();
                }
            }
            // Toggle help screen
            KeyCode::Char('?') => {
                self.help_visible = !self.help_visible;
                // Clear status message when toggling help
                if self.help_visible {
                    self.status_message = None;
                    self.pending_deletion = None;
                }
            }
            // Other handlers you could add here.
            _ => {}
        }
        Ok(())
    }

    /// Handle 'c' keypress with double-press confirmation.
    fn handle_cleanup_keypress(&mut self) {
        // Only works in Hosts view
        if self.view_mode != ViewMode::Hosts {
            return;
        }

        // Check if there's a selected host
        let has_selection = self.table_state.selected().is_some();

        if !has_selection {
            return;
        }

        if let Some(timestamp) = self.pending_deletion {
            // Second 'c' press - confirm deletion (within timeout)
            if timestamp.elapsed() < Duration::from_secs(CONFIRMATION_TIMEOUT_SECS) {
                self.clean_host_and_olders();
                self.pending_deletion = None;
                self.status_message = Some("Hosts cleaned".to_string());
            } else {
                // Timeout expired, start new confirmation
                self.pending_deletion = Some(std::time::Instant::now());
                self.status_message = Some("Press 'c' again to confirm cleanup".to_string());
            }
        } else {
            // First 'c' press - start confirmation
            self.pending_deletion = Some(std::time::Instant::now());
            self.status_message = Some("Press 'c' again to confirm cleanup".to_string());
        }
    }
}
