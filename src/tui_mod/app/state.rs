//! Application state management.
//!
//! This module contains the application state structure and constructor.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::Ipv4Addr,
    time::Instant,
};

use ratatui::widgets::{ScrollbarState, TableState};

use crate::tui_mod::app::events::{SpeedDisplayMode, ViewMode};
use netui::{event::SecurityAlert, scanner::Scanner, stats::StatsAggregator, types::MacAddr};

/// Application state.
pub struct App {
    /// Is not application running?
    pub running: bool,
    pub sending_arps: bool,
    /// hosts
    pub hosts: Vec<netui::host::Host>,
    /// Index for O(1) host lookup by IPv4 address
    pub host_index_by_ip: HashMap<Ipv4Addr, usize>,
    /// Index for O(1) host lookup by MAC address (for tracking devices across IP changes)
    pub host_index_by_mac: HashMap<MacAddr, usize>,
    /// Set of local IP addresses (for identifying "this device")
    pub local_ips: HashSet<Ipv4Addr>,
    pub table_state: TableState,
    pub scroll_state: ScrollbarState,
    pub interface: String,

    pub scanner: Scanner,

    pub stats_aggregator: StatsAggregator,

    /// Current view mode (Hosts table or Connections view)
    pub view_mode: ViewMode,

    /// Current speed display mode (Average, Current, Peak)
    pub speed_mode: SpeedDisplayMode,

    /// Track hosts from previous scan for new host detection
    pub previous_hosts: HashSet<Ipv4Addr>,
    /// Set of hosts discovered in the most recent scan
    pub new_hosts: HashSet<Ipv4Addr>,
    /// Track hosts with detected MAC changes (potential ARP spoofing)
    pub mac_changed_hosts: HashSet<Ipv4Addr>,
    /// Buffer of recent security alerts (max capacity)
    pub security_alerts: VecDeque<SecurityAlert>,

    /// Pending deletion confirmation (timestamp of first 'c' press)
    pub pending_deletion: Option<Instant>,
    /// Status message to display (e.g., "Press c again to confirm")
    pub status_message: Option<String>,
    /// Whether the help modal is visible
    pub help_visible: bool,
}

impl App {
    /// Constructs a new instance of [`App`].
    pub fn new(scanner: Scanner) -> netui::error::AppResult<Self> {
        use netui::constants::security;
        // Clone the local IPs set from scanner to identify "this device"
        let local_ips = scanner.local_ips().clone();
        Ok(Self {
            running: true,
            sending_arps: false,
            hosts: vec![],
            host_index_by_ip: HashMap::new(),
            host_index_by_mac: HashMap::new(),
            local_ips,
            interface: "".to_string(),
            table_state: TableState::default(),
            scanner,
            scroll_state: ScrollbarState::new(0),
            stats_aggregator: Default::default(),
            view_mode: ViewMode::Hosts,
            speed_mode: SpeedDisplayMode::Average,
            previous_hosts: HashSet::new(),
            new_hosts: HashSet::new(),
            mac_changed_hosts: HashSet::new(),
            security_alerts: VecDeque::with_capacity(security::MAX_ALERTS),
            pending_deletion: None,
            status_message: None,
            help_visible: false,
        })
    }
}
