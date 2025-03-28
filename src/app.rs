use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{error, net::Ipv4Addr};

use crate::{
    event::ScannerEvent,
    stats_aggregator::{Speed, StatsAggregator},
};

use pnet::util::MacAddr;
use ratatui::widgets::{ScrollbarState, TableState};

use crate::scanner::Scanner;

/// Application result type.
pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

/// Application.
pub struct App {
    /// Is the application running?
    pub running: bool,
    pub sending_arps: bool,
    /// hosts
    pub hosts: Vec<Host>,
    pub table_state: TableState,
    pub scroll_state: ScrollbarState,
    pub interface: String,

    scanner: Scanner,

    pub stats_aggregator: StatsAggregator,
}

#[derive(Clone, Debug)]
pub struct Host {
    pub time: chrono::DateTime<chrono::Local>,
    pub ipv4: Ipv4Addr,
    pub mac: MacAddr,
    pub hostname: Option<String>,
    pub is_my_device_mac: bool,
    pub speed: Option<Speed>,
}

impl PartialEq for Host {
    fn eq(&self, other: &Self) -> bool {
        self.ipv4 == other.ipv4 && self.mac == other.mac
    }
}

const ITEM_HEIGHT: usize = 4;
impl App {
    /// Constructs a new instance of [`App`].
    pub fn new(scanner: Scanner) -> AppResult<Self> {
        Ok(Self {
            running: true,
            sending_arps: false,
            hosts: vec![],
            interface: "".to_string(),
            table_state: TableState::default(),
            scanner,
            scroll_state: ScrollbarState::new(0),
            stats_aggregator: Default::default(),
        })
    }

    /// Handles the tick event of the terminal.
    pub fn tick(&self) {}

    /// Set running to false to quit the application.
    pub fn quit(&mut self) {
        self.running = false;
    }

    pub fn next_row(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i + 1 >= self.hosts.len() {
                    None
                } else {
                    Some(i + 1)
                }
            }
            None => Some(0),
        };
        self.table_state.select(i);
        self.scroll_state = self
            .scroll_state
            .position(i.unwrap_or(self.hosts.len().saturating_sub(1)) * ITEM_HEIGHT);
    }

    pub fn previous_row(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    None
                } else {
                    Some(i - 1)
                }
            }
            None => Some(self.hosts.len().saturating_sub(1)),
        };
        self.table_state.select(i);
        self.scroll_state = self.scroll_state.position(i.unwrap_or(0) * ITEM_HEIGHT);
    }

    pub fn next_column(&mut self) {
        if let Some(selected) = self.table_state.selected_column() {
            if selected == 2 {
                self.table_state.select_column(None);
                return;
            }
        }
        self.table_state.select_next_column();
    }

    pub fn previous_column(&mut self) {
        if let Some(selected) = self.table_state.selected_column() {
            if selected == 0 {
                self.table_state.select_column(None);
                return;
            }
        }
        self.table_state.select_previous_column();
    }
    pub fn handle_worker_events(&mut self, worker_event: ScannerEvent) -> AppResult<()> {
        match worker_event {
            ScannerEvent::HostFound(mut host) => {
                if let Some(h) = self.hosts.iter_mut().find(|h| h == &&host) {
                    host.speed = h.speed;
                    *h = host;
                } else {
                    self.hosts.push(host);
                    self.scroll_state = self
                        .scroll_state
                        .content_length((self.hosts.len().saturating_sub(1)) * ITEM_HEIGHT);
                }
            }
            ScannerEvent::Complete => {
                self.sending_arps = false;
            }
            ScannerEvent::BeginScan => {
                self.sending_arps = true;
            }
            ScannerEvent::InterfaceName(interface_name) => {
                self.interface = interface_name;
            }
            ScannerEvent::StatTick(hash_map) => {
                self.stats_aggregator.tick(hash_map);
                let speeds = self.stats_aggregator.speed_per_host();
                self.hosts.iter_mut().for_each(|h| {
                    if let Some(speed) = speeds.get(&h.ipv4) {
                        h.speed = Some(*speed);
                    }
                });
            }
        }
        Ok(())
    }

    pub fn handle_key_events(&mut self, key_event: KeyEvent) -> AppResult<()> {
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
                    self.clean_host_and_olders();
                }
            }
            // Counter handlers
            KeyCode::Char('j') => {
                self.next_row();
            }
            KeyCode::Char('k') => {
                self.previous_row();
            }
            KeyCode::Char('l') => {
                self.next_column();
            }
            KeyCode::Char('h') => {
                self.previous_column();
            }
            KeyCode::Char('s') => {
                if !self.sending_arps {
                    self.scanner.send_arp_packets();
                }
            }
            // Other handlers you could add here.
            _ => {}
        }
        Ok(())
    }

    fn clean_host_and_olders(&mut self) -> Option<()> {
        let host = self.hosts.get(self.table_state.selected()?)?;
        let time = host.time;
        self.hosts = self
            .hosts
            .clone()
            .into_iter()
            .filter(|h| h.time > time)
            .collect();

        Some(())
    }
}
