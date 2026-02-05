use std::{net::Ipv4Addr, time::Duration};

use crossterm::event::{Event as CrosstermEvent, KeyEvent, MouseEvent};
use futures::{FutureExt, StreamExt};
use tokio::sync::mpsc;

use crate::{
    error::{AppResult, NetuiError},
    host::Host,
    stats::StatsMap,
    types::MacAddr,
};

/// Terminal events.
#[derive(Clone, Debug)]
pub enum Event {
    /// Terminal tick.
    Tick,
    /// Key press.
    Key(KeyEvent),
    /// Mouse click/scroll.
    Mouse(MouseEvent),
    /// Terminal resize.
    Resize(u16, u16),

    Scanner(ScannerEvent),
}

#[derive(Clone, Debug)]
pub enum ScannerEvent {
    HostFound(Host),
    StatTick(StatsMap),
    InterfaceName(String),
    BeginScan,
    Complete,
    HostnameFound(Ipv4Addr, String),
    /// Security alert for MAC address change detection
    MacChanged(Ipv4Addr, MacAddr, MacAddr),
}

/// Security alert for tracking potential security issues.
/// These are generated in the scanner and forwarded to the UI.
#[derive(Clone, Debug)]
pub struct SecurityAlert {
    /// Type of security alert
    pub alert_type: SecurityAlertType,
    /// IP address associated with the alert
    pub ipv4: Ipv4Addr,
    /// When the alert was generated
    pub timestamp: chrono::DateTime<chrono::Local>,
}

/// Types of security alerts that can be generated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityAlertType {
    /// MAC address changed for the same IP (potential ARP spoofing)
    MacChanged {
        /// Previous MAC address
        old_mac: MacAddr,
        /// New MAC address
        new_mac: MacAddr,
    },
}

/// Terminal event handler.
#[allow(dead_code)]
#[derive(Debug)]
pub struct EventHandler {
    /// Event sender channel.
    sender: mpsc::Sender<Event>,
    /// Event receiver channel.
    receiver: mpsc::Receiver<Event>,
    /// Event handler thread.
    handler: tokio::task::JoinHandle<()>,
}

/// this acts as a hub of events
impl EventHandler {
    /// Constructs a new instance of [`EventHandler`].
    pub fn new(tick_rate: u64) -> Self {
        let tick_rate = Duration::from_millis(tick_rate);
        // Bounded channel with capacity 1000 to prevent DoS via OOM during event floods
        const EVENT_CHANNEL_CAPACITY: usize = 1000;
        let (sender, receiver) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let sender_clone = sender.clone();
        let handler = tokio::spawn(async move {
            let mut reader = crossterm::event::EventStream::new();
            let mut tick = tokio::time::interval(tick_rate);
            loop {
                let tick_delay = tick.tick();
                let crossterm_event = reader.next().fuse();
                tokio::select! {
                  _ = sender_clone.closed() => {
                    break;
                  }
                  _ = tick_delay => {
                    if let Err(e) = sender_clone.send(Event::Tick).await {
                      tracing::error!("Failed to send Tick event: {}", e);
                      break;
                    }
                  }
                  Some(Ok(evt)) = crossterm_event => {
                    match evt {
                      CrosstermEvent::Key(key) => {
                        if key.kind == crossterm::event::KeyEventKind::Press {
                          if let Err(e) = sender_clone.send(Event::Key(key)).await {
                            tracing::error!("Failed to send Key event: {}", e);
                            break;
                          }
                        }
                      },
                      CrosstermEvent::Mouse(mouse) => {
                        if let Err(e) = sender_clone.send(Event::Mouse(mouse)).await {
                          tracing::error!("Failed to send Mouse event: {}", e);
                          break;
                        }
                      },
                      CrosstermEvent::Resize(x, y) => {
                        if let Err(e) = sender_clone.send(Event::Resize(x, y)).await {
                          tracing::error!("Failed to send Resize event: {}", e);
                          break;
                        }
                      },
                      CrosstermEvent::FocusLost => {
                      },
                      CrosstermEvent::FocusGained => {
                      },
                      CrosstermEvent::Paste(_) => {
                      },
                    }
                  }
                };
            }
        });
        Self {
            sender,
            receiver,
            handler,
        }
    }

    /// Receive the next event from the handler thread.
    ///
    /// This function will always block the current thread if
    /// there is no data available and it's possible for more data to be sent.
    pub async fn next(&mut self) -> AppResult<Event> {
        self.receiver.recv().await.ok_or(NetuiError::ChannelClosed)
    }

    pub fn get_sender_clone(&self) -> mpsc::Sender<Event> {
        self.sender.clone()
    }
}
