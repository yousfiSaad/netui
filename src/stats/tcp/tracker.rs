//! TCP state tracker implementation.
//!
//! This module provides the TcpStateTracker for tracking TCP connection
//! states across multiple connections.

use crate::stats::tcp::TcpState;
use crate::stats::{IpPair, Speed};
use std::collections::HashMap;

/// TCP state tracker for multiple connections.
///
/// Tracks the state of each IP pair connection based on observed TCP flags.
pub struct TcpStateTracker {
    /// Map from IP pair to current TCP state
    pub(crate) states: HashMap<IpPair, TcpState>,
    /// Map from IP pair to last update time (for state timeout)
    last_update: HashMap<IpPair, std::time::Instant>,
    /// Map from IP pair to first seen time (for connection age tracking)
    first_seen: HashMap<IpPair, std::time::Instant>,
    /// State timeout duration (default 5 minutes)
    timeout: std::time::Duration,
}

impl Default for TcpStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpStateTracker {
    /// Create a new TCP state tracker.
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            last_update: HashMap::new(),
            first_seen: HashMap::new(),
            timeout: std::time::Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a new TCP state tracker with a custom timeout.
    pub fn with_timeout(timeout: std::time::Duration) -> Self {
        Self {
            states: HashMap::new(),
            last_update: HashMap::new(),
            first_seen: HashMap::new(),
            timeout,
        }
    }

    /// Update the TCP state for a connection based on observed TCP flags.
    ///
    /// # Arguments
    /// * `pair` - The IP pair identifying the connection
    /// * `syn` - TCP SYN flag
    /// * `ack` - TCP ACK flag
    /// * `fin` - TCP FIN flag
    /// * `rst` - TCP RST flag
    pub fn update(&mut self, pair: IpPair, syn: bool, ack: bool, fin: bool, rst: bool) {
        let current_state = self.states.get(&pair).copied().unwrap_or(TcpState::Closed);
        let new_state = current_state.transition(syn, ack, fin, rst);

        let now = std::time::Instant::now();

        // Track first seen time for connection age (use entry API for efficiency)
        self.first_seen.entry(pair).or_insert(now);

        self.states.insert(pair, new_state);
        self.last_update.insert(pair, now);
    }

    /// Get the current TCP state for a connection.
    pub fn get(&self, pair: &IpPair) -> Option<TcpState> {
        self.states.get(pair).copied()
    }

    /// Get all connections with their states and associated speeds.
    ///
    /// Returns a vector of (IpPair, TcpState, Speed) tuples.
    pub fn connections_with_state(
        &self,
        speeds: &HashMap<IpPair, Speed>,
    ) -> Vec<(IpPair, TcpState, Speed)> {
        self.states
            .iter()
            .filter_map(|(pair, state)| speeds.get(pair).map(|speed| (*pair, *state, *speed)))
            .collect()
    }

    /// Get the age of a connection as a Duration.
    ///
    /// Returns None if the connection is not being tracked.
    pub fn connection_age(&self, pair: &IpPair) -> Option<std::time::Duration> {
        self.first_seen
            .get(pair)
            .map(|first| std::time::Instant::now().duration_since(*first))
    }

    /// Prune stale connections that haven't been updated within the timeout period.
    pub fn prune_stale(&mut self) {
        let now = std::time::Instant::now();
        let to_remove: Vec<IpPair> = self
            .last_update
            .iter()
            .filter(|(_, last)| now.duration_since(**last) > self.timeout)
            .map(|(pair, _)| *pair)
            .collect();

        for pair in to_remove {
            self.states.remove(&pair);
            self.last_update.remove(&pair);
            self.first_seen.remove(&pair);
        }
    }

    /// Get the number of tracked connections.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Check if no connections are being tracked.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip_pair(a: u8, b: u8) -> IpPair {
        IpPair {
            src_ip: Ipv4Addr::new(192, 168, a, a),
            dst_ip: Ipv4Addr::new(192, 168, b, b),
            is_local: false,
            protocol: 6,
        }
    }

    #[test]
    fn test_tracker_update() {
        let mut tracker = TcpStateTracker::new();
        let pair = ip_pair(1, 2);

        tracker.update(pair, true, false, false, false);
        assert_eq!(tracker.get(&pair), Some(TcpState::SynSent));

        tracker.update(pair, false, true, false, false);
        assert_eq!(tracker.get(&pair), Some(TcpState::Established));
    }

    #[test]
    fn test_tracker_prune_stale() {
        let mut tracker = TcpStateTracker::with_timeout(std::time::Duration::from_millis(100));
        let pair = ip_pair(1, 2);

        tracker.update(pair, true, false, false, false);
        assert_eq!(tracker.len(), 1);

        std::thread::sleep(std::time::Duration::from_millis(150));
        tracker.prune_stale();
        assert_eq!(tracker.len(), 0);
    }
}
