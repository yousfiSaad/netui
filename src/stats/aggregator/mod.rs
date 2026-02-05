//! Main statistics aggregator orchestrator.
//!
//! This module contains the `StatsAggregator` struct which coordinates
//! the collection, aggregation, and querying of network statistics.
//! It delegates specialized operations to sub-modules (pairs, ports, etc.).

pub mod helpers;
mod query;
mod tick;

// Note: query module exports are available but not re-exported by default
// Consumers can use `netui::stats::aggregator::query::*` if needed

use std::{collections::HashMap, net::Ipv4Addr, time::Instant};

use crate::constants::{buffer, network_values::PROTOCOL_TCP};
use crate::stats::{
    update_pairs_stats_buffer, Direction, IpPair, PairStatMap, QualityTracker, SessionStats, Speed,
    StatKey, StatsMap, TcpStateTracker, TimedSpeed,
};
use ringbuf::traits::{Consumer, RingBuffer};
use ringbuf::HeapRb;

/// Main statistics aggregator.
///
/// The StatsAggregator collects and processes network statistics,
/// maintaining rolling buffers for various aggregation views.
pub struct StatsAggregator {
    /// Buffer for directional speed data [outgoing, incoming, local, other]
    speed_buffer: HeapRb<Vec<u128>>,
    /// Buffer for unique stat keys seen
    stat_keys_buffer: HeapRb<StatKey>,

    /// Buffer for raw statistics maps
    stats_buffer: HeapRb<StatsMap>,
    /// Buffer for IP pair aggregated statistics
    pairs_buffer: HeapRb<PairStatMap>,
    /// Buffer for per-host speed statistics
    hosts_buffer: HeapRb<HashMap<Ipv4Addr, Speed>>,
    /// Buffer for total speed across all hosts
    total_speed_buffer: HeapRb<TimedSpeed>,

    /// Track last tick time for rate calculation
    last_tick_time: Option<Instant>,
    /// Track elapsed time for the most recent tick
    last_elapsed_secs: f64,

    /// Cumulative session statistics
    pub session_stats: SessionStats,

    /// TCP connection state tracker
    tcp_state_tracker: TcpStateTracker,

    /// Connection quality metrics tracker
    quality_tracker: QualityTracker,

    /// Tracks ports and direction for each IP pair (for service identification)
    /// Maps IpPair -> (src_port, dst_port, direction)
    connection_ports: HashMap<IpPair, (u16, u16, Direction)>,
}

impl StatsAggregator {
    /// Create a new StatsAggregator with default buffer sizes.
    fn new() -> Self {
        Self::new_with_window_size(buffer::DEFAULT_STATS_WINDOW_SIZE)
    }

    /// Create a new StatsAggregator with a custom window size.
    fn new_with_window_size(window: usize) -> Self {
        Self {
            speed_buffer: HeapRb::new(window),
            stat_keys_buffer: HeapRb::new(buffer::DEFAULT_STATS_KEYS_BUFFER_SIZE),
            stats_buffer: HeapRb::new(window),
            pairs_buffer: HeapRb::new(window),
            hosts_buffer: HeapRb::new(window),
            total_speed_buffer: HeapRb::new(window),
            last_tick_time: None,
            last_elapsed_secs: 1.0,
            session_stats: Default::default(),
            tcp_state_tracker: TcpStateTracker::new(),
            quality_tracker: QualityTracker::new(),
            connection_ports: HashMap::new(),
        }
    }

    /// Update the pairs statistics buffer.
    fn update_pairs_stats_buffer(&mut self) {
        update_pairs_stats_buffer(
            &self.stats_buffer,
            &mut self.pairs_buffer,
            self.last_elapsed_secs,
        );
    }

    /// Update the hosts statistics buffer from pair statistics.
    fn update_hosts_stats_buffer(&mut self) {
        self.hosts_buffer.clear();
        self.pairs_buffer.iter().for_each(|pairs| {
            let mut hosts_pair: HashMap<Ipv4Addr, Speed> = Default::default();
            pairs
                .iter()
                .filter(|(pair, _)| !pair.is_local)
                .for_each(|(pair, timed_speed)| {
                    // For non-local pairs (incoming/outgoing), src_ip is the local device
                    // This is because IPs are swapped for incoming traffic
                    hosts_pair
                        .entry(pair.src_ip)
                        .and_modify(|sp| {
                            *sp += timed_speed.speed;
                        })
                        .or_insert(timed_speed.speed);
                });
            self.hosts_buffer.push_overwrite(hosts_pair);
        });
    }

    /// Update the total speed buffer from host statistics.
    fn update_total_speed(&mut self) {
        self.total_speed_buffer.clear();
        self.hosts_buffer.iter().for_each(|per_host| {
            let mut speed_sum: Speed = Default::default();
            per_host.iter().for_each(|(_adr, speed)| {
                speed_sum += *speed;
            });
            // Use the elapsed time from the most recent tick
            self.total_speed_buffer
                .push_overwrite(TimedSpeed::new(speed_sum, self.last_elapsed_secs));
        });
    }

    /// Update TCP connection states based on the latest statistics.
    fn update_tcp_states(&mut self) {
        // Prune stale connections first
        self.tcp_state_tracker.prune_stale();

        // Also prune stale port tracking
        let active_pairs: Vec<IpPair> = self.tcp_state_tracker.states.keys().copied().collect();
        let mut stale_ports = Vec::new();
        for pair in self.connection_ports.keys() {
            if !active_pairs.contains(pair) {
                stale_ports.push(*pair);
            }
        }
        for pair in stale_ports {
            self.connection_ports.remove(&pair);
        }

        // Update states based on the latest stats map
        if let Some(latest_stats) = self.stats_buffer.iter().last() {
            for (key, value) in latest_stats.iter() {
                // Only track TCP states (protocol 6)
                // We check the ports to determine if this is likely TCP
                // (TCP and UDP both have ports, but we only track TCP states)

                // Normalize IpPair to match the normalization logic in update_pairs_stats_buffer()
                // This is CRITICAL - both must use the same key construction or lookups will fail
                let (mut src, mut dst) = (key.src_ip, key.dst_ip);
                let is_local = key.direction == Direction::Local;

                // Normalize: for incoming, swap so remote is always "source"
                // For local traffic, ensure consistent ordering
                if Direction::Incoming == key.direction || (is_local && src > dst) {
                    (src, dst) = (dst, src);
                }

                let pair = IpPair {
                    src_ip: src,
                    dst_ip: dst,
                    is_local,
                    protocol: key.protocol,
                };

                // Track ports and direction for this connection (only store first seen)
                self.connection_ports.entry(pair).or_insert((
                    key.src_port,
                    key.dst_port,
                    key.direction,
                ));

                // Update the TCP state based on flags - ONLY for TCP protocol
                if key.protocol == PROTOCOL_TCP {
                    self.tcp_state_tracker.update(
                        pair,
                        key.tcp_syn,
                        key.tcp_ack,
                        key.tcp_fin,
                        key.tcp_rst,
                    );
                }

                // Update quality metrics if we have timestamp data
                if let Some(timestamp) = value.last_timestamp {
                    self.quality_tracker.update(
                        pair,
                        timestamp,
                        value.last_seq.unwrap_or(0),
                        value.last_ack.unwrap_or(0),
                    );
                }
            }
        }
    }

    /// Update connection quality metrics.
    ///
    /// This is called on each tick to update quality tracking.
    fn update_quality_metrics(&mut self) {
        self.quality_tracker.prune_stale();
    }
}

impl Default for StatsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::StatValues;

    // Helper macro for IP address creation in tests
    macro_rules! ip {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            std::net::Ipv4Addr::new($a, $b, $c, $d)
        };
    }

    #[test]
    fn test_aggregator_default() {
        let agg = StatsAggregator::default();
        // Should have empty buffers initially
        assert!(agg.speed_str().is_empty());
    }

    #[test]
    fn test_aggregator_tick_empty() {
        let mut agg = StatsAggregator::default();
        agg.tick(HashMap::new());
        // Should not panic
    }

    #[test]
    fn test_session_stats_tracking() {
        let mut agg = StatsAggregator::default();
        let mut stats = HashMap::new();

        // Add some outgoing traffic
        let key = StatKey {
            src_port: 12345,
            dst_port: 443,
            src_ip: ip!(192, 168, 1, 1),
            dst_ip: ip!(93, 184, 216, 34),
            direction: Direction::Outgoing,
            protocol: 6,
            tcp_syn: false,
            tcp_ack: false,
            tcp_fin: false,
            tcp_rst: false,
        };
        stats.insert(
            key,
            StatValues {
                size: 1000,
                last_timestamp: None,
                last_seq: None,
                last_ack: None,
            },
        );

        agg.tick(stats);

        // Session stats should be updated
        assert_eq!(agg.session_stats.total_bits_up, 1000);
        assert_eq!(agg.session_stats.total_bits_down, 0);
    }
}
