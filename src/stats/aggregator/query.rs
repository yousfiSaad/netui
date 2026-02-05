//! Query methods for the statistics aggregator.
//!
//! This module provides methods for querying statistics from the aggregator,
//! including per-host speeds, application statistics, connection details, etc.

use ringbuf::traits::{Consumer, Observer};
use std::{collections::HashMap, net::Ipv4Addr};

use crate::stats::{
    aggregate_by_app, format_connections as pairs_format_connections,
    format_port_stats as ports_format_port_stats, top_ports_all as ports_top_ports_all,
    top_ports_per_host as ports_top_ports_per_host, AppRegistry, AppStats, ConnectionDetails,
    Direction, IpPair, PortStats, QualityMetrics, Speed, SpeedAccumulator, TcpState,
};

use super::{helpers, StatsAggregator};

impl StatsAggregator {
    /// Get speed statistics per host (average over window).
    ///
    /// Returns a map of IP addresses to their average speed over the window.
    ///
    /// # Note
    /// **DEPRECATED**: This method uses count-based averaging instead of time-weighted averaging.
    /// This can produce incorrect results when tick intervals vary.
    ///
    /// For accurate time-weighted per-host speeds, consider using `speed_per_host_instant()`
    /// for the latest tick or use the pairs buffer directly with time-weighted aggregation.
    #[deprecated(since = "0.2.0", note = "Use time-weighted averaging methods instead")]
    #[allow(deprecated)]
    pub fn speed_per_host(&self) -> HashMap<Ipv4Addr, Speed> {
        helpers::aggregate_sum_speed(self.hosts_buffer.iter())
    }

    /// Get instantaneous speed statistics per host (latest tick).
    pub fn speed_per_host_instant(&self) -> HashMap<Ipv4Addr, Speed> {
        self.hosts_buffer.iter().last().cloned().unwrap_or_default()
    }

    /// Get peak speed statistics per host (max over window).
    pub fn speed_per_host_peak(&self) -> HashMap<Ipv4Addr, Speed> {
        helpers::aggregate_peak_speed(self.hosts_buffer.iter())
    }

    /// Get the total speed as a formatted string.
    ///
    /// Returns the average total speed across the window, formatted as
    /// "↓ XX Mib/s | ↑ XX Mib/s"
    ///
    /// Uses time-weighted average for accuracy when tick intervals vary.
    pub fn speed_str(&self) -> String {
        if self.total_speed_buffer.is_empty() {
            return "".to_string();
        }

        // Calculate weighted average by duration
        let total_duration: f64 = self
            .total_speed_buffer
            .iter()
            .map(|ts| ts.duration_secs)
            .sum();

        if total_duration == 0.0 {
            return Speed::default().to_string();
        }

        let weighted_input = self
            .total_speed_buffer
            .iter()
            .map(|ts| ts.speed.input as f64 * ts.duration_secs)
            .sum::<f64>()
            / total_duration;

        let weighted_output = self
            .total_speed_buffer
            .iter()
            .map(|ts| ts.speed.output as f64 * ts.duration_secs)
            .sum::<f64>()
            / total_duration;

        Speed::new(weighted_input as u128, weighted_output as u128).to_string()
    }

    /// Get the instantaneous total speed (last tick).
    pub fn total_speed_instant(&self) -> Speed {
        self.total_speed_buffer
            .iter()
            .last()
            .map(|ts| ts.speed)
            .unwrap_or_default()
    }

    /// Get the peak total speed (max over window).
    pub fn total_speed_peak(&self) -> Speed {
        let mut peak_speed = Speed::default();
        self.total_speed_buffer.iter().for_each(|timed_speed| {
            if timed_speed.speed.input > peak_speed.input {
                peak_speed.input = timed_speed.speed.input;
            }
            if timed_speed.speed.output > peak_speed.output {
                peak_speed.output = timed_speed.speed.output;
            }
        });
        peak_speed
    }

    /// Get speed history for sparkline visualization.
    ///
    /// Returns a vector of Speed values representing the historical total speed
    /// across the aggregation window. If `host_ip` is provided, returns history
    /// for that specific host; otherwise returns session-wide totals.
    ///
    /// # Arguments
    /// * `host_ip` - Optional host IP to filter history for
    ///
    /// # Returns
    /// Vector of Speed values (one per sample in the window)
    pub fn speed_history(&self, host_ip: Option<Ipv4Addr>) -> Vec<Speed> {
        if let Some(ip) = host_ip {
            // Return per-host speed history
            self.hosts_buffer
                .iter()
                .filter_map(|per_host| per_host.get(&ip).copied())
                .collect()
        } else {
            // Return total speed history (extract Speed from TimedSpeed)
            self.total_speed_buffer.iter().map(|ts| ts.speed).collect()
        }
    }

    /// Get application statistics grouped by service type.
    ///
    /// Returns a list of AppStats sorted by total bandwidth (descending),
    /// showing bandwidth usage per application (HTTP, SSH, etc.).
    ///
    /// # Returns
    /// Vector of AppStats sorted by bandwidth
    pub fn apps_stats(&self) -> Vec<AppStats> {
        let registry = AppRegistry::default();
        aggregate_by_app(&self.pairs_buffer, &registry, &self.connection_ports)
    }

    /// Get all connections as formatted strings.
    ///
    /// Returns a sorted list of connections with average bandwidth.
    pub fn connection_strings(&self) -> Vec<String> {
        pairs_format_connections(&self.pairs_buffer)
    }

    /// Get all connections as formatted strings.
    ///
    /// Returns a sorted list of connections with average bandwidth.
    ///
    /// # Deprecated
    /// Use [`connection_strings()`][Self::connection_strings] instead.
    #[deprecated(since = "0.2.0", note = "Use `connection_strings()` instead")]
    pub fn connections_strs(&self) -> Vec<String> {
        self.connection_strings()
    }

    /// Get top N ports by bandwidth for a specific host.
    ///
    /// Returns ports sorted by total bandwidth (descending).
    pub fn top_ports_per_host(&self, host_ip: Ipv4Addr, n: usize) -> Vec<PortStats> {
        ports_top_ports_per_host(&self.stats_buffer, host_ip, n)
    }

    /// Get top N ports globally across all hosts.
    ///
    /// Returns ports sorted by total bandwidth (descending).
    pub fn top_ports_all(&self, n: usize) -> Vec<PortStats> {
        ports_top_ports_all(&self.stats_buffer, n)
    }

    /// Format port stats for display.
    pub fn format_port_stats(port_stats: &PortStats) -> String {
        ports_format_port_stats(port_stats)
    }

    /// Get connections with their TCP states and speeds.
    ///
    /// Returns a vector of (IpPair, TcpState, Speed) tuples.
    /// Speeds are time-weighted averages across the aggregation window.
    pub fn connections_with_state(&self) -> Vec<(IpPair, TcpState, Speed)> {
        let mut accumulators: HashMap<IpPair, SpeedAccumulator> = Default::default();

        // Aggregate speeds using time-weighted average via SpeedAccumulator
        self.pairs_buffer.iter().for_each(|pair_map| {
            pair_map.iter().for_each(|(pair, timed_speed)| {
                accumulators
                    .entry(*pair)
                    .and_modify(|acc| acc.add(timed_speed))
                    .or_insert_with(|| timed_speed.accumulate());
            });
        });

        // Finalize time-weighted average speeds for each connection
        let averaged_speeds: HashMap<IpPair, Speed> = accumulators
            .into_iter()
            .filter_map(|(pair, acc)| acc.finalize().map(|speed| (pair, speed)))
            .collect();

        self.tcp_state_tracker
            .connections_with_state(&averaged_speeds)
    }

    /// Get connections with full details including ports.
    ///
    /// Returns a vector of (ConnectionDetails, TcpState, Speed, Option<Duration>) tuples.
    /// The Duration is the connection age if available.
    pub fn connections_with_details(
        &self,
    ) -> Vec<(
        ConnectionDetails,
        TcpState,
        Speed,
        Option<std::time::Duration>,
    )> {
        self.connections_with_state()
            .into_iter()
            .map(|(pair, state, speed)| {
                let (ports, direction) = self
                    .connection_ports
                    .get(&pair)
                    .map(|(src_port, dst_port, dir)| ((*src_port, *dst_port), *dir))
                    .unwrap_or(((0, 0), Direction::None));
                let details = ConnectionDetails::new(
                    pair.src_ip,
                    pair.dst_ip,
                    ports.0,
                    ports.1,
                    pair.is_local,
                    direction,
                    pair.protocol,
                );
                let age = self.connection_age(&pair);
                (details, state, speed, age)
            })
            .collect()
    }

    /// Get the age of a connection.
    ///
    /// Returns the duration since first seen, or None if not tracked.
    pub fn connection_age(&self, pair: &IpPair) -> Option<std::time::Duration> {
        self.tcp_state_tracker.connection_age(pair)
    }

    /// Get the AppRegistry instance for port-to-app lookups.
    pub fn app_registry(&self) -> AppRegistry {
        AppRegistry::default()
    }

    /// Get all quality metrics.
    ///
    /// Returns a map of IpPair to QualityMetrics.
    pub fn quality_metrics(&self) -> HashMap<IpPair, QualityMetrics> {
        // Clone the metrics from the tracker
        // Note: This is a simplified implementation. For production,
        // we'd want to avoid cloning by returning references.
        self.quality_tracker.all().clone()
    }

    /// Get quality metrics for a specific connection.
    ///
    /// Returns quality metrics if available for the connection.

    pub fn quality_metrics_for_connection(&self, pair: &IpPair) -> Option<&QualityMetrics> {
        self.quality_tracker.get(pair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{StatKey, StatValues};

    // Helper macro for IP address creation in tests
    macro_rules! ip {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            std::net::Ipv4Addr::new($a, $b, $c, $d)
        };
    }

    #[test]
    fn test_total_speed_modes() {
        let mut agg = StatsAggregator::new_with_window_size(10);
        let mut stats1 = HashMap::new();

        // Tick 1: 1000 bits input
        let key1 = StatKey {
            src_port: 123,
            dst_port: 456,
            src_ip: ip!(192, 168, 1, 2),
            dst_ip: ip!(10, 0, 0, 1),
            direction: Direction::Incoming,
            protocol: 6,
            tcp_syn: false,
            tcp_ack: false,
            tcp_fin: false,
            tcp_rst: false,
        };
        stats1.insert(
            key1,
            StatValues {
                size: 1000,
                last_timestamp: None,
                last_seq: None,
                last_ack: None,
            },
        );

        agg.tick(stats1);

        // Check instant
        let instant = agg.total_speed_instant();
        assert_eq!(instant.input, 1000);
        assert_eq!(instant.output, 0);

        // Check peak (should be 1000)
        let peak = agg.total_speed_peak();
        assert_eq!(peak.input, 1000);

        // Tick 2: 2000 bits input
        let mut stats2 = HashMap::new();
        stats2.insert(
            key1,
            StatValues {
                size: 2000,
                last_timestamp: None,
                last_seq: None,
                last_ack: None,
            },
        );

        agg.tick(stats2);

        // Check instant (now 2000)
        let instant = agg.total_speed_instant();
        assert_eq!(instant.input, 2000);

        // Check peak (now 2000)
        let peak = agg.total_speed_peak();
        assert_eq!(peak.input, 2000);

        // Tick 3: 500 bits input
        let mut stats3 = HashMap::new();
        stats3.insert(
            key1,
            StatValues {
                size: 500,
                last_timestamp: None,
                last_seq: None,
                last_ack: None,
            },
        );

        agg.tick(stats3);

        // Check instant (now 500)
        let instant = agg.total_speed_instant();
        assert_eq!(instant.input, 500);

        // Check peak (still 2000)
        let peak = agg.total_speed_peak();
        assert_eq!(peak.input, 2000);

        // Check average (rough check: (1000 + 2000 + 500) / 3 = 1166 bits/s)
        // 1166 bits/s / 8 = 145.75 Bytes/s
        let avg_str = agg.speed_str();
        assert!(avg_str.contains("145.75 B/s"));
    }

    #[test]
    fn test_connection_strings_weighted_average() {
        // Verify that connection_strings uses time-weighted averaging,
        // not simple summation across samples.
        let mut agg = StatsAggregator::new_with_window_size(10);

        let key1 = StatKey {
            src_port: 123,
            dst_port: 456,
            src_ip: ip!(192, 168, 1, 2),
            dst_ip: ip!(10, 0, 0, 1),
            direction: Direction::Incoming,
            protocol: 6,
            tcp_syn: false,
            tcp_ack: false,
            tcp_fin: false,
            tcp_rst: false,
        };

        // Simulate 3 ticks with the same rate (1000 bytes each tick)
        for _ in 0..3 {
            let mut stats = HashMap::new();
            stats.insert(
                key1,
                StatValues {
                    size: 1000,
                    last_timestamp: None,
                    last_seq: None,
                    last_ack: None,
                },
            );
            agg.tick(stats);
        }

        let connections = agg.connection_strings();
        assert_eq!(connections.len(), 1);

        // The connection string should show the average rate, not the sum
        // With 3 ticks of 1000 bytes each at ~1 sec intervals:
        // - WRONG (simple sum): would show ~3000 B/s
        // - CORRECT (weighted avg): should show ~1000 B/s
        let conn_str = &connections[0];
        // The format is "source_ip <-> dest_ip \t (down X | up Y)"
        // We just check that it doesn't show an absurdly high value (like 3000)
        // Parse the download speed
        let speed_part = conn_str
            .split("down ")
            .nth(1)
            .and_then(|s| s.split(" |").next());
        if let Some(speed_str) = speed_part {
            let speed_val = speed_str.trim().parse::<f64>().ok();
            if let Some(val) = speed_val {
                // Should be roughly 1000 (allowing for timing variance), not 3000
                assert!(
                    val < 2000.0,
                    "Connection speed {} seems to be a sum, not an average",
                    val
                );
            }
        }
    }
}
