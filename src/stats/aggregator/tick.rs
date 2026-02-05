//! Tick processing logic for the statistics aggregator.
//!
//! This module handles the processing of new statistics maps,
//! updating all aggregation buffers and derived statistics.

use crate::stats::{Direction, StatsMap};
use ringbuf::traits::RingBuffer;
use std::time::Instant;

use super::StatsAggregator;

impl StatsAggregator {
    /// Process a new statistics map and update all aggregations.
    ///
    /// This is the main entry point for new statistics. It:
    /// 1. Calculates elapsed time since last tick
    /// 2. Aggregates directional totals
    /// 3. Calculates actual rates (bits / elapsed_seconds)
    /// 4. Updates session statistics
    /// 5. Updates all derived buffers (pairs, hosts, totals)
    ///
    /// # Arguments
    /// * `hash_map` - Map of connection statistics for this tick
    pub fn tick(&mut self, hash_map: StatsMap) {
        let now = Instant::now();

        // Calculate elapsed time since last tick for rate calculation
        let elapsed_secs = match self.last_tick_time {
            Some(last_time) => {
                let duration = now.duration_since(last_time);
                let secs = duration.as_secs_f64();

                // Guard against edge cases
                if secs < 0.001 {
                    // Too short, use minimum to avoid spikes
                    1.0
                } else if secs > 5.0 {
                    // Too long, cap to avoid stale data
                    5.0
                } else {
                    secs
                }
            }
            None => 1.0, // First tick, assume 1 second
        };

        // Aggregate by direction
        // Note: Internet traffic is counted in the outgoing/incoming buckets
        // for total speed, but can be distinguished separately if needed
        let init = [0u128; 4]; // [outgoing, incoming, local, other] - stack-allocated
        let sum =
            hash_map
                .iter()
                .map(|(k, v)| (&k.direction, v.size))
                .fold(init, |mut acc, (di, si)| {
                    match di {
                        Direction::Outgoing => acc[0] += si,
                        Direction::Internet => acc[0] += si, // Internet upload counts as outgoing
                        Direction::Incoming => acc[1] += si,
                        Direction::Local => acc[2] += si,
                        Direction::None => acc[3] += si,
                    }
                    acc
                });

        // Update session totals with actual bit counts (not rates)
        self.session_stats.total_bits_up += sum[0];
        self.session_stats.total_bits_down += sum[1];

        // Store raw direction totals for other uses
        self.speed_buffer.push_overwrite(sum.to_vec());
        hash_map.keys().for_each(|key| {
            self.stat_keys_buffer.push_overwrite(*key);
        });

        self.stats_buffer.push_overwrite(hash_map);

        // Update all derived aggregations
        self.update_pairs_stats_buffer();
        self.update_hosts_stats_buffer();
        self.update_total_speed();
        self.update_tcp_states();
        self.update_quality_metrics();

        self.last_tick_time = Some(now);
        self.last_elapsed_secs = elapsed_secs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{Direction, StatKey, StatValues};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    // Helper macro for IP address creation in tests
    macro_rules! ip {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            Ipv4Addr::new($a, $b, $c, $d)
        };
    }

    #[test]
    fn test_rate_calculation_with_normal_tick() {
        let mut agg = StatsAggregator::new_with_window_size(10);
        let mut stats = HashMap::new();

        // Add 1000 bits of incoming traffic
        let key = StatKey {
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

        // First tick assumes 1.0 second duration
        // Rate should be 1000 bits / 1.0s = 1000 bits/s
        let instant = agg.total_speed_instant();
        assert_eq!(instant.input, 1000);
        assert_eq!(agg.last_elapsed_secs, 1.0);
    }

    #[test]
    fn test_elapsed_time_tracking() {
        let mut agg = StatsAggregator::new_with_window_size(10);

        // First tick
        agg.tick(HashMap::new());
        assert!(agg.last_tick_time.is_some());
        assert_eq!(agg.last_elapsed_secs, 1.0); // Default for first tick
    }

    #[test]
    fn test_session_stats_accumulation() {
        let mut agg = StatsAggregator::new_with_window_size(10);
        let mut stats = HashMap::new();

        // Add 1000 bits of outgoing traffic
        let key = StatKey {
            src_port: 123,
            dst_port: 456,
            src_ip: ip!(192, 168, 1, 2),
            dst_ip: ip!(10, 0, 0, 1),
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

        // Session stats should accumulate actual bit counts, not rates
        assert_eq!(agg.session_stats.total_bits_up, 1000);
        assert_eq!(agg.session_stats.total_bits_down, 0);

        // Tick again with 2000 bits
        let mut stats2 = HashMap::new();
        stats2.insert(
            key,
            StatValues {
                size: 2000,
                last_timestamp: None,
                last_seq: None,
                last_ack: None,
            },
        );
        agg.tick(stats2);

        // Session stats should now be 3000 total
        assert_eq!(agg.session_stats.total_bits_up, 3000);
    }

    #[test]
    fn test_elapsed_time_bounds() {
        // Test that elapsed time is properly bounded
        // This test verifies the edge case handling in the tick method
        let mut agg = StatsAggregator::new_with_window_size(10);

        // First tick - should use default 1.0
        agg.tick(HashMap::new());
        assert_eq!(agg.last_elapsed_secs, 1.0);

        // Simulate a quick second tick - should be close to actual elapsed time
        // In practice, this would be slightly more than 0, but bounded by min 1.0
        // Due to test timing, we can't precisely control this, but we can verify
        // the mechanism is in place
        agg.tick(HashMap::new());
        assert!(agg.last_elapsed_secs >= 0.001); // Should be at least min
        assert!(agg.last_elapsed_secs <= 5.0); // Should be at most max
    }
}
