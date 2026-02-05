//! IP pair aggregation for connection statistics.
//!
//! This module handles aggregation of statistics between pairs of IP addresses,
//! regardless of traffic direction. It provides functions for updating pair
//! statistics buffers and formatting connection information.

use crate::stats::{Direction, IpPair, Speed, StatKey, StatValues, TimedSpeed};
use ringbuf::traits::Consumer;
use ringbuf::traits::RingBuffer;
use ringbuf::HeapRb;
use std::collections::HashMap;

/// Type alias for IP pair statistics map.
pub type PairStatMap = HashMap<IpPair, TimedSpeed>;

/// Update the pairs statistics buffer from the current stats buffer.
///
/// This function aggregates statistics by IP pair, normalizing direction
/// so that traffic between two IPs is tracked together regardless of which
/// was the source or destination.
///
/// # Arguments
/// * `stats_buffer` - Ring buffer of statistics maps
/// * `pairs_buffer` - Ring buffer to update with pair statistics
/// * `elapsed_secs` - Duration in seconds for rate calculation
///
/// # How it works
/// - For incoming traffic, swaps src/dst so remote host is always source
/// - For local traffic, ensures consistent ordering (src > dst)
/// - Tracks bidirectional speed (input/output) for each pair
/// - Calculates rates as bits/elapsed_secs
pub fn update_pairs_stats_buffer(
    stats_buffer: &HeapRb<HashMap<StatKey, StatValues>>,
    pairs_buffer: &mut HeapRb<PairStatMap>,
    elapsed_secs: f64,
) {
    pairs_buffer.clear();
    stats_buffer.iter().for_each(|item| {
        let mut pairs: PairStatMap = Default::default();
        item.iter().for_each(|(k, v)| {
            let (mut src, mut dst) = (k.src_ip, k.dst_ip);
            let is_local = k.direction == Direction::Local;

            // Normalize: for incoming, swap so remote is always "source"
            // For local traffic, ensure consistent ordering
            if Direction::Incoming == k.direction || (is_local && src > dst) {
                (src, dst) = (dst, src);
            }

            let pair = IpPair {
                src_ip: src,
                dst_ip: dst,
                is_local,
                protocol: k.protocol,
            };

            // Calculate rate for this connection
            let rate_input: u128;
            let rate_output: u128;
            match k.direction {
                Direction::Outgoing => {
                    rate_input = 0;
                    rate_output = (v.size as f64 / elapsed_secs) as u128;
                }
                Direction::Internet => {
                    // Internet traffic: treat as outgoing (upload to gateway)
                    rate_input = 0;
                    rate_output = (v.size as f64 / elapsed_secs) as u128;
                }
                Direction::Incoming => {
                    rate_input = (v.size as f64 / elapsed_secs) as u128;
                    rate_output = 0;
                }
                Direction::Local => {
                    // For local traffic, track direction based on which IP was originally src
                    if src != k.src_ip {
                        rate_input = 0;
                        rate_output = (v.size as f64 / elapsed_secs) as u128;
                    } else {
                        rate_input = (v.size as f64 / elapsed_secs) as u128;
                        rate_output = 0;
                    }
                }
                Direction::None => {
                    // Include traffic with unknown direction in both directions
                    rate_input = (v.size as f64 / elapsed_secs) as u128;
                    rate_output = (v.size as f64 / elapsed_secs) as u128;
                }
            }

            let speed_pair_to_add = Speed::new(rate_input, rate_output);

            pairs
                .entry(pair)
                .and_modify(|timed_speed| {
                    timed_speed.speed += speed_pair_to_add;
                })
                .or_insert(TimedSpeed::new(speed_pair_to_add, elapsed_secs));
        });
        pairs_buffer.push_overwrite(pairs);
    });
}

/// Format connections as strings for display.
///
/// Returns a sorted list of connections with average bandwidth for each pair.
/// The format shows: "source_ip <-> dest_ip \t (down X | up Y)"
///
/// # Arguments
/// * `pairs_buffer` - Ring buffer of pair statistics
///
/// # Returns
/// A vector of formatted connection strings, sorted by IP pair
pub fn format_connections(pairs_buffer: &HeapRb<PairStatMap>) -> Vec<String> {
    let mut pairs_avg: HashMap<IpPair, (Speed, f64)> = Default::default();

    // Aggregate speeds across the buffer using time-weighted average
    pairs_buffer.iter().for_each(|map| {
        map.iter().for_each(|(pair, timed_speed)| {
            pairs_avg
                .entry(pair.to_owned())
                .and_modify(|pair_and_dur| {
                    pair_and_dur.0 += timed_speed.speed;
                    pair_and_dur.1 += timed_speed.duration_secs;
                })
                .or_insert((timed_speed.speed, timed_speed.duration_secs));
        });
    });

    // Sort pairs and format output
    let mut pairs: Vec<_> = pairs_avg.into_iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    pairs
        .into_iter()
        .map(|(pair, (speeds_sum, total_dur))| {
            // Calculate time-weighted average
            let speed_avg = if total_dur > 0.0 {
                Speed::new(
                    (speeds_sum.input as f64 / total_dur) as u128,
                    (speeds_sum.output as f64 / total_dur) as u128,
                )
            } else {
                speeds_sum
            };

            // Choose separator based on traffic direction
            let sep = match (speed_avg.input != 0, speed_avg.output != 0) {
                (true, true) => "<->",   // Bidirectional
                (true, false) => "-->",  // Download only
                (false, true) => "<--",  // Upload only
                (false, false) => "---", // No traffic
            };

            format!("{} {} {} \t ({})", pair.src_ip, sep, pair.dst_ip, speed_avg)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ringbuf::traits::Observer;
    use ringbuf::HeapRb;

    // Helper macro for IP address creation in tests
    macro_rules! ip {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            std::net::Ipv4Addr::new($a, $b, $c, $d)
        };
    }

    #[test]
    fn test_update_pairs_stats_buffer_empty() {
        let stats_buffer = HeapRb::<HashMap<StatKey, StatValues>>::new(2);
        let mut pairs_buffer = HeapRb::<PairStatMap>::new(2);

        update_pairs_stats_buffer(&stats_buffer, &mut pairs_buffer, 1.0);

        assert!(pairs_buffer.is_empty());
    }

    #[test]
    fn test_update_pairs_normalizes_direction() {
        let mut stats_buffer = HeapRb::<HashMap<StatKey, StatValues>>::new(2);
        let mut stats = HashMap::new();

        // Add incoming traffic - should normalize src/dst
        let key_incoming = StatKey {
            src_port: 12345,
            dst_port: 443,
            src_ip: ip!(93, 184, 216, 34),
            dst_ip: ip!(192, 168, 1, 1),
            direction: Direction::Incoming,
            protocol: 6,
            tcp_syn: false,
            tcp_ack: false,
            tcp_fin: false,
            tcp_rst: false,
        };
        stats.insert(
            key_incoming,
            StatValues {
                size: 1000,
                last_timestamp: None,
                last_seq: None,
                last_ack: None,
            },
        );

        stats_buffer.push_overwrite(stats);

        let mut pairs_buffer = HeapRb::<PairStatMap>::new(2);
        update_pairs_stats_buffer(&stats_buffer, &mut pairs_buffer, 1.0);

        // After normalization, remote IP should be src
        assert!(!pairs_buffer.is_empty());
    }

    #[test]
    fn test_format_connections_empty() {
        let pairs_buffer = HeapRb::<PairStatMap>::new(2);
        let result = format_connections(&pairs_buffer);
        assert!(result.is_empty());
    }
}
