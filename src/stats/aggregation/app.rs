//! Application statistics aggregation.
//!
//! This module provides application-level statistics aggregation,
//! grouping network traffic by application type based on port numbers.

use ringbuf::traits::Consumer;
use ringbuf::HeapRb;
use std::collections::{HashMap, HashSet};

use crate::stats::registry::AppRegistry;
use crate::stats::{Direction, IpPair, PairStatMap, Speed, SpeedAccumulator};

/// Statistics for a single application.
#[derive(Debug, Clone)]
pub struct AppStats {
    /// Application name (e.g., "HTTP", "SSH")
    pub name: String,
    /// All ports associated with this application
    pub ports: Vec<u16>,
    /// Total speed (input + output)
    pub speed: Speed,
    /// Percentage of total bandwidth (0.0 to 100.0)
    pub percentage: f32,
}

impl AppStats {
    /// Create a new AppStats instance.
    pub fn new(name: String, ports: Vec<u16>) -> Self {
        Self {
            name,
            ports,
            speed: Speed::default(),
            percentage: 0.0,
        }
    }

    /// Get the total bandwidth (input + output) in bits per second.
    pub fn total_bandwidth(&self) -> u128 {
        self.speed.input + self.speed.output
    }
}

/// Aggregate bandwidth statistics by application type.
///
/// This function processes a pairs buffer and groups traffic by application
/// based on port numbers, using time-weighted averages for accurate speed calculation.
/// It returns a sorted list of AppStats ordered by total bandwidth (descending).
///
/// # Arguments
/// * `pairs_buffer` - Ring buffer of pair statistics (from StatsAggregator)
/// * `registry` - AppRegistry for port-to-app name lookups
/// * `connection_ports` - Map of IpPair to (src_port, dst_port, direction) for service identification
///
/// # Returns
/// Vector of AppStats sorted by total bandwidth (descending)
///
/// # Aggregation Strategy
/// - For each pair, calculate its time-weighted average speed over the buffer using SpeedAccumulator
/// - For each app, sum the speeds of all pairs that belong to it
/// - This correctly handles multiple samples over time (averaging) and multiple connections (summing)
pub fn aggregate_by_app(
    pairs_buffer: &HeapRb<PairStatMap>,
    registry: &AppRegistry,
    connection_ports: &HashMap<IpPair, (u16, u16, Direction)>,
) -> Vec<AppStats> {
    // Step 1: Calculate time-weighted average speed for each pair using SpeedAccumulator
    let mut pair_accumulators: HashMap<IpPair, SpeedAccumulator> = HashMap::new();

    pairs_buffer.iter().for_each(|pair_map| {
        pair_map.iter().for_each(|(pair, timed_speed)| {
            pair_accumulators
                .entry(*pair)
                .and_modify(|acc| acc.add(timed_speed))
                .or_insert_with(|| timed_speed.accumulate());
        });
    });

    // Step 2: Finalize time-weighted averages for each pair
    let pair_averages: HashMap<IpPair, Speed> = pair_accumulators
        .into_iter()
        .filter_map(|(pair, acc)| acc.finalize().map(|speed| (pair, speed)))
        .collect();

    // Step 3: Group by app and sum speeds
    let mut app_speeds: HashMap<String, Speed> = HashMap::new();
    let mut port_sets: HashMap<String, HashSet<u16>> = HashMap::new();

    pair_averages.iter().for_each(|(pair, speed)| {
        if let Some((src_port, dst_port, direction)) = connection_ports.get(pair) {
            // Determine the service port based on direction
            // For incoming traffic, the src_port is the service port (since IPs are swapped in pairs.rs)
            let service_port = match direction {
                Direction::Incoming => *src_port,
                _ => *dst_port,
            };

            let app_name = registry.get_app_name_or_default(service_port);

            // Sum speeds for this app (different connections are additive)
            app_speeds
                .entry(app_name.clone())
                .and_modify(|s| *s += *speed)
                .or_insert(*speed);

            // Track ports for this app
            port_sets.entry(app_name).or_default().insert(service_port);
        }
    });

    // Step 4: Build AppStats structures
    let mut result: Vec<AppStats> = app_speeds
        .into_iter()
        .map(|(name, speed)| {
            let ports = port_sets
                .get(&name)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();

            AppStats {
                name,
                ports,
                speed,
                percentage: 0.0,
            }
        })
        .collect();

    // Step 5: Calculate percentages
    let total_bandwidth: u128 = result.iter().map(|s| s.total_bandwidth()).sum();
    for app in &mut result {
        if total_bandwidth > 0 {
            app.percentage = (app.total_bandwidth() as f32 / total_bandwidth as f32) * 100.0;
        }
    }

    result.sort_by(|a, b| {
        b.total_bandwidth()
            .partial_cmp(&a.total_bandwidth())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{Direction, IpPair, Speed, TimedSpeed};
    use ringbuf::traits::RingBuffer;
    use ringbuf::HeapRb;
    use std::net::Ipv4Addr;

    // Helper macro for IP address creation in tests
    macro_rules! ip {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            Ipv4Addr::new($a, $b, $c, $d)
        };
    }

    #[test]
    fn test_app_stats_new() {
        let app = AppStats::new("TestApp".to_string(), vec![8080]);
        assert_eq!(app.name, "TestApp");
        assert_eq!(app.ports, vec![8080]);
        assert_eq!(app.speed.input, 0);
        assert_eq!(app.speed.output, 0);
        assert_eq!(app.percentage, 0.0);
    }

    #[test]
    fn test_app_stats_total_bandwidth() {
        let mut app = AppStats::new("TestApp".to_string(), vec![8080]);
        app.speed.input = 1000;
        app.speed.output = 500;
        assert_eq!(app.total_bandwidth(), 1500);
    }

    #[test]
    fn test_aggregate_by_app_empty() {
        let registry = AppRegistry::new();
        let empty_buffer = HeapRb::<PairStatMap>::new(2);
        let connection_ports = HashMap::new();
        let results = aggregate_by_app(&empty_buffer, &registry, &connection_ports);
        assert!(results.is_empty());
    }

    #[test]
    fn test_aggregate_by_app_single_connection() {
        let registry = AppRegistry::new();
        let mut pairs_buffer = HeapRb::<PairStatMap>::new(2);
        let mut connection_ports = HashMap::new();

        // Create an IpPair for an outgoing HTTPS connection
        let pair = IpPair {
            src_ip: ip!(192, 168, 1, 1),
            dst_ip: ip!(93, 184, 216, 34),
            is_local: false,
            protocol: 6,
        };

        // Add to connection_ports with direction
        connection_ports.insert(pair, (12345, 443, Direction::Outgoing));

        // Create a pair map with timed speed (10000 bits/s output)
        let mut pair_map = PairStatMap::new();
        pair_map.insert(pair, TimedSpeed::new(Speed::new(0, 10000), 1.0));

        pairs_buffer.push_overwrite(pair_map);

        let results = aggregate_by_app(&pairs_buffer, &registry, &connection_ports);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "HTTPS");
        // Should be 10000 since we're using time-weighted average (not sum)
        assert_eq!(results[0].total_bandwidth(), 10000);
    }

    #[test]
    fn test_aggregate_by_app_multiple_connections_same_app() {
        let registry = AppRegistry::new();
        let mut pairs_buffer = HeapRb::<PairStatMap>::new(10);
        let mut connection_ports = HashMap::new();

        // Two HTTPS connections
        let pair1 = IpPair {
            src_ip: ip!(192, 168, 1, 1),
            dst_ip: ip!(93, 184, 216, 34),
            is_local: false,
            protocol: 6,
        };
        let pair2 = IpPair {
            src_ip: ip!(192, 168, 1, 1),
            dst_ip: ip!(172, 217, 16, 5),
            is_local: false,
            protocol: 6,
        };

        connection_ports.insert(pair1, (12345, 443, Direction::Outgoing));
        connection_ports.insert(pair2, (54321, 443, Direction::Outgoing));

        // Add both pairs to buffer with same speed
        let mut pair_map = PairStatMap::new();
        pair_map.insert(pair1, TimedSpeed::new(Speed::new(0, 10000), 1.0));
        pair_map.insert(pair2, TimedSpeed::new(Speed::new(0, 5000), 1.0));

        pairs_buffer.push_overwrite(pair_map);

        let results = aggregate_by_app(&pairs_buffer, &registry, &connection_ports);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "HTTPS");
        // Should be 15000 = (10000 + 5000) since both have duration 1.0
        assert_eq!(results[0].total_bandwidth(), 15000);
    }

    #[test]
    fn test_aggregate_by_app_percentage_calculation() {
        let registry = AppRegistry::new();
        let mut pairs_buffer = HeapRb::<PairStatMap>::new(10);
        let mut connection_ports = HashMap::new();

        // HTTPS connection
        let pair1 = IpPair {
            src_ip: ip!(192, 168, 1, 1),
            dst_ip: ip!(93, 184, 216, 34),
            is_local: false,
            protocol: 6,
        };
        connection_ports.insert(pair1, (12345, 443, Direction::Outgoing));

        // SSH connection
        let pair2 = IpPair {
            src_ip: ip!(192, 168, 1, 1),
            dst_ip: ip!(10, 0, 0, 1),
            is_local: false,
            protocol: 6,
        };
        connection_ports.insert(pair2, (54321, 22, Direction::Outgoing));

        let mut pair_map = PairStatMap::new();
        pair_map.insert(pair1, TimedSpeed::new(Speed::new(0, 10000), 1.0));
        pair_map.insert(pair2, TimedSpeed::new(Speed::new(0, 5000), 1.0));

        pairs_buffer.push_overwrite(pair_map);

        let results = aggregate_by_app(&pairs_buffer, &registry, &connection_ports);
        assert_eq!(results.len(), 2);

        // HTTPS should be first (10000 > 5000)
        assert_eq!(results[0].name, "HTTPS");
        assert_eq!(results[0].percentage, 10000.0 / 15000.0 * 100.0);

        assert_eq!(results[1].name, "SSH");
        assert_eq!(results[1].percentage, 5000.0 / 15000.0 * 100.0);
    }

    #[test]
    fn test_aggregate_by_app_time_weighted_average() {
        let registry = AppRegistry::new();
        let mut pairs_buffer = HeapRb::<PairStatMap>::new(10);
        let mut connection_ports = HashMap::new();

        // Single HTTPS connection
        let pair = IpPair {
            src_ip: ip!(192, 168, 1, 1),
            dst_ip: ip!(93, 184, 216, 34),
            is_local: false,
            protocol: 6,
        };
        connection_ports.insert(pair, (12345, 443, Direction::Outgoing));

        // Simulate 3 ticks with the same rate (10000 bytes/s each tick)
        for _ in 0..3 {
            let mut pair_map = PairStatMap::new();
            pair_map.insert(pair, TimedSpeed::new(Speed::new(0, 10000), 1.0));
            pairs_buffer.push_overwrite(pair_map);
        }

        let results = aggregate_by_app(&pairs_buffer, &registry, &connection_ports);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "HTTPS");

        // With time-weighted average: 3 samples of 10000 bits/s with 1 sec duration each
        // Average should be 10000, NOT 30000
        assert_eq!(results[0].total_bandwidth(), 10000);
    }

    #[test]
    fn test_aggregate_by_app_incoming_traffic_uses_src_port() {
        let registry = AppRegistry::new();
        let mut pairs_buffer = HeapRb::<PairStatMap>::new(10);
        let mut connection_ports = HashMap::new();

        // Create an incoming connection
        // In pairs.rs, incoming traffic has IPs swapped, so the remote IP is src
        let pair = IpPair {
            src_ip: ip!(93, 184, 216, 34), // Remote (was dst in original packet)
            dst_ip: ip!(192, 168, 1, 1),   // Local
            is_local: false,
            protocol: 6,
        };

        // Store original ports: src_port=443 (service port), dst_port=12345
        connection_ports.insert(pair, (443, 12345, Direction::Incoming));

        let mut pair_map = PairStatMap::new();
        pair_map.insert(pair, TimedSpeed::new(Speed::new(10000, 0), 1.0));

        pairs_buffer.push_overwrite(pair_map);

        let results = aggregate_by_app(&pairs_buffer, &registry, &connection_ports);
        assert_eq!(results.len(), 1);
        // Should use src_port (443) for incoming traffic
        assert_eq!(results[0].name, "HTTPS");
        assert_eq!(results[0].ports, vec![443]);
    }
}
