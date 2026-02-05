//! Application classification by port number.
//!
//! This module provides application name lookup based on well-known port numbers,
//! and aggregation of bandwidth statistics by application type.
//!
//! # Re-exports
//! This module re-exports the following types for backward compatibility:
//! - [`AppRegistry`] - From the `registry` submodule
//! - [`AppStats`] - From the `aggregation::app` submodule
//! - [`aggregate_by_app`] - From the `aggregation::app` submodule

// Re-export from submodules for backward compatibility
pub use crate::stats::aggregation::app::{aggregate_by_app, AppStats};
pub use crate::stats::registry::AppRegistry;

// Re-export tests for backward compatibility
#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{Direction, IpPair, PairStatMap, Speed, TimedSpeed};
    use ringbuf::traits::RingBuffer;
    use ringbuf::HeapRb;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    // Helper macro for IP address creation in tests
    macro_rules! ip {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            Ipv4Addr::new($a, $b, $c, $d)
        };
    }

    #[test]
    fn test_registry_known_ports() {
        let registry = AppRegistry::new();

        assert_eq!(registry.get_app_name(80), Some(&"HTTP".to_string()));
        assert_eq!(registry.get_app_name(443), Some(&"HTTPS".to_string()));
        assert_eq!(registry.get_app_name(22), Some(&"SSH".to_string()));
    }

    #[test]
    fn test_registry_unknown_port() {
        let registry = AppRegistry::new();
        assert_eq!(registry.get_app_name(9999), None);
    }

    #[test]
    fn test_registry_get_or_default() {
        let registry = AppRegistry::new();
        assert_eq!(registry.get_app_name_or_default(80), "HTTP");
        assert_eq!(registry.get_app_name_or_default(9999), "Port-9999");
    }

    #[test]
    fn test_registry_get_ports_for_app() {
        let registry = AppRegistry::new();
        let http_ports = registry.get_ports_for_app("HTTP");
        assert!(http_ports.contains(&80));
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
        assert_eq!(results[0].total_bandwidth(), 10000);
    }
}
