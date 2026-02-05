//! Port statistics for bandwidth breakdown by service.
//!
//! This module provides functions for analyzing and displaying network traffic
//! statistics organized by port number, useful for identifying which services
//! (HTTP, HTTPS, SSH, etc.) are consuming the most bandwidth.

use crate::stats::{Direction, Speed, StatKey, StatValues};
use ringbuf::traits::Consumer;
use ringbuf::HeapRb;
use std::collections::HashMap;

/// Port statistics for bandwidth breakdown by service.
#[derive(Debug, Clone, Default)]
pub struct PortStats {
    /// Port number (e.g., 443 for HTTPS)
    pub port: u16,
    /// Bidirectional speed for this port
    pub speed: Speed,
}

/// Get top N ports by bandwidth for a specific host.
///
/// Returns ports sorted by total bandwidth (descending). For each port,
/// analyzes whether traffic involves the specified host and aggregates accordingly.
///
/// # Arguments
/// * `stats_buffer` - Ring buffer of statistics maps
/// * `host_ip` - The IP address of the host to analyze
/// * `n` - Maximum number of ports to return
///
/// # Returns
/// A vector of PortStats sorted by total bandwidth (input + output)
///
/// # Port Selection Logic
/// - For incoming traffic to host: uses source port
/// - For outgoing traffic from host: uses destination port (service port)
pub fn top_ports_per_host(
    stats_buffer: &HeapRb<HashMap<StatKey, StatValues>>,
    host_ip: std::net::Ipv4Addr,
    n: usize,
) -> Vec<PortStats> {
    let mut port_map: HashMap<u16, Speed> = HashMap::new();

    // Aggregate from stats_buffer
    for stats in stats_buffer.iter() {
        for (key, value) in stats.iter() {
            // Check if this stat involves our host
            if key.src_ip == host_ip || key.dst_ip == host_ip {
                let port = if key.dst_ip == host_ip {
                    key.src_port // Incoming - use source port
                } else {
                    key.dst_port // Outgoing - use destination port (service)
                };

                let mut speed = Speed::default();
                match key.direction {
                    Direction::Incoming => speed.input = value.size,
                    Direction::Outgoing => speed.output = value.size,
                    Direction::Internet => speed.output = value.size, // Treat as outgoing
                    Direction::Local => {
                        speed.input += value.size;
                        speed.output += value.size;
                    }
                    Direction::None => {}
                }

                port_map
                    .entry(port)
                    .and_modify(|s| *s += speed)
                    .or_insert(speed);
            }
        }
    }

    // Convert to vector, sort by total bandwidth, return top N
    let mut result: Vec<PortStats> = port_map
        .into_iter()
        .map(|(port, speed)| PortStats { port, speed })
        .collect();

    result.sort_by(|a, b| {
        let a_total = a.speed.input + a.speed.output;
        let b_total = b.speed.input + b.speed.output;
        b_total.cmp(&a_total)
    });

    result.truncate(n);
    result
}

/// Get top N ports globally across all hosts.
///
/// Returns ports sorted by total bandwidth (descending). This analyzes
/// all traffic and aggregates by destination port (the service port).
///
/// # Arguments
/// * `stats_buffer` - Ring buffer of statistics maps
/// * `n` - Maximum number of ports to return
///
/// # Returns
/// A vector of PortStats sorted by total bandwidth (input + output)
///
/// # Note
/// Only tracks destination ports (service ports), not source ports.
/// This gives you the most-used services across all traffic.
pub fn top_ports_all(
    stats_buffer: &HeapRb<HashMap<StatKey, StatValues>>,
    n: usize,
) -> Vec<PortStats> {
    let mut port_map: HashMap<u16, Speed> = HashMap::new();

    for stats in stats_buffer.iter() {
        for (key, value) in stats.iter() {
            let mut speed = Speed::default();
            match key.direction {
                Direction::Incoming => speed.input = value.size,
                Direction::Outgoing => speed.output = value.size,
                Direction::Internet => speed.output = value.size, // Treat as outgoing
                Direction::Local => {
                    speed.input += value.size;
                    speed.output += value.size;
                }
                Direction::None => {}
            }

            // Track by destination port (service port)
            port_map
                .entry(key.dst_port)
                .and_modify(|s| *s += speed)
                .or_insert(speed);
        }
    }

    let mut result: Vec<PortStats> = port_map
        .into_iter()
        .map(|(port, speed)| PortStats { port, speed })
        .collect();

    result.sort_by(|a, b| {
        let a_total = a.speed.input + a.speed.output;
        let b_total = b.speed.input + b.speed.output;
        b_total.cmp(&a_total)
    });

    result.truncate(n);
    result
}

/// Format port stats for display.
///
/// Returns a string in the format: "PORT: ↓ XX Mib/s | ↑ XX Mib/s"
///
/// # Arguments
/// * `port_stats` - The PortStats to format
///
/// # Returns
/// A formatted string suitable for display
///
/// # Example
/// ```rust
/// use netui::stats::{PortStats, Speed, format_port_stats};
///
/// let stats = PortStats { port: 443, speed: Speed { input: 1048576, output: 524288 } };
/// assert_eq!(format_port_stats(&stats), "443: ↓ 128.00 KiB/s | ↑ 64.00 KiB/s");
/// ```
pub fn format_port_stats(port_stats: &PortStats) -> String {
    format!("{}: {}", port_stats.port, port_stats.speed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ringbuf::HeapRb;

    // Helper macro for IP address creation in tests
    macro_rules! ip {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            std::net::Ipv4Addr::new($a, $b, $c, $d)
        };
    }

    #[test]
    fn test_top_ports_per_host_empty() {
        let stats_buffer = HeapRb::<HashMap<StatKey, StatValues>>::new(2);
        let result = top_ports_per_host(&stats_buffer, ip!(192, 168, 1, 1), 10);
        assert!(result.is_empty());
    }

    #[test]
    fn test_top_ports_all_empty() {
        let stats_buffer = HeapRb::<HashMap<StatKey, StatValues>>::new(2);
        let result = top_ports_all(&stats_buffer, 10);
        assert!(result.is_empty());
    }

    #[test]
    fn test_format_port_stats() {
        let stats = PortStats {
            port: 443,
            speed: Speed {
                input: 16_777_216, // 2 MiB = 2 * 8 * 1024 * 1024 bits
                output: 8_388_608, // 1 MiB = 1 * 8 * 1024 * 1024 bits
            },
        };
        let formatted = format_port_stats(&stats);
        assert!(formatted.contains("443:"));
        assert!(formatted.contains("2.00 MiB/s"));
        assert!(formatted.contains("1.00 MiB/s"));
    }

    #[test]
    fn test_port_stats_default() {
        let stats = PortStats::default();
        assert_eq!(stats.port, 0);
        assert_eq!(stats.speed.input, 0);
        assert_eq!(stats.speed.output, 0);
    }
}
