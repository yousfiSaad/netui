//! Core type definitions for statistics aggregation.
//!
//! This module contains the fundamental data structures used throughout
//! the stats subsystem for tracking network traffic statistics.

use std::collections::HashMap;
use std::fmt::Display;
use std::net::Ipv4Addr;
use std::time::Instant;

// Re-export Speed from the speed module to avoid circular dependency
pub use crate::stats::speed::Speed;

/// Type alias for the main statistics map.
///
/// Maps a `StatKey` (identifying a specific connection) to its `StatValues` (traffic data).
pub type StatsMap = HashMap<StatKey, StatValues>;

/// Speed with explicit timing information for accurate rate calculation.
///
/// This structure tracks not just the speed value, but also when the sample
/// was taken and the duration it represents. This allows for accurate rate
/// calculation even when ticks don't occur at exactly one-second intervals.
#[derive(Debug, Clone)]
pub struct TimedSpeed {
    /// Speed in bits per second (calculated actual rate)
    pub speed: Speed,
    /// When this sample was taken
    pub timestamp: Instant,
    /// Duration this sample represents (seconds)
    pub duration_secs: f64,
}

impl TimedSpeed {
    /// Create a new TimedSpeed with the given speed and duration.
    ///
    /// # Arguments
    /// * `speed` - The speed value in bits per second
    /// * `duration_secs` - The duration this speed represents in seconds
    pub fn new(speed: Speed, duration_secs: f64) -> Self {
        Self {
            speed,
            timestamp: Instant::now(),
            duration_secs,
        }
    }

    /// Create a SpeedAccumulator from this TimedSpeed for time-weighted aggregation.
    pub fn accumulate(&self) -> SpeedAccumulator {
        SpeedAccumulator::from_timed_speed(self)
    }
}

/// Type-safe accumulator for time-weighted speed aggregation.
///
/// This type prevents bugs where raw byte values are summed across samples
/// instead of calculating time-weighted averages. By construction, it ensures
/// that speed values are properly weighted by their duration.
#[derive(Debug, Clone, Default)]
pub struct SpeedAccumulator {
    speed_sum: Speed,
    total_duration_secs: f64,
}

impl SpeedAccumulator {
    /// Create a new SpeedAccumulator from a TimedSpeed sample.
    pub fn from_timed_speed(ts: &TimedSpeed) -> Self {
        Self {
            speed_sum: ts.speed,
            total_duration_secs: ts.duration_secs,
        }
    }

    /// Add another TimedSpeed sample to this accumulator.
    pub fn add(&mut self, ts: &TimedSpeed) {
        self.speed_sum += ts.speed;
        self.total_duration_secs += ts.duration_secs;
    }

    /// Finalize the accumulator and return the time-weighted average speed.
    ///
    /// Returns None if the total duration is zero.
    pub fn finalize(self) -> Option<Speed> {
        if self.total_duration_secs > 0.0 {
            Some(Speed::new(
                (self.speed_sum.input as f64 / self.total_duration_secs) as u128,
                (self.speed_sum.output as f64 / self.total_duration_secs) as u128,
            ))
        } else {
            None
        }
    }
}

/// Individual statistics item with key and value.
#[derive(Debug, Clone)]
pub struct StatItem {
    pub key: StatKey,
    pub value: StatValues,
}

/// Key that uniquely identifies a network connection for statistics tracking.
///
/// The combination of source/destination IP, ports, direction, and TCP flags creates
/// a unique identifier for tracking traffic on a specific connection.
#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy)]
pub struct StatKey {
    /// Source port of the connection
    pub src_port: u16,
    /// Destination port of the connection
    pub dst_port: u16,
    /// Source IP address
    pub src_ip: Ipv4Addr,
    /// Destination IP address
    pub dst_ip: Ipv4Addr,
    /// Traffic direction relative to the local host
    pub direction: Direction,
    /// Protocol number (6=TCP, 17=UDP, etc.)
    pub protocol: u8,
    /// TCP SYN flag
    pub tcp_syn: bool,
    /// TCP ACK flag
    pub tcp_ack: bool,
    /// TCP FIN flag
    pub tcp_fin: bool,
    /// TCP RST flag
    pub tcp_rst: bool,
}

impl Display for StatKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.direction
        )
    }
}

/// Traffic direction relative to the local host.
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum Direction {
    /// Direction could not be determined
    None,
    /// Traffic from remote to local host (download)
    Incoming,
    /// Traffic between two local addresses
    Local,
    /// Traffic from local host to remote (upload)
    Outgoing,
    /// Traffic through the gateway (Internet)
    Internet,
}

impl Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::None => write!(f, "None"),
            Direction::Outgoing => write!(f, "Out"),
            Direction::Incoming => write!(f, "In"),
            Direction::Local => write!(f, "Local"),
            Direction::Internet => write!(f, "Internet"),
        }
    }
}

/// Statistics values for a tracked connection.
///
/// Currently tracks the size of traffic in bits.
#[derive(Debug, Clone)]
pub struct StatValues {
    /// Size of the traffic in bits
    pub size: u128,
    /// Last seen kernel timestamp (ns)
    pub last_timestamp: Option<u64>,
    /// Last seen TCP sequence number
    pub last_seq: Option<u32>,
    /// Last seen TCP acknowledgment number
    pub last_ack: Option<u32>,
}

/// Represents a bidirectional IP pair for connection tracking.
///
/// Used internally for aggregating statistics between pairs of IP addresses,
/// regardless of direction. The `is_local` flag indicates whether both
/// endpoints are local addresses.
#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy, PartialOrd, Ord)]
pub struct IpPair {
    /// Source IP address
    pub src_ip: Ipv4Addr,
    /// Destination IP address
    pub dst_ip: Ipv4Addr,
    /// Whether this is a local-to-local connection
    pub is_local: bool,
    /// Protocol number
    pub protocol: u8,
}

/// Full connection details including ports for display purposes.
///
/// Extends IpPair with source and destination port information,
/// allowing the UI to display service identification (e.g., ":443 → HTTPS").
#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy, PartialOrd, Ord)]
pub struct ConnectionDetails {
    /// Source IP address
    pub src_ip: Ipv4Addr,
    /// Destination IP address
    pub dst_ip: Ipv4Addr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Whether this is a local-to-local connection
    pub is_local: bool,
    /// Connection initiation direction (who initiated the connection)
    pub direction: Direction,
    /// Protocol number
    pub protocol: u8,
}

impl ConnectionDetails {
    /// Create a new ConnectionDetails from components.
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        is_local: bool,
        direction: Direction,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            is_local,
            direction,
            protocol,
        }
    }

    /// Create a ConnectionDetails from an IpPair, using ports from a StatKey.
    /// This is a convenience method when you have an IpPair but need ports.
    pub fn from_ip_pair_and_ports(pair: &IpPair, src_port: u16, dst_port: u16) -> Self {
        Self {
            src_ip: pair.src_ip,
            dst_ip: pair.dst_ip,
            src_port,
            dst_port,
            is_local: pair.is_local,
            direction: Direction::None,
            protocol: pair.protocol,
        }
    }

    /// Get the IpPair portion of this connection.
    pub fn as_ip_pair(&self) -> IpPair {
        IpPair {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            is_local: self.is_local,
            protocol: self.protocol,
        }
    }
}

impl Display for IpPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_local {
            write!(f, "{} <-> {} (local)", self.src_ip, self.dst_ip)
        } else {
            write!(f, "{} <-> {}", self.src_ip, self.dst_ip)
        }
    }
}

impl Display for ConnectionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_local {
            write!(
                f,
                "{}:{} <-> {}:{} (local)",
                self.src_ip, self.src_port, self.dst_ip, self.dst_port
            )
        } else {
            write!(
                f,
                "{}:{} <-> {}:{}",
                self.src_ip, self.src_port, self.dst_ip, self.dst_port
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stat_key_display() {
        let key = StatKey {
            src_port: 12345,
            dst_port: 443,
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(93, 184, 216, 34),
            direction: Direction::Outgoing,
            protocol: 6,
            tcp_syn: false,
            tcp_ack: false,
            tcp_fin: false,
            tcp_rst: false,
        };
        let display = format!("{}", key);
        assert!(display.contains("192.168.1.1:12345"));
        assert!(display.contains("93.184.216.34:443"));
        assert!(display.contains("Out"));
    }

    #[test]
    fn test_direction_display() {
        assert_eq!(format!("{}", Direction::None), "None");
        assert_eq!(format!("{}", Direction::Outgoing), "Out");
        assert_eq!(format!("{}", Direction::Incoming), "In");
        assert_eq!(format!("{}", Direction::Local), "Local");
        assert_eq!(format!("{}", Direction::Internet), "Internet");
    }

    #[test]
    fn test_ip_pair_display() {
        let pair = IpPair {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(192, 168, 1, 2),
            is_local: true,
            protocol: 6,
        };
        let display = format!("{}", pair);
        assert!(display.contains("local"));
    }

    #[test]
    fn test_stat_key_ord() {
        let key1 = StatKey {
            src_port: 80,
            dst_port: 443,
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(192, 168, 1, 2),
            direction: Direction::Local,
            protocol: 6,
            tcp_syn: false,
            tcp_ack: false,
            tcp_fin: false,
            tcp_rst: false,
        };
        let key2 = StatKey {
            src_port: 80,
            dst_port: 443,
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(192, 168, 1, 2),
            direction: Direction::Local,
            protocol: 6,
            tcp_syn: false,
            tcp_ack: false,
            tcp_fin: false,
            tcp_rst: false,
        };
        assert_eq!(key1, key2);
    }
}
