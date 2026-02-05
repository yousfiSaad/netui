//! Connection quality metrics tracking.
//!
//! This module provides quality scoring for TCP connections based on:
//! - Round-trip time (RTT) measurement
//! - Retransmission rate tracking
//! - Combined quality score (0-100)

use crate::stats::IpPair;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Quality metrics for a TCP connection.
#[derive(Debug, Clone)]
pub struct QualityMetrics {
    /// Round-trip time in microseconds
    pub rtt_us: u64,
    /// Number of retransmissions detected
    pub retransmissions: u32,
    /// Total packets observed
    pub total_packets: u32,
    /// Quality score (0-100, where 100 is excellent)
    pub score: u8,
    /// Last update timestamp
    pub last_update: Instant,
}

impl Default for QualityMetrics {
    fn default() -> Self {
        Self {
            rtt_us: 0,
            retransmissions: 0,
            total_packets: 0,
            score: 100, // Start with excellent quality
            last_update: Instant::now(),
        }
    }
}

impl QualityMetrics {
    /// Calculate quality score from RTT and retransmit rate.
    ///
    /// Score calculation:
    /// - RTT score: 100 at <10ms, 0 at >500ms (linear interpolation)
    /// - Retransmit score: 100 at 0%, 0 at >10%
    /// - Combined: 70% RTT + 30% retransmit
    pub fn calculate_score(rtt_us: u64, retransmit_rate: f32) -> u8 {
        // RTT score (70% weight)
        let rtt_score = if rtt_us < 10_000 {
            100.0
        } else if rtt_us > 500_000 {
            0.0
        } else {
            // Linear interpolation: 10ms → 100, 500ms → 0
            100.0 * (1.0 - ((rtt_us - 10_000) as f32 / (500_000 - 10_000) as f32))
        };

        // Retransmit score (30% weight)
        let retrans_score = if retransmit_rate < 0.01 {
            100.0
        } else if retransmit_rate > 0.10 {
            0.0
        } else {
            // Linear interpolation: 1% → 100, 10% → 0
            100.0 * (1.0 - ((retransmit_rate - 0.01) / (0.10 - 0.01)))
        };

        // Weighted combination
        let score = (rtt_score * 0.7 + retrans_score * 0.3).clamp(0.0, 100.0);
        score as u8
    }

    /// Update the quality score based on current metrics.
    pub fn update_score(&mut self) {
        let retransmit_rate = if self.total_packets > 0 {
            (self.retransmissions as f32) / (self.total_packets as f32)
        } else {
            0.0
        };
        self.score = Self::calculate_score(self.rtt_us, retransmit_rate);
    }

    /// Get the RTT in milliseconds (for display).
    pub fn rtt_ms(&self) -> f64 {
        self.rtt_us as f64 / 1000.0
    }

    /// Get the retransmit rate as a percentage (for display).
    pub fn retransmit_rate(&self) -> f64 {
        if self.total_packets > 0 {
            ((self.retransmissions as f64) / (self.total_packets as f64)) * 100.0
        } else {
            0.0
        }
    }

    /// Get the quality bar as a string of █ and ░ characters.
    ///
    /// Returns a string like "████████░░" for 80% quality.
    pub fn quality_bar(&self) -> String {
        let filled = (self.score as usize / 10).min(10);
        let empty = 10 - filled;
        format!("{}{}", "█".repeat(filled), "░".repeat(empty))
    }
}

/// Tracks connection quality metrics (RTT, retransmits, score).
///
/// Uses TCP sequence numbers and timestamps to estimate RTT and detect retransmissions.
pub struct QualityTracker {
    /// Quality metrics per connection
    metrics: HashMap<IpPair, QualityMetrics>,
    /// Last seen sequence numbers (for retransmit detection)
    sequences: HashMap<IpPair, HashSet<u32>>,
    /// Last seen timestamps (for RTT calculation)
    last_seen: HashMap<IpPair, u64>,
    /// Timeout for stale data removal
    timeout: Duration,
}

impl Default for QualityTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl QualityTracker {
    /// Create a new quality tracker.
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            sequences: HashMap::new(),
            last_seen: HashMap::new(),
            timeout: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a new quality tracker with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            metrics: HashMap::new(),
            sequences: HashMap::new(),
            last_seen: HashMap::new(),
            timeout,
        }
    }

    /// Update quality metrics for a connection based on a new packet.
    ///
    /// # Arguments
    /// * `pair` - The IP pair identifying the connection
    /// * `timestamp_ns` - Kernel timestamp when packet was captured
    /// * `seq` - TCP sequence number (for retransmit detection)
    /// * `ack` - TCP acknowledgment number (for RTT calculation)
    pub fn update(&mut self, pair: IpPair, timestamp_ns: u64, seq: u32, _ack: u32) {
        let now = Instant::now();
        // Note: We need clone() here because entry() takes ownership of the key
        // and we need to use pair twice. Since IpPair: Copy, this is just a memcpy.
        let metrics = self.metrics.entry(pair).or_default();

        // Track sequence numbers for retransmit detection
        let seq_set = self.sequences.entry(pair.clone()).or_default();
        let is_retransmit = seq_set.contains(&seq);
        seq_set.insert(seq);

        // Limit sequence tracking to prevent unbounded growth
        if seq_set.len() > 100 {
            // Remove oldest entries (simplified - just clear half)
            let old_len = seq_set.len() / 2;
            let mut temp_set = HashSet::new();
            for (i, &s) in seq_set.iter().enumerate() {
                if i >= old_len {
                    temp_set.insert(s);
                }
            }
            *seq_set = temp_set;
        }

        // Update metrics
        metrics.total_packets += 1;
        if is_retransmit {
            metrics.retransmissions += 1;
        }

        // RTT calculation: if we've seen this pair before, calculate time difference
        if let Some(&last_timestamp) = self.last_seen.get(&pair) {
            let rtt_ns = timestamp_ns.saturating_sub(last_timestamp);
            // Update RTT using exponential moving average (smoothing factor 0.1)
            if metrics.rtt_us == 0 {
                metrics.rtt_us = rtt_ns / 1000; // Convert to microseconds
            } else {
                metrics.rtt_us = (metrics.rtt_us * 9 + rtt_ns / 1000) / 10;
            }
        }

        metrics.last_update = now;
        metrics.update_score();

        self.last_seen.insert(pair, timestamp_ns);
    }

    /// Get quality metrics for a connection.
    pub fn get(&self, pair: &IpPair) -> Option<&QualityMetrics> {
        self.metrics.get(pair)
    }

    /// Get all quality metrics.
    pub fn all(&self) -> &HashMap<IpPair, QualityMetrics> {
        &self.metrics
    }

    /// Prune stale connections that haven't been updated within the timeout period.
    pub fn prune_stale(&mut self) {
        let now = Instant::now();
        let to_remove: Vec<IpPair> = self
            .metrics
            .iter()
            .filter(|(_, m)| now.duration_since(m.last_update) > self.timeout)
            .map(|(pair, _)| *pair)
            .collect();

        for pair in to_remove {
            self.metrics.remove(&pair);
            self.sequences.remove(&pair);
            self.last_seen.remove(&pair);
        }
    }

    /// Get the number of tracked connections.
    pub fn len(&self) -> usize {
        self.metrics.len()
    }

    /// Check if no connections are being tracked.
    pub fn is_empty(&self) -> bool {
        self.metrics.is_empty()
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
    fn test_quality_metrics_default() {
        let m = QualityMetrics::default();
        assert_eq!(m.rtt_us, 0);
        assert_eq!(m.retransmissions, 0);
        assert_eq!(m.total_packets, 0);
        assert_eq!(m.score, 100);
    }

    #[test]
    fn test_calculate_score_perfect() {
        let score = QualityMetrics::calculate_score(5000, 0.0);
        assert_eq!(score, 100);
    }

    #[test]
    fn test_calculate_score_poor() {
        let score = QualityMetrics::calculate_score(600_000, 0.15);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_calculate_score_mixed() {
        // 100ms RTT (moderate), 5% retransmit (moderate-poor)
        let score = QualityMetrics::calculate_score(100_000, 0.05);
        assert!(score > 0 && score < 100);
    }

    #[test]
    fn test_quality_bar() {
        let mut m = QualityMetrics {
            score: 80,
            ..Default::default()
        };
        assert_eq!(m.quality_bar(), "████████░░");

        m.score = 30;
        assert_eq!(m.quality_bar(), "███░░░░░░░");
    }

    #[test]
    fn test_tracker_update() {
        let mut tracker = QualityTracker::new();
        let pair = ip_pair(1, 2);

        // First packet
        tracker.update(pair, 1_000_000_000, 1000, 0);
        assert_eq!(tracker.get(&pair).unwrap().total_packets, 1);

        // Second packet (no retransmit)
        tracker.update(pair, 1_000_050_000, 1001, 0);
        assert_eq!(tracker.get(&pair).unwrap().rtt_us, 50); // 50us RTT

        // Third packet (simulated retransmit - same sequence)
        tracker.update(pair, 1_000_100_000, 1000, 0);
        assert_eq!(tracker.get(&pair).unwrap().retransmissions, 1);
    }

    #[test]
    fn test_tracker_prune_stale() {
        let mut tracker = QualityTracker::with_timeout(Duration::from_millis(100));
        let pair = ip_pair(1, 2);

        tracker.update(pair, 1_000_000_000, 1000, 0);
        assert_eq!(tracker.len(), 1);

        std::thread::sleep(Duration::from_millis(150));
        tracker.prune_stale();
        assert_eq!(tracker.len(), 0);
    }
}
