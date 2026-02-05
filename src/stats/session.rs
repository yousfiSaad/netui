//! Session statistics tracking cumulative data transfer.
//!
//! This module provides the `SessionStats` struct for tracking cumulative
//! network traffic statistics since the monitoring session started.

use std::fmt::Display;
use std::time::Instant;

/// Session statistics tracking cumulative data transfer since start.
#[derive(Debug, Clone)]
pub struct SessionStats {
    /// Time when the session started
    pub start_time: Instant,
    /// Total bits downloaded since session start
    pub total_bits_down: u128,
    /// Total bits uploaded since session start
    pub total_bits_up: u128,
}

impl Default for SessionStats {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            total_bits_down: 0,
            total_bits_up: 0,
        }
    }
}

impl SessionStats {
    /// Create a new SessionStats with the current time as start time.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new SessionStats with a specific start time.
    pub fn with_start_time(start_time: Instant) -> Self {
        Self {
            start_time,
            total_bits_down: 0,
            total_bits_up: 0,
        }
    }

    /// Add download traffic to the session totals.
    pub fn add_download(&mut self, bits: u128) {
        self.total_bits_down += bits;
    }

    /// Add upload traffic to the session totals.
    pub fn add_upload(&mut self, bits: u128) {
        self.total_bits_up += bits;
    }

    /// Get the session duration as a Duration.
    pub fn duration(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Format a summary of the session statistics.
    ///
    /// Returns a human-readable string showing total data transferred
    /// and the session duration.
    ///
    /// # Examples
    /// ```rust
    /// use netui::stats::SessionStats;
    ///
    /// let stats = SessionStats::new();
    /// // ... after some activity ...
    /// let summary = stats.format_summary();
    /// // e.g., "Session: ↓ 12.34 MiB | ↑ 5.67 MiB | 2m"
    /// ```
    pub fn format_summary(&self) -> String {
        let duration = self.duration();
        let seconds = duration.as_secs();

        // Convert bits to mebibytes for display
        let down_mib = (self.total_bits_down as f64) / (8.0 * 1024.0 * 1024.0);
        let up_mib = (self.total_bits_up as f64) / (8.0 * 1024.0 * 1024.0);

        if seconds < 60 {
            format!(
                "Session: ↓ {:.2} MiB | ↑ {:.2} MiB | {}s",
                down_mib, up_mib, seconds
            )
        } else {
            let minutes = seconds / 60;
            format!(
                "Session: ↓ {:.2} MiB | ↑ {:.2} MiB | {}m",
                down_mib, up_mib, minutes
            )
        }
    }

    /// Get the total bits downloaded in bytes.
    pub fn total_bytes_down(&self) -> u128 {
        self.total_bits_down / 8
    }

    /// Get the total bits uploaded in bytes.
    pub fn total_bytes_up(&self) -> u128 {
        self.total_bits_up / 8
    }
}

impl Display for SessionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format_summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_stats_default() {
        let stats = SessionStats::default();
        assert_eq!(stats.total_bits_down, 0);
        assert_eq!(stats.total_bits_up, 0);
    }

    #[test]
    fn test_session_stats_new() {
        let stats = SessionStats::new();
        assert_eq!(stats.total_bits_down, 0);
        assert_eq!(stats.total_bits_up, 0);
        // Duration should be very small
        assert!(stats.duration().as_secs() < 1);
    }

    #[test]
    fn test_add_download() {
        let mut stats = SessionStats::new();
        stats.add_download(1000);
        assert_eq!(stats.total_bits_down, 1000);
        assert_eq!(stats.total_bytes_down(), 125);
    }

    #[test]
    fn test_add_upload() {
        let mut stats = SessionStats::new();
        stats.add_upload(500);
        assert_eq!(stats.total_bits_up, 500);
        assert_eq!(stats.total_bytes_up(), 62);
    }

    #[test]
    fn test_format_summary_empty() {
        let stats = SessionStats::new();
        let summary = stats.format_summary();
        assert!(summary.contains("Session:"));
        assert!(summary.contains("↓ 0.00 MiB"));
        assert!(summary.contains("↑ 0.00 MiB"));
        assert!(summary.contains("s")); // seconds
    }

    #[test]
    fn test_format_summary_with_data() {
        let mut stats = SessionStats::new();
        // Add ~1 MiB of data
        stats.add_download(8 * 1024 * 1024);
        stats.add_upload(4 * 1024 * 1024);
        let summary = stats.format_summary();
        assert!(summary.contains("↓ 1.00 MiB"));
        assert!(summary.contains("↑ 0.50 MiB"));
    }

    #[test]
    fn test_session_stats_display() {
        let stats = SessionStats::new();
        let display = format!("{}", stats);
        assert!(display.contains("Session:"));
    }
}
