//! Connection quality assessment thresholds.

/// RTT threshold (microseconds) for excellent quality
pub const RTT_EXCELLENT_US: u64 = 10_000;

/// RTT threshold (microseconds) for poor quality
pub const RTT_POOR_US: u64 = 500_000;

/// Retransmission rate threshold for excellent quality (as ratio)
pub const RETRANSMIT_EXCELLENT: f32 = 0.01;

/// Retransmission rate threshold for poor quality (as ratio)
pub const RETRANSMIT_POOR: f32 = 0.10;

/// Weight factor for RTT in quality calculation (0.0-1.0)
pub const RTT_WEIGHT: f32 = 0.7;

/// Weight factor for retransmission in quality calculation (0.0-1.0)
pub const RETRANSMIT_WEIGHT: f32 = 0.3;
