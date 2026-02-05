//! Statistics and timing constants.

/// Delay between ARP scan requests in milliseconds
/// This non-standard delay helps avoid flooding the network
pub const ARP_SCAN_DELAY_MS: u64 = 37;

/// Interval between stats aggregation ticks in seconds
pub const STATS_TICK_INTERVAL_SECS: u64 = 1;

/// Delay before retrying when packet reader encounters an error
pub const READER_ERROR_RETRY_DELAY_MS: u64 = 100;

/// Default window size for stats aggregation (number of samples)
pub const DEFAULT_STATS_WINDOW_SIZE: usize = 10;

/// Default buffer size for stat keys
pub const DEFAULT_STATS_KEYS_BUFFER_SIZE: usize = 100;

/// Buffer capacity for perf packet reads
/// Increased from 10 to 256 to reduce syscalls and improve throughput (~10% gain)
pub const PERF_PACKET_BUFFER_CAPACITY: usize = 256;

/// Maximum consecutive errors before giving up on a packet reader
pub const MAX_CONSECUTIVE_ERRORS: u32 = 10;
