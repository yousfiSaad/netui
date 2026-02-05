//! Backward compatibility module for buffer constants.
//! Re-exports stats-related buffer constants from parent module.

pub use super::{
    DEFAULT_STATS_KEYS_BUFFER_SIZE, DEFAULT_STATS_WINDOW_SIZE, MAX_CONSECUTIVE_ERRORS,
    PERF_PACKET_BUFFER_CAPACITY,
};
