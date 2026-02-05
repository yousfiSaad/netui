//! Task lifecycle management for the scanner.
//!
//! This module provides functions for spawning background tasks
//! for packet listening, stats aggregation, and packet transmission.

pub mod listener_task;
pub mod stats_task;
pub mod tx_task;

pub use listener_task::start_listening;
pub use stats_task::spawn_stats_aggregator;
pub use tx_task::start_tx_worker;
