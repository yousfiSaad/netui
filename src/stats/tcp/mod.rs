//! TCP connection state tracking.
//!
//! This module provides TCP state machine logic for tracking connection
//! states (SYN_SENT, ESTABLISHED, FIN_WAIT, etc.) based on TCP flags.

mod state;
mod tracker;

pub use state::TcpState;
pub use tracker::TcpStateTracker;
