//! Utility modules for common operations.
//!
//! This module contains reusable utilities that are shared across
//! the codebase to reduce duplication and improve maintainability.

pub mod mutex;

pub use mutex::recover_or_log;
