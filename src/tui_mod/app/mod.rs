//! Main application module.
//!
//! This module coordinates all application functionality through
//! focused sub-modules, following the Single Responsibility Principle.

mod cleanup;
mod events;
mod hosts;
mod navigation;
mod security;
mod state;

// Re-export the main App struct and ViewMode enum
pub use events::{SpeedDisplayMode, ViewMode};
pub use state::App;
