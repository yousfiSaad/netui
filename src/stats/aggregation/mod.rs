//! Aggregation utilities for statistics processing.
//!
//! This module provides traits and implementations for aggregating
//! network statistics by various dimensions (direction, application, etc.).

pub mod app;

pub use app::{aggregate_by_app, AppStats};

use crate::stats::{Direction, Speed};

/// Trait for types that can aggregate values by network direction.
///
/// This trait encapsulates the common pattern of adding a value to a
/// speed based on the traffic direction, eliminating duplicate match
/// expressions across the codebase.
pub trait DirectionalAggregation {
    /// Add a value to this speed based on the traffic direction.
    ///
    /// # Arguments
    /// * `size` - The value to add (e.g., packet size in bits)
    /// * `direction` - The traffic direction
    ///
    /// # Behavior
    /// - `Direction::Incoming`: Adds to input
    /// - `Direction::Outgoing`: Adds to output
    /// - `Direction::Internet`: Adds to output (treated as upload)
    /// - `Direction::Local`: Adds to both input and output
    /// - `Direction::None`: No change
    fn add_directional(&mut self, size: u128, direction: Direction);
}

impl DirectionalAggregation for Speed {
    fn add_directional(&mut self, size: u128, direction: Direction) {
        match direction {
            Direction::Incoming => {
                self.input += size;
            }
            Direction::Outgoing => {
                self.output += size;
            }
            Direction::Internet => {
                // Internet traffic: treat as outgoing (upload to gateway)
                self.output += size;
            }
            Direction::Local => {
                // Local traffic: count in both directions
                self.input += size;
                self.output += size;
            }
            Direction::None => {
                // Unknown direction: no change
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directional_aggregation_incoming() {
        let mut speed = Speed::default();
        speed.add_directional(1000, Direction::Incoming);
        assert_eq!(speed.input, 1000);
        assert_eq!(speed.output, 0);
    }

    #[test]
    fn test_directional_aggregation_outgoing() {
        let mut speed = Speed::default();
        speed.add_directional(1000, Direction::Outgoing);
        assert_eq!(speed.input, 0);
        assert_eq!(speed.output, 1000);
    }

    #[test]
    fn test_directional_aggregation_internet() {
        let mut speed = Speed::default();
        speed.add_directional(1000, Direction::Internet);
        assert_eq!(speed.input, 0);
        assert_eq!(speed.output, 1000);
    }

    #[test]
    fn test_directional_aggregation_local() {
        let mut speed = Speed::default();
        speed.add_directional(1000, Direction::Local);
        assert_eq!(speed.input, 1000);
        assert_eq!(speed.output, 1000);
    }

    #[test]
    fn test_directional_aggregation_none() {
        let mut speed = Speed::default();
        speed.add_directional(1000, Direction::None);
        assert_eq!(speed.input, 0);
        assert_eq!(speed.output, 0);
    }

    #[test]
    fn test_directional_aggregation_mixed() {
        let mut speed = Speed::default();
        speed.add_directional(1000, Direction::Incoming);
        speed.add_directional(500, Direction::Outgoing);
        speed.add_directional(200, Direction::Local);
        assert_eq!(speed.input, 1200); // 1000 + 200
        assert_eq!(speed.output, 700); // 500 + 200
    }
}
