//! Statistics aggregation and formatting modules.
//!
//! This module provides types and utilities for collecting, aggregating,
//! and displaying network statistics including bandwidth, ports, and sessions.

pub mod aggregation;
pub mod aggregator;
pub mod apps;
pub mod pairs;
pub mod ports;
pub mod quality;
pub mod registry;
pub mod session;
pub mod speed;
pub mod tcp;
pub mod types;

pub use aggregation::{aggregate_by_app, AppStats, DirectionalAggregation};
pub use aggregator::StatsAggregator;
pub use apps::AppRegistry;
pub use pairs::{format_connections, update_pairs_stats_buffer, PairStatMap};
pub use ports::{format_port_stats, top_ports_all, top_ports_per_host, PortStats};
pub use quality::{QualityMetrics, QualityTracker};
pub use registry::AppRegistry as Registry;
pub use session::SessionStats;
pub use speed::{format_size, Speed};
pub use tcp::{TcpState, TcpStateTracker};
pub use types::{
    ConnectionDetails, Direction, IpPair, SpeedAccumulator, StatItem, StatKey, StatValues, StatsMap, TimedSpeed,
};
