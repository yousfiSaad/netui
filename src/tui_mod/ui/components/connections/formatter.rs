//! Data formatting utilities for the connections view.
//!
//! This module contains pure functions for formatting various data types
//! displayed in the connections table.

use std::time::Duration;

use netui::constants::{IP_TRUNCATE_AT, MAX_IP_DISPLAY_LENGTH};
use netui::stats::Direction;

/// Format a connection age duration as a compact string.
///
/// Returns: "45s" for < 1 minute, "5m 23s" for < 1 hour, "1h 05m" for >= 1 hour
pub fn format_age(age: Duration) -> String {
    let secs = age.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Determine the direction arrow based on input/output speeds.
///
/// Returns "↓" for mostly download, "↑" for mostly upload, "↔" for bidirectional
pub fn direction_arrow(speed_input: u128, speed_output: u128) -> &'static str {
    if speed_input > speed_output * 10 {
        "↓"
    } else if speed_output > speed_input * 10 {
        "↑"
    } else {
        "↔"
    }
}

/// Determine the connection initiation direction arrow.
///
/// Returns "→" for outgoing connections (your device initiated),
/// "←" for incoming connections (remote device initiated),
/// "↔" for local-to-local connections,
/// "INET" for Internet (through gateway) connections,
/// "?" for unknown direction
pub fn initiation_arrow(direction: Direction) -> &'static str {
    match direction {
        Direction::Outgoing => "→",
        Direction::Incoming => "←",
        Direction::Local => "↔",
        Direction::Internet => "INET",
        Direction::None => "?",
    }
}

/// Format local endpoint with port (truncates port if too long).
pub fn format_local_endpoint(ip: &str, port: u16) -> String {
    // Truncate IP for very long addresses (IPv6 or complex display)
    let ip_short = if ip.len() > MAX_IP_DISPLAY_LENGTH && ip.len() >= IP_TRUNCATE_AT + 2 {
        format!("{}..", &ip[..IP_TRUNCATE_AT])
    } else {
        ip.to_string()
    };
    format!("{}:{}", ip_short, port)
}

/// Format remote endpoint with port and app name.
pub fn format_remote_endpoint(ip: &str, port: u16, app_name: Option<&str>, width: usize) -> String {
    let ip_short = if ip.len() > MAX_IP_DISPLAY_LENGTH && ip.len() >= IP_TRUNCATE_AT + 2 {
        format!("{}..", &ip[..IP_TRUNCATE_AT])
    } else {
        ip.to_string()
    };

    let app_display = if let Some(app) = app_name {
        format!(" ({})", app)
    } else {
        String::new()
    };

    let full = format!("{}:{}{}", ip_short, port, app_display);

    // Truncate if too long for column
    if full.len() > width && width >= 3 {
        format!("{}..", &full[..width - 2])
    } else {
        full
    }
}
