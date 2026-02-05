//! Speed calculation and formatting utilities.
//!
//! This module provides the `Speed` struct for tracking bidirectional
//! bandwidth (input/output) and formatting utilities for human-readable display.

use std::fmt::Display;
use std::ops::{Add, AddAssign, Div};

/// Bidirectional speed tracking (input and output).
///
/// Speed is measured in bits per second. The `input` field represents
/// download/incoming traffic, while `output` represents upload/outgoing traffic.
#[derive(Default, Debug, Clone, Copy)]
pub struct Speed {
    /// Output/upload speed in bits per second
    pub output: u128,
    /// Input/download speed in bits per second
    pub input: u128,
}

impl Speed {
    /// Create a new Speed with the given input and output values.
    pub const fn new(input: u128, output: u128) -> Self {
        Self { input, output }
    }

    /// Format the input speed as a human-readable string (e.g., "12.3 MiB/s").
    pub fn to_string_input(&self) -> String {
        format_size(self.input)
    }

    /// Format the output speed as a human-readable string (e.g., "5.4 MiB/s").
    pub fn to_string_output(&self) -> String {
        format_size(self.output)
    }
}

impl Add for Speed {
    type Output = Speed;

    fn add(self, rhs: Self) -> Self::Output {
        Speed {
            input: self.input + rhs.input,
            output: self.output + rhs.output,
        }
    }
}

impl AddAssign for Speed {
    fn add_assign(&mut self, rhs: Self) {
        self.input += rhs.input;
        self.output += rhs.output;
    }
}

impl Div<u128> for Speed {
    type Output = Speed;

    fn div(self, rhs: u128) -> Self::Output {
        Speed {
            input: self.input / rhs,
            output: self.output / rhs,
        }
    }
}

impl Display for Speed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "↓ {} | ↑ {}",
            format_size(self.input),
            format_size(self.output)
        )
    }
}

/// Format a bit rate as a human-readable string in Bytes/s.
///
/// The output uses IEC binary prefixes (KiB, MiB) with base-1024 units,
/// converting the input bits to bytes (divide by 8):
/// - B/s: values < 1024 bytes
/// - KiB/s: values >= 1024 bytes and < 1,048,576 bytes
/// - MiB/s: values >= 1,048,576 bytes
/// - GiB/s: values >= 1,073,741,824 bytes
///
/// # Arguments
/// * `bits` - The bit rate to format (in bits per second)
///
/// # Returns
/// A formatted string with the value and appropriate unit
///
/// # Examples
/// ```rust
/// use netui::stats::format_size;
///
/// // 8000 bits = 1000 bytes
/// assert_eq!(format_size(8000), "1000.00 B/s");
/// // 16384 bits = 2048 bytes = 2 KiB
/// assert_eq!(format_size(16384), "2.00 KiB/s");
/// ```
pub fn format_size(bits: u128) -> String {
    // Convert bits to bytes
    let bytes = bits as f64 / 8.0;
    const UNIT_1024: f64 = 1024.0;

    if bytes < UNIT_1024 {
        return format!("{:.2} B/s", bytes);
    }

    let kib = bytes / UNIT_1024;
    if kib < UNIT_1024 {
        return format!("{:.2} KiB/s", kib);
    }

    let mib = kib / UNIT_1024;
    if mib < UNIT_1024 {
        return format!("{:.2} MiB/s", mib);
    }

    let gib = mib / UNIT_1024;
    format!("{:.2} GiB/s", gib)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speed_default() {
        let speed = Speed::default();
        assert_eq!(speed.input, 0);
        assert_eq!(speed.output, 0);
    }

    #[test]
    fn test_speed_new() {
        let speed = Speed::new(1000, 2000);
        assert_eq!(speed.input, 1000);
        assert_eq!(speed.output, 2000);
    }

    #[test]
    fn test_speed_add() {
        let a = Speed::new(100, 200);
        let b = Speed::new(50, 75);
        let sum = a + b;
        assert_eq!(sum.input, 150);
        assert_eq!(sum.output, 275);
    }

    #[test]
    fn test_speed_add_assign() {
        let mut speed = Speed::new(100, 200);
        speed += Speed::new(50, 75);
        assert_eq!(speed.input, 150);
        assert_eq!(speed.output, 275);
    }

    #[test]
    fn test_speed_div() {
        let speed = Speed::new(1000, 2000);
        let result = speed / 2;
        assert_eq!(result.input, 500);
        assert_eq!(result.output, 1000);
    }

    #[test]
    fn test_speed_display() {
        // 2 MiB = 2 * 1024 * 1024 bytes = 16,777,216 bits
        let mib_2_bits = 16_777_216;
        // 1 MiB = 1 * 1024 * 1024 bytes = 8,388,608 bits
        let mib_1_bits = 8_388_608;

        let speed = Speed::new(mib_2_bits, mib_1_bits);
        let display = format!("{}", speed);
        assert!(display.contains("2.00 MiB/s"));
        assert!(display.contains("1.00 MiB/s"));
        assert!(display.contains("↓"));
        assert!(display.contains("↑"));
    }

    #[test]
    fn test_format_size_bytes() {
        // 8 bits = 1 byte
        assert_eq!(format_size(8), "1.00 B/s");
        // 8000 bits = 1000 bytes
        assert_eq!(format_size(8000), "1000.00 B/s");
    }

    #[test]
    fn test_format_size_kib() {
        // 1 KiB = 1024 bytes = 8192 bits
        assert_eq!(format_size(8192), "1.00 KiB/s");
        // 2 KiB = 2048 bytes = 16384 bits
        assert_eq!(format_size(16384), "2.00 KiB/s");
    }

    #[test]
    fn test_format_size_mib() {
        // 1 MiB = 1024 KiB = 1,048,576 bytes = 8,388,608 bits
        assert_eq!(format_size(8_388_608), "1.00 MiB/s");
    }

    #[test]
    fn test_format_size_gib() {
        // 1 GiB = 1024 MiB = 1,073,741,824 bytes = 8,589,934,592 bits
        assert_eq!(format_size(8_589_934_592), "1.00 GiB/s");
    }

    #[test]
    fn test_speed_to_string_input() {
        // 2 MiB input
        let speed = Speed::new(16_777_216, 0);
        assert_eq!(speed.to_string_input(), "2.00 MiB/s");
    }

    #[test]
    fn test_speed_to_string_output() {
        // 1 MiB output
        let speed = Speed::new(0, 8_388_608);
        assert_eq!(speed.to_string_output(), "1.00 MiB/s");
    }
}
