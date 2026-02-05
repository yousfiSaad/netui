//! Helper functions for statistics aggregation.
//!
//! This module provides reusable aggregation functions used across
//! the statistics aggregator, eliminating code duplication.

use crate::stats::Speed;
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Aggregate peak speed per host from a buffer of per-host speed maps.
///
/// For each host, this function finds the maximum input and output speeds
/// across all samples in the buffer.
///
/// # Arguments
/// * `hosts_buffer` - Iterator over references to HashMaps mapping IP addresses to Speed values
///
/// # Returns
/// A HashMap mapping each IP address to its peak speed
///
/// # Example
/// ```rust
/// use std::collections::HashMap;
/// use std::net::Ipv4Addr;
/// use netui::stats::Speed;
/// use netui::stats::aggregator::helpers::aggregate_peak_speed;
///
/// let mut buffer = vec![];
/// let mut map1 = HashMap::new();
/// map1.insert(Ipv4Addr::new(192, 168, 1, 1), Speed::new(1000, 500));
/// buffer.push(map1);
///
/// let mut map2 = HashMap::new();
/// map2.insert(Ipv4Addr::new(192, 168, 1, 1), Speed::new(2000, 1000));
/// buffer.push(map2);
///
/// let peaks = aggregate_peak_speed(buffer.iter());
/// assert_eq!(peaks[&Ipv4Addr::new(192, 168, 1, 1)].input, 2000);
/// ```
pub fn aggregate_peak_speed<'a, I>(hosts_buffer: I) -> HashMap<Ipv4Addr, Speed>
where
    I: Iterator<Item = &'a HashMap<Ipv4Addr, Speed>>,
{
    let mut peak_speeds: HashMap<Ipv4Addr, Speed> = Default::default();

    hosts_buffer.for_each(|pair| {
        pair.iter().for_each(|(ip, speed)| {
            peak_speeds
                .entry(*ip)
                .and_modify(|s| {
                    if speed.input > s.input {
                        s.input = speed.input;
                    }
                    if speed.output > s.output {
                        s.output = speed.output;
                    }
                })
                .or_insert(*speed);
        });
    });

    peak_speeds
}

/// Aggregate sum speed per host from a buffer of per-host speed maps.
///
/// For each host, this function sums all the speed values across all samples
/// in the buffer and calculates the average.
///
/// # Arguments
/// * `hosts_buffer` - Iterator over references to HashMaps mapping IP addresses to Speed values
///
/// # Returns
/// A HashMap mapping each IP address to the average of its speeds
///
/// # Note
/// **DEPRECATED**: This function uses count-based averaging instead of time-weighted averaging.
/// This can produce incorrect results when tick intervals vary. Use time-weighted aggregation
/// functions (like those using `SpeedAccumulator`) for accurate results.
///
/// This function is kept for backward compatibility but should be replaced with
/// time-weighted averaging in future versions.
///
/// # Example
/// ```rust
/// use std::collections::HashMap;
/// use std::net::Ipv4Addr;
/// use netui::stats::Speed;
/// use netui::stats::aggregator::helpers::aggregate_sum_speed;
///
/// let mut buffer = vec![];
/// let mut map1 = HashMap::new();
/// map1.insert(Ipv4Addr::new(192, 168, 1, 1), Speed::new(1000, 500));
/// buffer.push(map1);
///
/// let mut map2 = HashMap::new();
/// map2.insert(Ipv4Addr::new(192, 168, 1, 1), Speed::new(2000, 1000));
/// buffer.push(map2);
///
/// let sums = aggregate_sum_speed(buffer.iter());
/// assert_eq!(sums[&Ipv4Addr::new(192, 168, 1, 1)].input, 1500); // (1000+2000)/2
/// assert_eq!(sums[&Ipv4Addr::new(192, 168, 1, 1)].output, 750); // (500+1000)/2
/// ```
#[deprecated(
    since = "0.2.0",
    note = "Use time-weighted averaging with SpeedAccumulator instead"
)]
pub fn aggregate_sum_speed<'a, I>(hosts_buffer: I) -> HashMap<Ipv4Addr, Speed>
where
    I: Iterator<Item = &'a HashMap<Ipv4Addr, Speed>>,
{
    let mut speed_and_count: HashMap<Ipv4Addr, (Speed, u8)> = Default::default();

    hosts_buffer.for_each(|pair| {
        pair.iter().for_each(|(ip, speed)| {
            speed_and_count
                .entry(*ip)
                .and_modify(|(s, n)| {
                    *s += *speed;
                    *n += 1
                })
                .or_insert((*speed, 1));
        });
    });

    // Calculate average speed for each host
    let mut average_speeds: HashMap<Ipv4Addr, Speed> = Default::default();
    speed_and_count.iter().for_each(|(ip, (speed, n))| {
        average_speeds.insert(*ip, *speed / (*n as u128));
    });
    average_speeds
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;

    // Helper macro for IP address creation in tests
    macro_rules! ip {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            std::net::Ipv4Addr::new($a, $b, $c, $d)
        };
    }

    #[test]
    fn test_aggregate_peak_speed_empty() {
        let buffer: Vec<HashMap<Ipv4Addr, Speed>> = vec![];
        let result = aggregate_peak_speed(buffer.iter());
        assert!(result.is_empty());
    }

    #[test]
    fn test_aggregate_peak_speed_single_entry() {
        let mut buffer = vec![];
        let mut map = HashMap::new();
        map.insert(ip!(192, 168, 1, 1), Speed::new(1000, 500));
        buffer.push(map);

        let result = aggregate_peak_speed(buffer.iter());
        assert_eq!(result.len(), 1);
        assert_eq!(result[&ip!(192, 168, 1, 1)].input, 1000);
        assert_eq!(result[&ip!(192, 168, 1, 1)].output, 500);
    }

    #[test]
    fn test_aggregate_peak_speed_multiple_samples() {
        let mut buffer = vec![];
        let mut map1 = HashMap::new();
        map1.insert(ip!(192, 168, 1, 1), Speed::new(1000, 500));
        buffer.push(map1);

        let mut map2 = HashMap::new();
        map2.insert(ip!(192, 168, 1, 1), Speed::new(2000, 1000));
        buffer.push(map2);

        let mut map3 = HashMap::new();
        map3.insert(ip!(192, 168, 1, 1), Speed::new(1500, 750));
        buffer.push(map3);

        let result = aggregate_peak_speed(buffer.iter());
        assert_eq!(result[&ip!(192, 168, 1, 1)].input, 2000); // max input
        assert_eq!(result[&ip!(192, 168, 1, 1)].output, 1000); // max output
    }

    #[test]
    fn test_aggregate_peak_speed_multiple_hosts() {
        let mut buffer = vec![];
        let mut map1 = HashMap::new();
        map1.insert(ip!(192, 168, 1, 1), Speed::new(1000, 500));
        map1.insert(ip!(192, 168, 1, 2), Speed::new(2000, 1500));
        buffer.push(map1);

        let mut map2 = HashMap::new();
        map2.insert(ip!(192, 168, 1, 1), Speed::new(3000, 1000));
        map2.insert(ip!(192, 168, 1, 2), Speed::new(500, 250));
        buffer.push(map2);

        let result = aggregate_peak_speed(buffer.iter());
        assert_eq!(result[&ip!(192, 168, 1, 1)].input, 3000);
        assert_eq!(result[&ip!(192, 168, 1, 1)].output, 1000);
        assert_eq!(result[&ip!(192, 168, 1, 2)].input, 2000);
        assert_eq!(result[&ip!(192, 168, 1, 2)].output, 1500);
    }

    #[test]
    fn test_aggregate_sum_speed_empty() {
        let buffer: Vec<HashMap<Ipv4Addr, Speed>> = vec![];
        let result = aggregate_sum_speed(buffer.iter());
        assert!(result.is_empty());
    }

    #[test]
    fn test_aggregate_sum_speed_single_entry() {
        let mut buffer = vec![];
        let mut map = HashMap::new();
        map.insert(ip!(192, 168, 1, 1), Speed::new(1000, 500));
        buffer.push(map);

        let result = aggregate_sum_speed(buffer.iter());
        assert_eq!(result.len(), 1);
        assert_eq!(result[&ip!(192, 168, 1, 1)].input, 1000);
        assert_eq!(result[&ip!(192, 168, 1, 1)].output, 500);
    }

    #[test]
    fn test_aggregate_sum_speed_multiple_samples() {
        let mut buffer = vec![];
        let mut map1 = HashMap::new();
        map1.insert(ip!(192, 168, 1, 1), Speed::new(1000, 500));
        buffer.push(map1);

        let mut map2 = HashMap::new();
        map2.insert(ip!(192, 168, 1, 1), Speed::new(2000, 1000));
        buffer.push(map2);

        let result = aggregate_sum_speed(buffer.iter());
        // Average: (1000+2000)/2 = 1500 input, (500+1000)/2 = 750 output
        assert_eq!(result[&ip!(192, 168, 1, 1)].input, 1500);
        assert_eq!(result[&ip!(192, 168, 1, 1)].output, 750);
    }

    #[test]
    fn test_aggregate_sum_speed_multiple_hosts() {
        let mut buffer = vec![];
        let mut map1 = HashMap::new();
        map1.insert(ip!(192, 168, 1, 1), Speed::new(1000, 500));
        map1.insert(ip!(192, 168, 1, 2), Speed::new(2000, 1500));
        buffer.push(map1);

        let mut map2 = HashMap::new();
        map2.insert(ip!(192, 168, 1, 1), Speed::new(3000, 1000));
        map2.insert(ip!(192, 168, 1, 2), Speed::new(500, 250));
        buffer.push(map2);

        let result = aggregate_sum_speed(buffer.iter());
        // Host 1: (1000+3000)/2 = 2000 input, (500+1000)/2 = 750 output
        assert_eq!(result[&ip!(192, 168, 1, 1)].input, 2000);
        assert_eq!(result[&ip!(192, 168, 1, 1)].output, 750);
        // Host 2: (2000+500)/2 = 1250 input, (1500+250)/2 = 875 output
        assert_eq!(result[&ip!(192, 168, 1, 2)].input, 1250);
        assert_eq!(result[&ip!(192, 168, 1, 2)].output, 875);
    }
}
