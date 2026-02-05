//! Unicode sparkline visualization for bandwidth trends.
//!
//! This module provides sparkline rendering using Unicode block characters.
//! Sparklines show historical data trends in a compact horizontal format.

use netui::stats::Speed;

/// Unicode block characters for sparkline rendering.
///
/// Each character represents 1/8th of the vertical range, from empty (▁) to full (█).
/// These are the block characters from U+2581 to U+2588.
const BLOCK_CHARS: [char; 8] = [
    '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}',
];

/// A sparkline visualization for bandwidth trends.
///
/// Sparklines display historical data as a compact string of Unicode block characters,
/// where each character represents a data point and its height indicates the value.
pub struct Sparkline {
    /// Normalized data values (0.0 to 1.0)
    data: Vec<f32>,
}

impl Sparkline {
    /// Create a sparkline from a slice of Speed values.
    ///
    /// The speed values are normalized to the 0.0-1.0 range based on the maximum
    /// value in the dataset, then mapped to Unicode block characters.
    ///
    /// # Arguments
    /// * `speeds` - Slice of Speed values to visualize
    /// * `width` - Target width in characters (data will be sampled to fit)
    ///
    /// # Examples
    ///
    /// ```text,no_run
    /// let speeds = vec![
    ///     Speed::new(1000, 500),
    ///     Speed::new(2000, 1000),
    ///     Speed::new(1500, 750),
    /// ];
    /// let sparkline = Sparkline::from_speeds(&speeds, 10);
    /// ```
    pub fn from_speeds(speeds: &[Speed], width: usize) -> Self {
        if speeds.is_empty() || width == 0 {
            return Self { data: Vec::new() };
        }

        // Extract total bandwidth (input + output) for each speed
        let totals: Vec<f32> = speeds.iter().map(|s| (s.input + s.output) as f32).collect();

        // Find max for normalization
        let max_val = totals.iter().fold(0.0f32, |acc, &v| acc.max(v));

        // Normalize to 0.0-1.0 range (avoid division by zero)
        let normalized: Vec<f32> = if max_val > 0.0 {
            totals.iter().map(|&v| v / max_val).collect()
        } else {
            totals.iter().map(|_| 0.0).collect()
        };

        // Sample data to fit target width
        let sampled = Self::sample(&normalized, width);

        Self { data: sampled }
    }

    /// Create a sparkline from pre-normalized f32 values.
    ///
    /// # Arguments
    /// * `data` - Normalized values (0.0 to 1.0)
    /// * `width` - Target width in characters
    #[allow(dead_code)]
    pub fn from_normalized(data: &[f32], width: usize) -> Self {
        let sampled = if data.is_empty() {
            Vec::new()
        } else {
            Self::sample(data, width)
        };

        Self { data: sampled }
    }

    /// Sample data to fit target width.
    ///
    /// If data is shorter than width, pads with zeros.
    /// If data is longer than width, samples evenly.
    fn sample(data: &[f32], width: usize) -> Vec<f32> {
        if data.len() <= width {
            // Pad with zeros at the beginning
            let mut result = vec![0.0; width - data.len()];
            result.extend(data.iter().copied());
            result
        } else {
            // Sample evenly across the data
            let step = data.len() as f32 / width as f32;
            (0..width)
                .map(|i| {
                    let idx = ((i as f32) * step) as usize;
                    data[idx.min(data.len() - 1)]
                })
                .collect()
        }
    }

    /// Render the sparkline as a String.
    ///
    /// Returns a string of Unicode block characters representing the data trend.
    /// Each character's height corresponds to the normalized value at that position.
    ///
    /// # Examples
    ///
    /// ```text,no_run
    /// let sparkline = Sparkline::from_normalized(&[0.1, 0.5, 1.0, 0.3], 4);
    /// assert_eq!(sparkline.render(), "▂▄█▃");
    /// ```
    pub fn render(&self) -> String {
        self.data.iter().map(|&v| Self::value_to_block(v)).collect()
    }

    /// Convert a normalized value (0.0-1.0) to a Unicode block character.
    ///
    /// Values are clamped to [0.0, 1.0] range and mapped to one of 8 block levels.
    fn value_to_block(value: f32) -> char {
        let clamped = value.clamp(0.0, 1.0);
        let idx = (clamped * 7.0).round() as usize;
        BLOCK_CHARS[idx.min(7)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparkline_empty() {
        let sparkline = Sparkline::from_speeds(&[], 10);
        assert_eq!(sparkline.render(), "");
    }

    #[test]
    fn test_sparkline_zero_width() {
        let speeds = vec![Speed::new(1000, 500)];
        let sparkline = Sparkline::from_speeds(&speeds, 0);
        assert_eq!(sparkline.render(), "");
    }

    #[test]
    fn test_sparkline_basic() {
        // Test with known values: 0%, 25%, 50%, 75%, 100%
        let data = vec![0.0, 0.25, 0.5, 0.75, 1.0];
        let sparkline = Sparkline::from_normalized(&data, 5);
        let rendered = sparkline.render();
        // Should show progression from low to high
        assert_eq!(rendered.chars().count(), 5);
        // First char should be lowest block
        assert_eq!(rendered.chars().next().unwrap(), '\u{2581}');
        // Last char should be highest block
        assert_eq!(rendered.chars().last().unwrap(), '\u{2588}');
    }

    #[test]
    fn test_sparkline_sampling() {
        // When data > width, should sample
        let data: Vec<f32> = (0..20).map(|i| i as f32 / 19.0).collect();
        let sparkline = Sparkline::from_normalized(&data, 10);
        assert_eq!(sparkline.render().chars().count(), 10);
    }

    #[test]
    fn test_sparkline_padding() {
        // When data < width, should pad
        let data = vec![0.5, 1.0];
        let sparkline = Sparkline::from_normalized(&data, 5);
        let rendered = sparkline.render();
        assert_eq!(rendered.chars().count(), 5);
        // First chars should be empty (block 1 at index 0)
        assert_eq!(rendered.chars().next().unwrap(), '\u{2581}');
    }

    #[test]
    fn test_value_to_block_clamping() {
        // Test clamping behavior
        assert_eq!(Sparkline::value_to_block(-0.5), '\u{2581}');
        assert_eq!(Sparkline::value_to_block(0.0), '\u{2581}');
        // With 8 characters (0-7), 0.5 * 7 = 3.5 → rounds to 4 → '▅'
        assert_eq!(Sparkline::value_to_block(0.5), '\u{2585}');
        assert_eq!(Sparkline::value_to_block(1.0), '\u{2588}');
        assert_eq!(Sparkline::value_to_block(1.5), '\u{2588}');
    }

    #[test]
    fn test_sparkline_from_speeds() {
        let speeds = vec![
            Speed::new(1000, 500),
            Speed::new(2000, 1000),
            Speed::new(500, 250),
        ];
        let sparkline = Sparkline::from_speeds(&speeds, 3);
        let rendered = sparkline.render();
        assert_eq!(rendered.chars().count(), 3);
        // Middle value should be highest
        let mut chars: Vec<char> = rendered.chars().collect();
        chars.sort_by_key(|&c| c as u32);
        // Sorted should go from low to high
        assert_eq!(chars[2], '\u{2588}'); // Highest is full block
    }
}
