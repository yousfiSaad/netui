//! UI layout constants.

/// Minimum terminal width for full detail view
pub const WIDTH_FULL_DETAIL: u16 = 130;

/// Minimum terminal width for view without RTT column
pub const WIDTH_NO_RTT: u16 = 110;

/// Minimum terminal width for middle view (with RTT but shorter columns)
pub const WIDTH_MIDDLE: u16 = 100;

/// Minimum terminal width for compact view
pub const WIDTH_COMPACT: u16 = 90;

/// Height of the tabs area
pub const TAB_HEIGHT: u16 = 3;

/// Height of the footer area
pub const FOOTER_HEIGHT: u16 = 1;

/// Minimum height for the table area
pub const MIN_TABLE_HEIGHT: u16 = 5;

/// Maximum length for IP display before truncation
pub const MAX_IP_DISPLAY_LENGTH: usize = 15;

/// Character count to truncate IP to
pub const IP_TRUNCATE_AT: usize = 13;

/// Maximum length for vendor name display
pub const MAX_VENDOR_LENGTH: usize = 20;

/// Minimum terminal width
pub const MIN_TERMINAL_WIDTH: u16 = 40;

/// Minimum terminal height
pub const MIN_TERMINAL_HEIGHT: u16 = 10;

/// Width of sparkline in characters
pub const SPARKLINE_WIDTH: usize = 20;

/// Confirmation timeout in seconds for cleanup operation
pub const CONFIRMATION_TIMEOUT_SECS: u64 = 5;
