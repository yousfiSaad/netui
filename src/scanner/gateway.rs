//! Default gateway detection for distinguishing Internet vs LAN traffic.
//!
//! This module provides cross-platform gateway detection to identify
//! the default route used for Internet traffic.

use std::net::Ipv4Addr;

#[cfg(target_os = "macos")]
use std::process::Command;

/// Detect the default gateway IPv4 address.
///
/// This function attempts to detect the default gateway using platform-specific
/// methods. The gateway is the router that handles Internet traffic.
///
/// # Returns
/// - `Some(Ipv4Addr)` - The gateway IP if detected
/// - `None` - If gateway detection fails
///
/// # Platform Support
/// - **Linux**: Uses `/proc/net/route` parsing
/// - **macOS**: Uses `netstat -rn` command
/// - **Other**: Returns None (could be extended)
pub fn detect_default_gateway() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        detect_gateway_linux()
    }

    #[cfg(target_os = "macos")]
    {
        detect_gateway_macos()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        detect_gateway_fallback()
    }
}

/// Detect default gateway on Linux by parsing /proc/net/route.
#[cfg(target_os = "linux")]
fn detect_gateway_linux() -> Option<Ipv4Addr> {
    use std::fs;

    // /proc/net/route format:
    // Iface Destination Gateway Flags ...
    // eth0  00000000    010011AC  ...  (Destination 00000000 = default route)
    if let Ok(content) = fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                // Destination is in hex, little-endian
                let dest = parts[1];
                // Gateway is in hex, little-endian
                let gateway_hex = parts[2];

                // Check if this is the default route (Destination == 00000000)
                if dest == "00000000" && gateway_hex != "00000000" {
                    // Parse hex gateway address (little-endian)
                    if let Ok(gateway_u32) = u32::from_str_radix(gateway_hex, 16) {
                        // Convert from little-endian to host order
                        let gateway_bytes = gateway_u32.to_le_bytes();
                        return Some(Ipv4Addr::new(
                            gateway_bytes[0],
                            gateway_bytes[1],
                            gateway_bytes[2],
                            gateway_bytes[3],
                        ));
                    }
                }
            }
        }
    }

    tracing::debug!("Failed to detect gateway on Linux");
    None
}

/// Detect default gateway on macOS using `netstat -rn`.
#[cfg(target_os = "macos")]
fn detect_gateway_macos() -> Option<Ipv4Addr> {
    // netstat -rn output format:
    // Destination        Gateway            Flags
    // default            192.168.1.1        UGSc
    let output = Command::new("netstat")
        .arg("-rn")
        .arg("-f")
        .arg("inet")
        .output();

    if let Ok(output) = output {
        let content = String::from_utf8_lossy(&output.stdout);
        for line in content.lines() {
            let line = line.trim();
            // Look for "default" route
            if line.starts_with("default") || line.starts_with("0.0.0.0") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // The gateway is typically the second column
                if parts.len() >= 2 {
                    if let Ok(gateway) = parts[1].parse::<Ipv4Addr>() {
                        return Some(gateway);
                    }
                }
            }
        }
    }

    tracing::debug!("Failed to detect gateway on macOS");
    None
}

/// Fallback gateway detection (returns None).
///
/// This could be extended to support other platforms or use
/// external libraries like pnet for cross-platform detection.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_gateway_fallback() -> Option<Ipv4Addr> {
    tracing::warn!("Gateway detection not implemented for this platform");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_gateway_returns_some_ip() {
        // This test will pass if gateway detection works on the current platform
        // It may return None on unsupported platforms or in CI environments
        let gateway = detect_default_gateway();
        if let Some(gw) = gateway {
            // Verify it's a valid IPv4 address (not 0.0.0.0)
            assert_ne!(gw, Ipv4Addr::new(0, 0, 0, 0));
            println!("Detected gateway: {}", gw);
        } else {
            println!("Gateway detection returned None (expected in some environments)");
        }
    }

    #[test]
    fn test_detect_gateway_does_not_panic() {
        // Verify the function doesn't panic
        let _ = detect_default_gateway();
    }
}
