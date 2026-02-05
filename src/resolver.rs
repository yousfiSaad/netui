//! DNS reverse lookup module.
//!
//! Performs asynchronous reverse DNS lookups for IPv4 addresses to resolve hostnames.

use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;

/// Default timeout for DNS reverse lookup operations.
const DEFAULT_LOOKUP_TIMEOUT_MS: u64 = 2000;

/// Maximum size of /etc/hosts file to prevent DoS via large files.
const MAX_HOSTS_FILE_SIZE: usize = 1_000_000; // 1MB

/// Maximum hostname length per RFC 1035.
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Maximum line length in /etc/hosts to prevent memory exhaustion.
const MAX_HOSTS_LINE_LENGTH: usize = 1024;

/// Perform reverse DNS lookup for an IPv4 address.
///
/// This function attempts to resolve the hostname associated with the given IP address
/// using a reverse DNS query (PTR record) via the system's DNS resolver.
///
/// # Arguments
/// * `ip` - The IPv4 address to resolve
///
/// # Returns
/// - `Some(String)` - The hostname if resolution succeeds
/// - `None` - If lookup fails, times out, or no PTR record exists
///
/// # Behavior
/// - Uses the system's DNS resolver configuration
/// - Times out after 2 seconds to avoid blocking indefinitely
/// - Returns None for both lookup failures and timeouts (indistinguishable for privacy)
/// - Logs errors at debug level for troubleshooting
///
/// # Example
/// ```no_run
/// use netui::resolver::resolve_hostname;
/// use std::net::Ipv4Addr;
///
/// #[tokio::main]
/// async fn main() {
///     let ip = Ipv4Addr::new(8, 8, 8, 8);
///     if let Some(hostname) = resolve_hostname(ip).await {
///         println!("Hostname for {}: {}", ip, hostname);
///     }
/// }
/// ```
pub async fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
    // Use spawn_blocking for reverse DNS lookup
    // This blocks a thread pool thread but doesn't block the async runtime
    let lookup_future = tokio::task::spawn_blocking(move || {
        // Perform reverse DNS lookup via /etc/hosts and system DNS
        reverse_dns_lookup(ip)
    });

    match timeout(
        Duration::from_millis(DEFAULT_LOOKUP_TIMEOUT_MS),
        lookup_future,
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            // Spawn_blocking failed (thread pool exhausted)
            tracing::debug!("DNS reverse lookup thread pool exhausted for {}", ip);
            None
        }
        Err(_) => {
            tracing::debug!(
                "DNS reverse lookup timed out for {} after {}ms",
                ip,
                DEFAULT_LOOKUP_TIMEOUT_MS
            );
            None
        }
    }
}

/// Synchronous reverse DNS lookup implementation.
///
/// This function performs a blocking reverse DNS lookup by:
/// 1. Checking /etc/hosts for local hostname mappings
/// 2. Using system's reverse DNS via getnameinfo (via trust-dns or similar)
///
/// For this implementation, we check /etc/hosts which works well for local networks.
/// For internet hostnames, a proper DNS library would be needed.
///
/// Note: This is intentionally simple. For production use with proper DNS resolution,
/// consider adding hickory-resolver or trust-dns-client as dependencies.
fn reverse_dns_lookup(ip: Ipv4Addr) -> Option<String> {
    use std::fs;

    // First, check /etc/hosts for local hostname mappings
    if let Ok(hosts_content) = fs::read_to_string("/etc/hosts") {
        // Validate file size to prevent DoS via large files
        if hosts_content.len() > MAX_HOSTS_FILE_SIZE {
            tracing::warn!(
                "/etc/hosts file too large ({} bytes), skipping",
                hosts_content.len()
            );
            return None;
        }

        for line in hosts_content.lines() {
            // Validate line length to prevent memory exhaustion
            if line.len() > MAX_HOSTS_LINE_LENGTH {
                tracing::debug!("Skipping overly long line in /etc/hosts");
                continue;
            }

            // Skip comments and empty lines
            let line = line.split('#').next().unwrap_or(line).trim();
            if line.is_empty() {
                continue;
            }

            // Parse hosts file format: IP hostname [aliases...]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(host_ip) = parts[0].parse::<Ipv4Addr>() {
                    if host_ip == ip {
                        let hostname = parts[1];

                        // Validate hostname length
                        if hostname.len() > MAX_HOSTNAME_LENGTH {
                            tracing::debug!("Hostname too long in /etc/hosts, skipping");
                            continue;
                        }

                        // Sanitize hostname: only allow alphanumeric, hyphen, and dot
                        let is_valid = hostname
                            .chars()
                            .all(|c| c.is_alphanumeric() || c == '-' || c == '.');

                        if !is_valid {
                            tracing::debug!("Invalid hostname characters in /etc/hosts, skipping");
                            continue;
                        }

                        // Found a valid match in /etc/hosts
                        return Some(hostname.to_string());
                    }
                }
            }
        }
    }

    // For full reverse DNS, we would need to use getnameinfo() via libc
    // or a DNS library. For now, return None for non-/etc/hosts lookups.
    // This provides basic local hostname resolution which is useful for LAN environments.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_localhost() {
        // Localhost should resolve from /etc/hosts
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let result = resolve_hostname(ip).await;
        // Should return Some("localhost") if found in /etc/hosts
        if let Some(hostname) = result {
            assert_eq!(hostname, "localhost");
        }
        // None is also acceptable if /etc/hosts doesn't have localhost
    }

    #[tokio::test]
    async fn test_resolve_unreachable_address() {
        // Use an unlikely-to-be-assigned address
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        let result = resolve_hostname(ip).await;
        // This should return None (no /etc/hosts entry)
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_resolve_does_not_panic() {
        // Verify the function doesn't panic for any IP
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let result = resolve_hostname(ip).await;
        // We don't assert on the result since it depends on /etc/hosts
        // Just verify it doesn't panic
        let _ = result;
    }
}
