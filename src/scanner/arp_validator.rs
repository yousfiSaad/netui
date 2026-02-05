//! ARP reply validation for security.
//!
//! This module implements ARP reply validation to prevent ARP poisoning attacks.
//! It tracks pending ARP requests and validates that incoming replies correspond
//! to requests we actually sent.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Result of ARP reply validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpValidation {
    /// The reply is valid (we sent a request for this IP)
    Valid,
    /// The reply is unsolicited (we didn't send a request for this IP)
    Unsolicited,
    /// The reply is expired (request was too long ago)
    Expired,
}

/// ARP validator for tracking pending ARP requests and validating replies.
///
/// This validator maintains a map of pending ARP requests with timestamps.
/// When an ARP reply is received, it checks if a corresponding request was made.
/// Unsolicited replies are rejected as potential ARP poisoning attempts.
pub struct ArpValidator {
    /// Map of target IP → request timestamp
    pending_requests: HashMap<Ipv4Addr, Instant>,
    /// How long an ARP request is considered valid (default 15 seconds for scanner use)
    timeout: Duration,
}

impl ArpValidator {
    /// Create a new ARP validator with the specified timeout.
    ///
    /// # Arguments
    /// * `timeout` - How long ARP requests remain valid (default 15 seconds for scanner use)
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending_requests: HashMap::new(),
            timeout,
        }
    }

    /// Create a new ARP validator with default 2-second timeout.
    ///
    /// Note: The scanner uses a 15-second timeout to accommodate full network scans.
    pub fn with_default_timeout() -> Self {
        Self::new(Duration::from_secs(2))
    }

    /// Record that we're sending an ARP request for the target IP.
    ///
    /// This should be called immediately before sending an ARP request.
    ///
    /// # Arguments
    /// * `target_ip` - The IP address we're querying
    pub fn record_request(&mut self, target_ip: Ipv4Addr) {
        self.pending_requests.insert(target_ip, Instant::now());
    }

    /// Validate an ARP reply for the given IP.
    ///
    /// This checks if we sent a request for this IP within the timeout window.
    ///
    /// # Arguments
    /// * `ip` - The IP address from the ARP reply
    ///
    /// # Returns
    /// * `ArpValidation::Valid` - We sent a request recently
    /// * `ArpValidation::Unsolicited` - We didn't send a request for this IP
    /// * `ArpValidation::Expired` - Request was sent too long ago
    pub fn validate_reply(&mut self, ip: Ipv4Addr) -> ArpValidation {
        match self.pending_requests.remove(&ip) {
            Some(request_time) => {
                if request_time.elapsed() <= self.timeout {
                    ArpValidation::Valid
                } else {
                    ArpValidation::Expired
                }
            }
            None => ArpValidation::Unsolicited,
        }
    }

    /// Remove expired requests from the pending map.
    ///
    /// This is NOT called automatically during validation, but can be called
    /// manually to clean up old requests periodically.
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.pending_requests
            .retain(|_, &mut request_time| now.duration_since(request_time) <= self.timeout);
    }

    /// Get the number of pending ARP requests.
    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Clear all pending requests.
    pub fn clear(&mut self) {
        self.pending_requests.clear();
    }
}

impl Default for ArpValidator {
    fn default() -> Self {
        Self::with_default_timeout()
    }
}

/// Thread-safe wrapper for ARP validator.
///
/// This wraps `ArpValidator` in `Arc<Mutex<>>` for safe sharing across tasks.
pub struct SharedArpValidator {
    inner: Arc<Mutex<ArpValidator>>,
}

impl SharedArpValidator {
    /// Create a new shared ARP validator with the specified timeout.
    pub fn new(timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ArpValidator::new(timeout))),
        }
    }

    /// Create a new shared ARP validator with default 2-second timeout.
    ///
    /// Note: The scanner uses a 15-second timeout to accommodate full network scans.
    pub fn with_default_timeout() -> Self {
        Self::new(Duration::from_secs(2))
    }

    /// Record that we're sending an ARP request for the target IP.
    pub fn record_request(&self, target_ip: Ipv4Addr) {
        if let Ok(mut validator) = self.inner.lock() {
            validator.record_request(target_ip);
        }
    }

    /// Validate an ARP reply for the given IP.
    pub fn validate_reply(&self, ip: Ipv4Addr) -> ArpValidation {
        self.inner
            .lock()
            .map(|mut validator| validator.validate_reply(ip))
            .unwrap_or(ArpValidation::Unsolicited)
    }

    /// Get the number of pending ARP requests.
    pub fn pending_count(&self) -> usize {
        self.inner
            .lock()
            .map(|validator| validator.pending_count())
            .unwrap_or(0)
    }

    /// Clear all pending requests.
    pub fn clear(&self) {
        if let Ok(mut validator) = self.inner.lock() {
            validator.clear();
        }
    }

    /// Clone the inner Arc for sharing across tasks.
    pub fn clone_inner(&self) -> Arc<Mutex<ArpValidator>> {
        Arc::clone(&self.inner)
    }
}

impl Default for SharedArpValidator {
    fn default() -> Self {
        Self::with_default_timeout()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_validate_reply() {
        let mut validator = ArpValidator::with_default_timeout();

        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();

        // Validate without recording - should be unsolicited
        assert_eq!(validator.validate_reply(ip), ArpValidation::Unsolicited);

        // Record a request
        validator.record_request(ip);

        // Validate immediately - should be valid
        assert_eq!(validator.validate_reply(ip), ArpValidation::Valid);

        // Validate again - should be unsolicited (was consumed)
        assert_eq!(validator.validate_reply(ip), ArpValidation::Unsolicited);
    }

    #[test]
    fn test_expired_request() {
        let mut validator = ArpValidator::new(Duration::from_millis(100));

        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();

        validator.record_request(ip);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(150));

        // Should be expired
        assert_eq!(validator.validate_reply(ip), ArpValidation::Expired);
    }

    #[test]
    fn test_cleanup_expired() {
        let mut validator = ArpValidator::new(Duration::from_millis(100));

        let ip1: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let ip2: Ipv4Addr = "192.168.1.2".parse().unwrap();

        validator.record_request(ip1);
        validator.record_request(ip2);

        assert_eq!(validator.pending_count(), 2);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(150));

        // Cleanup should remove expired requests
        validator.cleanup_expired();
        assert_eq!(validator.pending_count(), 0);
    }

    #[test]
    fn test_shared_validator() {
        let validator = SharedArpValidator::with_default_timeout();

        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();

        // Validate without recording - should be unsolicited
        assert_eq!(validator.validate_reply(ip), ArpValidation::Unsolicited);

        // Record a request
        validator.record_request(ip);

        // Validate immediately - should be valid
        assert_eq!(validator.validate_reply(ip), ArpValidation::Valid);
    }

    #[test]
    fn test_clear_pending() {
        let mut validator = ArpValidator::with_default_timeout();

        let ip1: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let ip2: Ipv4Addr = "192.168.1.2".parse().unwrap();

        validator.record_request(ip1);
        validator.record_request(ip2);

        assert_eq!(validator.pending_count(), 2);

        validator.clear();
        assert_eq!(validator.pending_count(), 0);
    }
}
