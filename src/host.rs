//! Host information structure shared between library and binary.

use std::net::Ipv4Addr;

use crate::stats::Speed;
use crate::types::MacAddr;

/// Host discovered during network scanning.
#[derive(Clone, Debug)]
pub struct Host {
    /// Timestamp when the host was last seen
    pub time: chrono::DateTime<chrono::Local>,
    /// IPv4 address of the host
    pub ipv4: Ipv4Addr,
    /// MAC address of the host
    pub mac: MacAddr,
    /// Optional hostname (if resolved)
    pub hostname: Option<String>,
    /// Optional bandwidth speed information
    pub speed: Option<Speed>,
}

impl PartialEq for Host {
    fn eq(&self, other: &Self) -> bool {
        self.ipv4 == other.ipv4 && self.mac == other.mac
    }
}
