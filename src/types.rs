use std::fmt;

/// Custom MAC address type to decouple from pnet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        MacAddr([a, b, c, d, e, f])
    }

    pub const fn broadcast() -> Self {
        MacAddr([0xFF; 6])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[cfg(feature = "pnet-backend")]
impl From<pnet_datalink::MacAddr> for MacAddr {
    fn from(mac: pnet_datalink::MacAddr) -> Self {
        MacAddr([mac.0, mac.1, mac.2, mac.3, mac.4, mac.5])
    }
}

#[cfg(feature = "pnet-backend")]
impl From<MacAddr> for pnet_datalink::MacAddr {
    fn from(mac: MacAddr) -> Self {
        pnet_datalink::MacAddr::new(mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5])
    }
}
