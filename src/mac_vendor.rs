//! MAC address vendor (OUI) lookup module.
//!
//! Provides lookup of hardware vendor names from MAC addresses using the
//! first 3 bytes (OUI - Organizationally Unique Identifier).
//!
//! The vendor database is loaded from `data/oui_database.json` at compile time.

use crate::types::MacAddr;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

/// OUI database structure loaded from JSON.
#[derive(Deserialize)]
struct OuiDatabase {
    vendors: HashMap<String, String>,
}

/// Global OUI database, initialized once at runtime.
static OUI_DB: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Get the OUI database, initializing it on first access.
fn get_oui_db() -> &'static HashMap<String, String> {
    OUI_DB.get_or_init(|| {
        // Load JSON at compile time using include_str!
        let json_str = include_str!("../data/oui_database.json");

        // Parse the JSON
        let db: OuiDatabase = match serde_json::from_str(json_str) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to parse OUI database JSON: {}", e);
                // Return empty map on error to avoid crashes
                return HashMap::new();
            }
        };

        db.vendors
    })
}

/// Look up vendor name from MAC address OUI (first 3 bytes).
///
/// Returns `Some(vendor_name)` if the OUI is known, `None` otherwise.
///
/// # Example
/// ```no_run
/// use netui::types::MacAddr;
/// use netui::lookup_vendor;
///
/// let mac = MacAddr::new(0x00, 0x0a, 0x95, 0x12, 0x34, 0x56);
/// assert_eq!(lookup_vendor(&mac), Some("Apple"));
/// ```
pub fn lookup_vendor(mac: &MacAddr) -> Option<&'static str> {
    let oui = format!("{:02x}:{:02x}:{:02x}", mac.0[0], mac.0[1], mac.0[2]);
    get_oui_db().get(oui.as_str()).map(|s| s.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apple_vendor() {
        let mac = MacAddr::new(0x00, 0x0a, 0x95, 0x12, 0x34, 0x56);
        assert_eq!(lookup_vendor(&mac), Some("Apple"));
    }

    #[test]
    fn test_unknown_vendor() {
        let mac = MacAddr::new(0xff, 0xff, 0xff, 0x12, 0x34, 0x56);
        assert_eq!(lookup_vendor(&mac), None);
    }

    #[test]
    fn test_multiple_vendors() {
        // Test a few known vendors
        assert_eq!(
            lookup_vendor(&MacAddr::new(0x00, 0x00, 0x0c, 0x12, 0x34, 0x56)),
            Some("Cisco")
        );
        assert_eq!(
            lookup_vendor(&MacAddr::new(0x00, 0x02, 0xb3, 0x12, 0x34, 0x56)),
            Some("Intel")
        );
        assert_eq!(
            lookup_vendor(&MacAddr::new(0x00, 0x04, 0x76, 0x12, 0x34, 0x56)),
            Some("Samsung")
        );
    }
}
