//! Default port-to-application mappings.
//!
//! This module provides the default port mappings for common network services.

use std::collections::HashMap;

/// Create the default port-to-application mappings.
///
/// Returns a HashMap mapping well-known port numbers to their application names.
pub fn default_port_mappings() -> HashMap<u16, String> {
    let mut port_to_app = HashMap::new();

    // Web services
    port_to_app.insert(80, "HTTP".to_string());
    port_to_app.insert(443, "HTTPS".to_string());
    port_to_app.insert(8080, "HTTP-Alt".to_string());

    // Remote access
    port_to_app.insert(22, "SSH".to_string());
    port_to_app.insert(23, "Telnet".to_string());
    port_to_app.insert(3389, "RDP".to_string());
    port_to_app.insert(5900, "VNC".to_string());

    // File transfer
    port_to_app.insert(20, "FTP-Data".to_string());
    port_to_app.insert(21, "FTP".to_string());
    port_to_app.insert(69, "TFTP".to_string());
    port_to_app.insert(445, "SMB".to_string());

    // DNS
    port_to_app.insert(53, "DNS".to_string());

    // Email
    port_to_app.insert(25, "SMTP".to_string());
    port_to_app.insert(587, "SMTP-Submission".to_string());
    port_to_app.insert(110, "POP3".to_string());
    port_to_app.insert(995, "POP3S".to_string());
    port_to_app.insert(143, "IMAP".to_string());
    port_to_app.insert(993, "IMAPS".to_string());

    // Databases
    port_to_app.insert(3306, "MySQL".to_string());
    port_to_app.insert(5432, "PostgreSQL".to_string());
    port_to_app.insert(6379, "Redis".to_string());
    port_to_app.insert(27017, "MongoDB".to_string());
    port_to_app.insert(1521, "Oracle".to_string());
    port_to_app.insert(1433, "MSSQL".to_string());

    // Directory services
    port_to_app.insert(389, "LDAP".to_string());
    port_to_app.insert(636, "LDAPS".to_string());

    // Other common services
    port_to_app.insert(161, "SNMP".to_string());
    port_to_app.insert(123, "NTP".to_string());
    port_to_app.insert(1194, "OpenVPN".to_string());
    port_to_app.insert(500, "IKE".to_string());
    port_to_app.insert(4500, "IPsec-NAT".to_string());

    port_to_app
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_mappings_not_empty() {
        let mappings = default_port_mappings();
        assert!(!mappings.is_empty());
    }

    #[test]
    fn test_default_web_services() {
        let mappings = default_port_mappings();
        assert_eq!(mappings.get(&80), Some(&"HTTP".to_string()));
        assert_eq!(mappings.get(&443), Some(&"HTTPS".to_string()));
    }

    #[test]
    fn test_default_remote_access() {
        let mappings = default_port_mappings();
        assert_eq!(mappings.get(&22), Some(&"SSH".to_string()));
        assert_eq!(mappings.get(&3389), Some(&"RDP".to_string()));
    }

    #[test]
    fn test_default_databases() {
        let mappings = default_port_mappings();
        assert_eq!(mappings.get(&3306), Some(&"MySQL".to_string()));
        assert_eq!(mappings.get(&5432), Some(&"PostgreSQL".to_string()));
        assert_eq!(mappings.get(&6379), Some(&"Redis".to_string()));
    }

    #[test]
    fn test_default_count() {
        let mappings = default_port_mappings();
        // Ensure we have a reasonable number of mappings
        assert!(mappings.len() > 20);
    }
}
