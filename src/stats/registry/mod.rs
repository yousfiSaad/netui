//! Application registry module.
//!
//! This module provides the `AppRegistry` for port-to-application name lookups.
//! Default port mappings are defined in the `default` submodule.

mod default;

pub use default::default_port_mappings;

use std::collections::HashMap;

/// Registry of well-known port numbers to application names.
#[derive(Debug, Clone)]
pub struct AppRegistry {
    /// Mapping from port number to application name
    port_to_app: HashMap<u16, String>,
}

impl Default for AppRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AppRegistry {
    /// Create a new AppRegistry with well-known service mappings.
    ///
    /// Includes common web, email, database, and other network services.
    pub fn new() -> Self {
        Self {
            port_to_app: default_port_mappings(),
        }
    }

    /// Create a new AppRegistry with custom port mappings.
    ///
    /// This allows extending or overriding the default mappings.
    ///
    /// # Arguments
    /// * `custom_mappings` - Additional port-to-app mappings to add
    ///
    /// # Example
    /// ```rust
    /// use netui::stats::registry::AppRegistry;
    /// use std::collections::HashMap;
    ///
    /// let mut custom = HashMap::new();
    /// custom.insert(8080, "MyCustomApp".to_string());
    /// let registry = AppRegistry::with_mappings(custom);
    /// ```
    pub fn with_mappings(custom_mappings: HashMap<u16, String>) -> Self {
        let mut registry = Self::new();
        for (port, name) in custom_mappings {
            registry.port_to_app.insert(port, name);
        }
        registry
    }

    /// Register a custom port-to-application mapping.
    ///
    /// This allows extending the registry at runtime.
    ///
    /// # Arguments
    /// * `port` - The port number
    /// * `app_name` - The application name to associate with the port
    pub fn register(&mut self, port: u16, app_name: String) {
        self.port_to_app.insert(port, app_name);
    }

    /// Get the application name for a given port number.
    ///
    /// Returns the application name if known, or None for unregistered ports.
    pub fn get_app_name(&self, port: u16) -> Option<&String> {
        self.port_to_app.get(&port)
    }

    /// Get the application name for a port, or a default "Port-XXXXX" format.
    pub fn get_app_name_or_default(&self, port: u16) -> String {
        self.get_app_name(port)
            .cloned()
            .unwrap_or_else(|| format!("Port-{}", port))
    }

    /// Get all ports associated with an application name.
    pub fn get_ports_for_app(&self, app_name: &str) -> Vec<u16> {
        self.port_to_app
            .iter()
            .filter(|(_, name)| name.as_str() == app_name)
            .map(|(&port, _)| port)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_known_ports() {
        let registry = AppRegistry::new();

        assert_eq!(registry.get_app_name(80), Some(&"HTTP".to_string()));
        assert_eq!(registry.get_app_name(443), Some(&"HTTPS".to_string()));
        assert_eq!(registry.get_app_name(22), Some(&"SSH".to_string()));
    }

    #[test]
    fn test_registry_unknown_port() {
        let registry = AppRegistry::new();
        assert_eq!(registry.get_app_name(9999), None);
    }

    #[test]
    fn test_registry_get_or_default() {
        let registry = AppRegistry::new();
        assert_eq!(registry.get_app_name_or_default(80), "HTTP");
        assert_eq!(registry.get_app_name_or_default(9999), "Port-9999");
    }

    #[test]
    fn test_registry_get_ports_for_app() {
        let registry = AppRegistry::new();
        let http_ports = registry.get_ports_for_app("HTTP");
        assert!(http_ports.contains(&80));
    }

    #[test]
    fn test_registry_with_mappings() {
        let mut custom = HashMap::new();
        custom.insert(9999, "CustomApp".to_string());
        let registry = AppRegistry::with_mappings(custom);

        assert_eq!(registry.get_app_name(9999), Some(&"CustomApp".to_string()));
        // Default mappings should still be available
        assert_eq!(registry.get_app_name(80), Some(&"HTTP".to_string()));
    }

    #[test]
    fn test_registry_register() {
        let mut registry = AppRegistry::new();
        registry.register(9999, "CustomApp".to_string());

        assert_eq!(registry.get_app_name(9999), Some(&"CustomApp".to_string()));
    }

    #[test]
    fn test_registry_register_overrides_default() {
        let mut registry = AppRegistry::new();
        registry.register(80, "CustomHTTP".to_string());

        assert_eq!(registry.get_app_name(80), Some(&"CustomHTTP".to_string()));
    }
}
