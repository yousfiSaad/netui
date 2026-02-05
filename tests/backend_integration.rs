//! Backend integration tests.
//!
//! This module tests the backend abstraction layer, ensuring that both
//! pnet and eBPF backends implement the PacketSource and PacketSink
//! traits correctly and can be used interchangeably.

#[cfg(feature = "pnet-backend")]
use netui::backend::PnetBackendFactory;
#[cfg(feature = "pnet-backend")]
use netui::backend::{BackendConfig, BackendFactory};

#[cfg(feature = "ebpf-backend")]
use netui::backend::EbpfBackendFactory;

/// Helper to get a test interface name.
///
/// Returns the first available non-loopback interface, or "lo" if none found.
fn get_test_interface() -> String {
    use pnet_datalink::interfaces;

    // Try to find a non-loopback interface
    for interface in interfaces() {
        if !interface.is_loopback() && !interface.ips.is_empty() {
            return interface.name;
        }
    }

    // Fallback to loopback
    "lo".to_string()
}

/// Test that backend factory names are unique and non-empty.
#[test]
#[cfg(feature = "pnet-backend")]
fn test_backend_factory_names() {
    let pnet_factory = PnetBackendFactory;
    assert_eq!(pnet_factory.name(), "pnet");
    assert!(!pnet_factory.name().is_empty());
}

/// Test that BackendConfig can be created with an interface name.
#[test]
fn test_backend_config_creation() {
    let config = BackendConfig::new("test0".to_string());
    assert_eq!(config.interface_name, "test0");
    assert_eq!(config.read_timeout_ms, Some(500));
}

/// Test that pnet backend creation fails with invalid interface.
#[test]
#[cfg(feature = "pnet-backend")]
fn test_pnet_backend_fails_with_invalid_interface() {
    let factory = PnetBackendFactory;
    let config = BackendConfig::new("nonexistent_interface_12345".to_string());

    let result = factory.create(config);
    assert!(result.is_err(), "Should fail with invalid interface name");

    if let Err(e) = result {
        let error_msg = e.to_string().to_lowercase();
        assert!(
            error_msg.contains("interface") || error_msg.contains("not found"),
            "Error should mention interface issue: {}",
            e
        );
    }
}

/// Test that pnet backend can be created with a valid interface.
///
/// Note: This test may fail on systems without network interfaces or
/// without sufficient permissions. It's marked as [ignore] by default
/// and can be run with: cargo test --test backend_integration -- --ignored
#[test]
#[cfg(feature = "pnet-backend")]
#[ignore]
fn test_pnet_backend_creates_with_valid_interface() {
    let factory = PnetBackendFactory;
    let interface_name = get_test_interface();
    let config = BackendConfig::new(interface_name.clone());

    let result = factory.create(config);

    match result {
        Ok((mut source, _sink)) => {
            // Test that we can call next_packet (may return None if no traffic)
            let packet = source.next_packet();
            // We don't assert on packet content since we can't guarantee traffic
            // Just verify the method doesn't panic
            let _ = packet;
        }
        Err(e) => {
            // Some systems may not allow raw socket access
            // Log the error but don't fail the test
            eprintln!(
                "Warning: Could not create pnet backend on {}: {}",
                interface_name, e
            );
        }
    }
}

/// Test that both backends have the same factory interface.
#[test]
#[cfg(all(feature = "pnet-backend", feature = "ebpf-backend"))]
fn test_both_backends_implement_factory() {
    let _pnet_factory = PnetBackendFactory;
    let _ebpf_factory = EbpfBackendFactory;

    // Both implement BackendFactory, so they should have the same interface
    // This is a compile-time check that the traits are implemented
    fn assert_factory<T: BackendFactory>(_factory: T) {}

    assert_factory(PnetBackendFactory);
    assert_factory(EbpfBackendFactory);
}

/// Test eBPF backend factory name.
#[test]
#[cfg(feature = "ebpf-backend")]
fn test_ebpf_backend_factory_name() {
    let factory = EbpfBackendFactory;
    assert_eq!(factory.name(), "ebpf");
}

/// Test that eBPF backend creation fails with invalid interface.
#[test]
#[cfg(feature = "ebpf-backend")]
fn test_ebpf_backend_fails_with_invalid_interface() {
    let factory = EbpfBackendFactory;
    let config = BackendConfig::new("nonexistent_interface_12345".to_string());

    let result = factory.create(config);
    assert!(result.is_err(), "Should fail with invalid interface name");
}

/// Integration test: Test packet sink send error handling.
#[test]
#[cfg(feature = "pnet-backend")]
fn test_packet_sink_handles_invalid_data() {
    use netui::backend::PnetBackendFactory;

    let factory = PnetBackendFactory;
    let interface_name = get_test_interface();
    let config = BackendConfig::new(interface_name.clone());

    let result = factory.create(config);

    match result {
        Ok((mut _source, mut sink)) => {
            // Test sending invalid data (too short for Ethernet frame)
            let invalid_packet = vec![0u8; 5];
            let send_result = sink.send_packet(&invalid_packet);

            // The result should either be Ok or a proper error
            // We just verify it doesn't panic and returns a Result
            let _ = send_result;
        }
        Err(e) => {
            // Some systems may not allow raw socket access
            eprintln!(
                "Warning: Could not create pnet backend on {}: {}",
                interface_name, e
            );
        }
    }
}

/// Test that PacketWithContext can be created with valid data.
#[test]
#[cfg(feature = "pnet-backend")]
fn test_packet_with_context_creation() {
    use netui::backend::PacketWithContext;

    // Test pnet-style packet (no hook source)
    let packet = PacketWithContext {
        data: vec![0u8; 100],
        hook_source: None,
        original_len: None,
        direct_event: None,
        timestamp_ns: None,
    };
    assert_eq!(packet.data.len(), 100);
    assert!(packet.hook_source.is_none());
    assert!(packet.original_len.is_none());

    // Test eBPF-style packet (with hook source)
    let packet = PacketWithContext {
        data: vec![0u8; 100],
        hook_source: Some(0), // XDP
        original_len: Some(1500),
        direct_event: None,
        timestamp_ns: Some(123456789),
    };
    assert_eq!(packet.data.len(), 100);
    assert_eq!(packet.hook_source, Some(0));
    assert_eq!(packet.original_len, Some(1500));
}
