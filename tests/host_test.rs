use netui::app::Host;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

#[test]
fn test_host_equality() {
    let host1 = Host {
        time: chrono::Local::now(),
        ipv4: Ipv4Addr::new(192, 168, 1, 100),
        mac: MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
        hostname: None,
        is_my_device_mac: false,
        speed: None,
    };

    let host2 = Host {
        time: chrono::Local::now(),
        ipv4: Ipv4Addr::new(192, 168, 1, 100),
        mac: MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
        hostname: Some("test-host".to_string()),
        is_my_device_mac: true,
        speed: None,
    };

    // Hosts should be equal if IP and MAC match, regardless of other fields
    assert_eq!(host1, host2);
}

#[test]
fn test_host_inequality_different_ip() {
    let host1 = Host {
        time: chrono::Local::now(),
        ipv4: Ipv4Addr::new(192, 168, 1, 100),
        mac: MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
        hostname: None,
        is_my_device_mac: false,
        speed: None,
    };

    let host2 = Host {
        time: chrono::Local::now(),
        ipv4: Ipv4Addr::new(192, 168, 1, 101), // Different IP
        mac: MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
        hostname: None,
        is_my_device_mac: false,
        speed: None,
    };

    assert_ne!(host1, host2);
}

#[test]
fn test_host_inequality_different_mac() {
    let host1 = Host {
        time: chrono::Local::now(),
        ipv4: Ipv4Addr::new(192, 168, 1, 100),
        mac: MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
        hostname: None,
        is_my_device_mac: false,
        speed: None,
    };

    let host2 = Host {
        time: chrono::Local::now(),
        ipv4: Ipv4Addr::new(192, 168, 1, 100),
        mac: MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x66), // Different MAC
        hostname: None,
        is_my_device_mac: false,
        speed: None,
    };

    assert_ne!(host1, host2);
}
