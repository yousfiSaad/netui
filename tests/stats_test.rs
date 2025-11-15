use netui::stats_aggregator::{Direction, Speed, StatKey, StatValues};
use std::net::Ipv4Addr;

#[test]
fn test_direction_enum() {
    let outgoing = Direction::Outgoing;
    let incoming = Direction::Incoming;
    let local = Direction::Local;
    let none = Direction::None;

    assert_ne!(outgoing, incoming);
    assert_ne!(outgoing, local);
    assert_ne!(outgoing, none);
}

#[test]
fn test_speed_default() {
    let speed = Speed::default();
    assert_eq!(speed.to_string_input(), "0.00 Bit/s");
    assert_eq!(speed.to_string_output(), "0.00 Bit/s");
}

#[test]
fn test_speed_addition() {
    let speed1 = Speed::default();
    let speed2 = Speed::default();
    let result = speed1 + speed2;

    assert_eq!(result.to_string_input(), "0.00 Bit/s");
    assert_eq!(result.to_string_output(), "0.00 Bit/s");
}

#[test]
fn test_speed_division() {
    let speed = Speed::default();
    let result = speed / 2;

    assert_eq!(result.to_string_input(), "0.00 Bit/s");
    assert_eq!(result.to_string_output(), "0.00 Bit/s");
}

#[test]
fn test_stat_key_creation() {
    let key = StatKey {
        src_port: 80,
        dst_port: 443,
        src_ip: Ipv4Addr::new(192, 168, 1, 1),
        dst_ip: Ipv4Addr::new(192, 168, 1, 2),
        direction: Direction::Outgoing,
    };

    assert_eq!(key.src_port, 80);
    assert_eq!(key.dst_port, 443);
    assert_eq!(key.direction, Direction::Outgoing);
}

#[test]
fn test_stat_values_creation() {
    let values = StatValues { size: 1024 };
    assert_eq!(values.size, 1024);
}
