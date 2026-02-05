//! TCP protocol flag constants.
//!
//! This module defines the TCP control flags used in packet processing.
//! These constants correspond to the bit positions in the TCP header flags field.

/// TCP FIN flag (0x01) - No more data from sender
pub const TCP_FIN: u8 = 0x01;

/// TCP SYN flag (0x02) - Synchronize sequence numbers
pub const TCP_SYN: u8 = 0x02;

/// TCP RST flag (0x04) - Reset the connection
pub const TCP_RST: u8 = 0x04;

/// TCP PSH flag (0x08) - Push function
pub const TCP_PSH: u8 = 0x08;

/// TCP ACK flag (0x10) - Acknowledgment field significant
pub const TCP_ACK: u8 = 0x10;

/// TCP URG flag (0x20) - Urgent pointer field significant
pub const TCP_URG: u8 = 0x20;

/// TCP ECE flag (0x40) - ECN-Echo (explicit congestion notification)
pub const TCP_ECE: u8 = 0x40;

/// TCP CWR flag (0x80) - Congestion window reduced
pub const TCP_CWR: u8 = 0x80;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_are_powers_of_two() {
        // All TCP flags should be powers of two (single bit set)
        assert!(TCP_FIN.is_power_of_two());
        assert!(TCP_SYN.is_power_of_two());
        assert!(TCP_RST.is_power_of_two());
        assert!(TCP_PSH.is_power_of_two());
        assert!(TCP_ACK.is_power_of_two());
        assert!(TCP_URG.is_power_of_two());
        assert!(TCP_ECE.is_power_of_two());
        assert!(TCP_CWR.is_power_of_two());
    }

    #[test]
    fn test_tcp_flag_values() {
        assert_eq!(TCP_FIN, 0x01);
        assert_eq!(TCP_SYN, 0x02);
        assert_eq!(TCP_RST, 0x04);
        assert_eq!(TCP_ACK, 0x10);
    }

    #[test]
    fn test_tcp_flag_combinations() {
        // Common flag combinations
        let syn_ack = TCP_SYN | TCP_ACK;
        assert_eq!(syn_ack, 0x12);

        let fin_ack = TCP_FIN | TCP_ACK;
        assert_eq!(fin_ack, 0x11);

        let rst_ack = TCP_RST | TCP_ACK;
        assert_eq!(rst_ack, 0x14);
    }
}
