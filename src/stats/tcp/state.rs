//! TCP state machine implementation.
//!
//! This module defines the TcpState enum and implements the TCP state
//! machine transition logic as defined in RFC 793.

/// TCP connection state as defined in RFC 793.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// Initial state, connection not yet established
    Closed,
    /// Connection attempt sent, waiting for ACK
    SynSent,
    /// Received SYN, sent SYN+ACK, waiting for ACK
    SynReceived,
    /// Connection established, data transfer possible
    Established,
    /// Application initiated close, waiting for ACK
    FinWait1,
    /// Received ACK for FIN, waiting for remote FIN
    FinWait2,
    /// Received remote FIN, waiting for application to close
    CloseWait,
    /// Application closed, sent FIN, waiting for ACK
    Closing,
    /// Sent FIN and received ACK, waiting for remote FIN
    LastAck,
    /// Received FIN and sent ACK, waiting for application to close
    TimeWait,
    /// Unknown or invalid state
    Unknown,
}

impl TcpState {
    /// Get the color name for UI rendering of this state.
    ///
    /// Returns a color name that can be used with ratatui's Color.
    pub fn color(&self) -> &str {
        match self {
            TcpState::Established => "green",
            TcpState::SynSent | TcpState::SynReceived => "cyan",
            TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing => "yellow",
            TcpState::TimeWait => "blue",
            TcpState::CloseWait | TcpState::LastAck => "magenta",
            TcpState::Closed => "dark_gray",
            TcpState::Unknown => "gray",
        }
    }

    /// Get a short display name for the state.
    pub fn short_name(&self) -> &str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RECV",
            TcpState::Established => "ESTAB",
            TcpState::FinWait1 => "FIN_W1",
            TcpState::FinWait2 => "FIN_W2",
            TcpState::CloseWait => "CLOSE_W",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WT",
            TcpState::Unknown => "UNKNOWN",
        }
    }

    /// Get an ultra-short display name (3 characters max) for compact UI.
    pub fn short_name_3char(&self) -> &str {
        match self {
            TcpState::Closed => "CLS",
            TcpState::SynSent => "SYN",
            TcpState::SynReceived => "SYR",
            TcpState::Established => "EST",
            TcpState::FinWait1 => "FW1",
            TcpState::FinWait2 => "FW2",
            TcpState::CloseWait => "CW",
            TcpState::Closing => "CLO",
            TcpState::LastAck => "LA",
            TcpState::TimeWait => "TW",
            TcpState::Unknown => "UNK",
        }
    }

    /// Determine the next state based on current state and TCP flags.
    ///
    /// This implements a simplified TCP state machine transition logic.
    pub fn transition(&self, syn: bool, ack: bool, fin: bool, rst: bool) -> Self {
        // RST immediately transitions to Closed
        if rst {
            return TcpState::Closed;
        }

        match self {
            TcpState::Closed | TcpState::Unknown => {
                if syn && !ack {
                    TcpState::SynSent
                } else if ack && !syn && !fin {
                    // ACK without SYN indicates an already-established connection
                    // (mid-connection monitoring scenario)
                    TcpState::Established
                } else {
                    *self
                }
            }
            TcpState::SynSent => {
                if syn && ack {
                    TcpState::SynReceived
                } else if ack && !syn {
                    TcpState::Established
                } else {
                    *self
                }
            }
            TcpState::SynReceived => {
                if ack && !syn {
                    TcpState::Established
                } else if fin {
                    TcpState::FinWait1
                } else {
                    *self
                }
            }
            TcpState::Established => {
                if fin {
                    TcpState::FinWait1
                } else {
                    *self
                }
            }
            TcpState::FinWait1 => {
                if ack && !fin {
                    TcpState::FinWait2
                } else if fin && ack {
                    TcpState::TimeWait
                } else if fin {
                    TcpState::Closing
                } else {
                    *self
                }
            }
            TcpState::FinWait2 => {
                if fin {
                    TcpState::TimeWait
                } else {
                    *self
                }
            }
            TcpState::CloseWait => {
                if fin {
                    TcpState::LastAck
                } else {
                    *self
                }
            }
            TcpState::Closing => {
                if ack && !fin {
                    TcpState::TimeWait
                } else {
                    *self
                }
            }
            TcpState::LastAck => {
                if ack && !fin {
                    TcpState::Closed
                } else {
                    *self
                }
            }
            TcpState::TimeWait => {
                // TimeWait eventually expires to Closed
                // This is handled externally via timeout
                *self
            }
        }
    }

    /// Create a TcpState from TCP flags directly.
    ///
    /// This is a simpler alternative that maps flag combinations to states
    /// without full state machine tracking.
    ///
    /// Note: ACK-only packets (ack=true, syn=false, fin=false) indicate
    /// an established connection, which handles the mid-connection
    /// monitoring scenario where we start tracking after the handshake.
    pub fn from_flags(syn: bool, ack: bool, fin: bool, rst: bool) -> Self {
        if rst {
            return TcpState::Closed;
        }

        match (syn, ack, fin) {
            (true, false, false) => TcpState::SynSent,
            (true, true, false) => TcpState::SynReceived,
            (false, true, false) => TcpState::Established,
            (false, _, true) => TcpState::FinWait1,
            (false, false, false) => TcpState::Unknown,
            _ => TcpState::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_state_closed() {
        let state = TcpState::Closed;
        assert_eq!(state.color(), "dark_gray");
        assert_eq!(state.short_name(), "CLOSED");
    }

    #[test]
    fn test_tcp_state_established() {
        let state = TcpState::Established;
        assert_eq!(state.color(), "green");
        assert_eq!(state.short_name(), "ESTAB");
    }

    #[test]
    fn test_tcp_state_from_flags() {
        assert_eq!(
            TcpState::from_flags(true, false, false, false),
            TcpState::SynSent
        );
        assert_eq!(
            TcpState::from_flags(true, true, false, false),
            TcpState::SynReceived
        );
        assert_eq!(
            TcpState::from_flags(false, true, false, false),
            TcpState::Established
        );
        assert_eq!(
            TcpState::from_flags(false, false, true, false),
            TcpState::FinWait1
        );
        assert_eq!(
            TcpState::from_flags(false, false, false, true),
            TcpState::Closed
        );
    }

    #[test]
    fn test_tcp_state_transition_syn_to_established() {
        let state = TcpState::Closed;
        // SYN sent
        let state = state.transition(true, false, false, false);
        assert_eq!(state, TcpState::SynSent);
        // ACK received
        let state = state.transition(false, true, false, false);
        assert_eq!(state, TcpState::Established);
    }

    #[test]
    fn test_tcp_state_rst_closes() {
        let state = TcpState::Established;
        let state = state.transition(false, false, false, true);
        assert_eq!(state, TcpState::Closed);
    }

    #[test]
    fn test_tcp_state_mid_connection_monitoring() {
        // Simulate starting monitoring mid-connection (first packet is ACK-only)
        let state = TcpState::Closed;
        let state = state.transition(false, true, false, false);
        // Should recognize this as an established connection
        assert_eq!(state, TcpState::Established);
    }

    #[test]
    fn test_tcp_state_from_flags_ack_only() {
        // ACK-only packets indicate established connection
        assert_eq!(
            TcpState::from_flags(false, true, false, false),
            TcpState::Established
        );
    }
}
