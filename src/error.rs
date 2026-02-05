//! Common error types for the application.

use std::error::Error;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;

/// Application result type.
///
/// This is a convenience type alias for Result with our structured error type.
pub type AppResult<T> = std::result::Result<T, NetuiError>;

/// Main application error type.
///
/// This enum provides structured, type-safe error handling with context
/// for all error conditions in the application.
#[derive(Debug)]
pub enum NetuiError {
    /// Channel closed unexpectedly
    ChannelClosed,

    /// Network interface not found or unavailable
    InterfaceNotFound { name: String },

    /// Backend-specific error (pnet, eBPF, etc.)
    Backend(String),

    /// Packet processing failed
    PacketProcessing { context: String },

    /// I/O error (file, network, etc.)
    Io(io::Error),

    /// Channel send error (receiver dropped)
    ChannelSend(String),

    /// Invalid configuration
    InvalidConfig { message: String },

    /// eBPF loading/attachment error
    Ebpf(String),

    /// Host/DNS resolution error
    Resolution { host: Ipv4Addr, message: String },

    /// Generic error with message
    Message(String),
}

impl fmt::Display for NetuiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetuiError::ChannelClosed => {
                write!(f, "Channel closed unexpectedly")
            }
            NetuiError::InterfaceNotFound { name } => {
                write!(f, "Interface not found: {}", name)
            }
            NetuiError::Backend(msg) => {
                write!(f, "Backend error: {}", msg)
            }
            NetuiError::PacketProcessing { context } => {
                write!(f, "Packet processing failed: {}", context)
            }
            NetuiError::Io(err) => {
                write!(f, "I/O error: {}", err)
            }
            NetuiError::ChannelSend(msg) => {
                write!(f, "Channel send failed: {}", msg)
            }
            NetuiError::InvalidConfig { message } => {
                write!(f, "Invalid configuration: {}", message)
            }
            NetuiError::Ebpf(msg) => {
                write!(f, "eBPF error: {}", msg)
            }
            NetuiError::Resolution { host, message } => {
                write!(f, "DNS resolution error for {}: {}", host, message)
            }
            NetuiError::Message(msg) => {
                write!(f, "{}", msg)
            }
        }
    }
}

impl Error for NetuiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NetuiError::Io(err) => Some(err),
            _ => None,
        }
    }
}

// Automatic conversions from common error types

impl From<io::Error> for NetuiError {
    fn from(err: io::Error) -> Self {
        NetuiError::Io(err)
    }
}

impl From<tokio::sync::mpsc::error::SendError<String>> for NetuiError {
    fn from(err: tokio::sync::mpsc::error::SendError<String>) -> Self {
        NetuiError::ChannelSend(err.to_string())
    }
}

impl From<&str> for NetuiError {
    fn from(msg: &str) -> Self {
        NetuiError::Message(msg.to_string())
    }
}

impl From<String> for NetuiError {
    fn from(msg: String) -> Self {
        NetuiError::Message(msg)
    }
}

impl From<Box<dyn Error + Send + Sync>> for NetuiError {
    fn from(err: Box<dyn Error + Send + Sync>) -> Self {
        NetuiError::Message(err.to_string())
    }
}
