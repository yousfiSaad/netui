//! Backward compatibility module for network constants.
//! Re-exports network constants from parent module.

pub use super::{
    ARP_PACKET_SIZE, ETHERNET_ARP_BUFFER_SIZE, ETHERNET_HEADER_SIZE, HOOK_TC_EGRESS,
    HOOK_TC_INGRESS, HOOK_XDP, MIN_IPV4_HEADER_SIZE,
};
