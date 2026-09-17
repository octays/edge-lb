//! Backend Redirect-only return path ABI.

pub const BACKEND_RETURN_INGRESS_PROGRAM: &str = "backend_return_ingress";
pub const BACKEND_RETURN_EGRESS_PROGRAM: &str = "backend_return_egress";
pub const BACKEND_RETURN_DSCP_MAP: &str = "BACKEND_RETURN_DSCP";
pub const BACKEND_RETURN_FLOWS_MAP: &str = "BACKEND_RETURN_FLOWS";
pub const BACKEND_RETURN_STATS_MAP: &str = "BACKEND_RETURN_STATS";
pub const BACKEND_RETURN_DSCP_CAPACITY: u32 = 64;
pub const BACKEND_RETURN_FLOW_CAPACITY: u32 = 262_144;
pub const BACKEND_RETURN_FLOW_TTL_NS: u64 = 3 * 60 * 60 * 1_000_000_000;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendReturnDscp {
    pub flags: u32,
    pub return_ifindex: u32,
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub _pad: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BackendReturnFlowKey {
    /// IPv4 source address in host order.
    pub src: u32,
    /// IPv4 destination address in host order.
    pub dst: u32,
    /// L4 source port in host order.
    pub sport: u16,
    /// L4 destination port in host order.
    pub dport: u16,
    /// IP protocol number.
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendReturnFlow {
    pub expires_ns: u64,
    pub return_ifindex: u32,
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendReturnStats {
    pub learned: u64,
    pub submitted: u64,
    pub dscp_miss: u64,
    pub flow_miss: u64,
    pub expired: u64,
    pub unsupported: u64,
    pub mutation_error: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendReturnDscp {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendReturnFlowKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendReturnFlow {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendReturnStats {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_return_abi_layout_is_stable() {
        assert_eq!(core::mem::size_of::<BackendReturnDscp>(), 24);
        assert_eq!(core::mem::size_of::<BackendReturnFlowKey>(), 16);
        assert_eq!(core::mem::offset_of!(BackendReturnFlowKey, proto), 12);
        assert_eq!(core::mem::size_of::<BackendReturnFlow>(), 32);
        assert_eq!(core::mem::size_of::<BackendReturnStats>(), 56);
    }
}
