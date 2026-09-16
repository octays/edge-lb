//! Return admission ABI. No client route, MAC, flow or user-controlled switch.

pub const NATIVE_RETURN_LEASES_MAP: &str = "NATIVE_RETURN_LEASES";
pub const NATIVE_RETURN_STATS_MAP: &str = "NATIVE_RETURN_STATS";
pub const NATIVE_RETURN_LEASES_CAPACITY: u32 = 16_384;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReturnLeaseKey {
    pub ingress_ifindex: u32,
    pub ifindex: u32,
    /// Host byte order; only currently owned local IPv4 addresses are admitted.
    pub source: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReturnLease {
    pub expires_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReturnRedirectStats {
    pub submitted: u64,
    pub policy: u64,
    pub expired: u64,
    pub route: u64,
    pub neighbor: u64,
    pub ttl: u64,
    pub mtu: u64,
    pub unsupported: u64,
    pub mutation_error: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ReturnLeaseKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ReturnLease {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ReturnRedirectStats {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_abi_has_no_padding_or_forward_stats_dependency() {
        assert_eq!(core::mem::size_of::<ReturnLeaseKey>(), 12);
        assert_eq!(core::mem::offset_of!(ReturnLeaseKey, source), 8);
        assert_eq!(core::mem::size_of::<ReturnLease>(), 8);
        assert_eq!(core::mem::size_of::<ReturnRedirectStats>(), 72);
    }
}
