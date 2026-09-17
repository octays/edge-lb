//! Shared redirect-map ABI and packet-independent route validation.

pub const NATIVE_TARGET_ROUTES_MAP: &str = "NATIVE_TARGET_ROUTES";
pub const NATIVE_REDIRECT_STATS_MAP: &str = "NATIVE_REDIRECT_STATS";
pub const NATIVE_LOCAL_ADDRS_MAP: &str = "NATIVE_LOCAL_ADDRS";
pub const NATIVE_LOCAL_ADDRS_CAPACITY: u32 = 4096;
pub const NATIVE_TARGET_ROUTES_CAPACITY: u32 = 16_384;

/// All scalar addresses/ports are host order, matching NativeFlowValue.
/// MAC addresses belong to the selected output link and its next hop.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeTargetRoute {
    pub expires_ns: u64,
    pub target: u32,
    pub ingress_ifindex: u32,
    pub ifindex: u32,
    pub mtu: u32,
    pub target_port: u16,
    pub dscp: u8,
    pub _pad: u8,
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectFallback {
    InvalidRoute,
    Expired,
    TargetChanged,
    Ttl,
    Mtu,
    Unsupported,
}

pub struct RedirectPacket {
    pub target: u32,
    pub target_port: u16,
    pub ingress_ifindex: u32,
    pub ip_len: u32,
    pub ttl: u8,
    pub dscp: u8,
}

impl NativeTargetRoute {
    #[inline(always)]
    pub fn validate(&self, packet: &RedirectPacket, now_ns: u64) -> Result<(), RedirectFallback> {
        if self.ifindex == 0
            || self.ingress_ifindex == 0
            || self.mtu < 68
            || self.dscp > 63
            || self._pad != 0
            || !unicast_mac(self.source_mac)
            || !unicast_mac(self.destination_mac)
        {
            return Err(RedirectFallback::InvalidRoute);
        }
        if self.expires_ns <= now_ns {
            return Err(RedirectFallback::Expired);
        }
        if self.target != packet.target || self.target_port != packet.target_port {
            return Err(RedirectFallback::TargetChanged);
        }
        if self.ingress_ifindex != packet.ingress_ifindex || self.dscp != packet.dscp {
            return Err(RedirectFallback::Unsupported);
        }
        if packet.ttl <= 1 {
            return Err(RedirectFallback::Ttl);
        }
        if packet.ip_len > self.mtu {
            return Err(RedirectFallback::Mtu);
        }
        Ok(())
    }
}

#[inline(always)]
fn unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

/// Separate map: adding redirect counters does not resize NATIVE_STATS.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeRedirectStats {
    pub submitted: u64,
    pub route_miss: u64,
    pub route_invalid: u64,
    pub expired: u64,
    pub target_changed: u64,
    pub ttl: u64,
    pub mtu: u64,
    pub unsupported: u64,
    pub mutation_error: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeTargetRoute {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeRedirectStats {}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> NativeTargetRoute {
        NativeTargetRoute {
            expires_ns: 100,
            target: 0xc0000214,
            ingress_ifindex: 2,
            ifindex: 7,
            mtu: 1450,
            target_port: 8080,
            dscp: 46,
            source_mac: [2, 0, 0, 0, 0, 1],
            destination_mac: [2, 0, 0, 0, 0, 2],
            ..Default::default()
        }
    }

    fn packet() -> RedirectPacket {
        let route = route();
        RedirectPacket {
            target: route.target,
            target_port: route.target_port,
            ingress_ifindex: route.ingress_ifindex,
            ip_len: 1450,
            ttl: 64,
            dscp: 46,
        }
    }

    #[test]
    fn redirect_abi_has_no_implicit_padding() {
        assert_eq!(core::mem::size_of::<NativeTargetRoute>(), 40);
        assert_eq!(core::mem::offset_of!(NativeTargetRoute, target_port), 24);
        assert_eq!(core::mem::offset_of!(NativeTargetRoute, source_mac), 28);
        assert_eq!(core::mem::size_of::<NativeRedirectStats>(), 72);
    }

    #[test]
    fn route_expires_at_deadline() {
        assert_eq!(route().validate(&packet(), 99), Ok(()));
        assert_eq!(
            route().validate(&packet(), 100),
            Err(RedirectFallback::Expired)
        );
    }

    #[test]
    fn reused_target_slot_cannot_redirect_an_old_flow() {
        let mut packet = packet();
        packet.target += 1;
        assert_eq!(
            route().validate(&packet, 1),
            Err(RedirectFallback::TargetChanged)
        );
        packet.target = route().target;
        packet.target_port += 1;
        assert_eq!(
            route().validate(&packet, 1),
            Err(RedirectFallback::TargetChanged)
        );
    }

    #[test]
    fn ttl_and_mtu_boundaries() {
        let mut packet = packet();
        packet.ttl = 1;
        assert_eq!(route().validate(&packet, 1), Err(RedirectFallback::Ttl));
        packet.ttl = 2;
        assert_eq!(route().validate(&packet, 1), Ok(()));
        packet.ip_len += 1;
        assert_eq!(route().validate(&packet, 1), Err(RedirectFallback::Mtu));
    }

    #[test]
    fn foreign_ingress_and_dscp_are_not_admitted() {
        let mut packet = packet();
        packet.ingress_ifindex += 1;
        assert_eq!(
            route().validate(&packet, 1),
            Err(RedirectFallback::Unsupported)
        );
        packet.ingress_ifindex = route().ingress_ifindex;
        packet.dscp = 0;
        assert_eq!(
            route().validate(&packet, 1),
            Err(RedirectFallback::Unsupported)
        );
    }

    #[test]
    fn incomplete_route_is_not_usable() {
        for invalid in [
            NativeTargetRoute {
                ifindex: 0,
                ..route()
            },
            NativeTargetRoute { mtu: 0, ..route() },
            NativeTargetRoute {
                source_mac: [0; 6],
                ..route()
            },
            NativeTargetRoute {
                destination_mac: [255; 6],
                ..route()
            },
            NativeTargetRoute { _pad: 1, ..route() },
        ] {
            assert_eq!(
                invalid.validate(&packet(), 1),
                Err(RedirectFallback::InvalidRoute)
            );
        }
    }
}
