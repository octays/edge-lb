//! Forward redirect after successful DNAT. No fallthrough after mutation.

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::map,
    maps::{HashMap, PerCpuArray},
    programs::TcContext,
};
use edge_lb_common::{
    NativeTargetKey,
    redirect::{
        NATIVE_LOCAL_ADDRS_CAPACITY, NATIVE_TARGET_ROUTES_CAPACITY, NativeRedirectStats,
        NativeTargetRoute, RedirectFallback, RedirectPacket,
    },
};

#[map]
static NATIVE_TARGET_ROUTES: HashMap<NativeTargetKey, NativeTargetRoute> =
    HashMap::with_max_entries(NATIVE_TARGET_ROUTES_CAPACITY, 0);

#[map]
static NATIVE_REDIRECT_STATS: PerCpuArray<NativeRedirectStats> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static NATIVE_LOCAL_ADDRS: HashMap<u32, u32> =
    HashMap::with_max_entries(NATIVE_LOCAL_ADDRS_CAPACITY, 0);

fn bump(update: impl FnOnce(&mut NativeRedirectStats)) {
    if let Some(ptr) = NATIVE_REDIRECT_STATS.get_ptr_mut(0) {
        unsafe { update(&mut *ptr) };
    }
}

fn fallback(reason: RedirectFallback) -> i32 {
    bump(|stats| match reason {
        RedirectFallback::InvalidRoute => stats.route_invalid += 1,
        RedirectFallback::Expired => stats.expired += 1,
        RedirectFallback::TargetChanged => stats.target_changed += 1,
        RedirectFallback::Ttl => stats.ttl += 1,
        RedirectFallback::Mtu => stats.mtu += 1,
        RedirectFallback::Unsupported => stats.unsupported += 1,
    });
    TC_ACT_PIPE
}

#[inline(always)]
pub fn forward(ctx: &mut TcContext, key: NativeTargetKey, now_ns: u64) -> i32 {
    let Some(route) = (unsafe { NATIVE_TARGET_ROUTES.get(&key) }) else {
        bump(|stats| stats.route_miss += 1);
        return TC_ACT_PIPE;
    };
    let route = *route;
    let Ok(ip) = ctx.load::<[u8; 20]>(14) else {
        return fallback(RedirectFallback::Unsupported);
    };
    let skb = ctx.skb.skb;
    // These packets still need the kernel's fragmentation/options/offload
    // handling. A marked or non-host packet may have additional policy.
    if ip[0] != 0x45
        || u16::from_be_bytes([ip[6], ip[7]]) & 0xbfff != 0
        || unsafe {
            (*skb).mark != 0
                || (*skb).pkt_type != 0
                || (*skb).vlan_present != 0
                || (*skb).gso_segs > 1
                || (*skb).gso_size != 0
        }
    {
        return fallback(RedirectFallback::Unsupported);
    }
    let ip_len = u16::from_be_bytes([ip[2], ip[3]]) as u32;
    let source = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
    if ip[12] == 0
        || ip[12] == 127
        || ip[12] >= 224
        || (ip[12] == 169 && ip[13] == 254)
        || unsafe { NATIVE_LOCAL_ADDRS.get(&source).is_some() }
    {
        return fallback(RedirectFallback::Unsupported);
    }
    // load/store use skb helpers, not direct payload pointers. A non-linear
    // payload is valid; store_bytes makes only the modified headers writable.
    // GSO remains excluded above, without pulling/copying the whole payload.
    if ip_len + 14 != ctx.len() {
        return fallback(RedirectFallback::Unsupported);
    }
    let min_len = match ip[9] {
        6 => 40,
        17 => 28,
        _ => return fallback(RedirectFallback::Unsupported),
    };
    if ip_len < min_len {
        return fallback(RedirectFallback::Unsupported);
    }
    let Ok(port) = ctx.load::<u16>(36) else {
        return fallback(RedirectFallback::Unsupported);
    };
    let packet = RedirectPacket {
        target: u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]),
        target_port: u16::from_be(port),
        ingress_ifindex: unsafe { (*skb).ingress_ifindex },
        ip_len,
        ttl: ip[8],
        dscp: ip[1] >> 2,
    };
    if let Err(reason) = route.validate(&packet, now_ns) {
        return fallback(reason);
    }
    let mut sum = 0u32;
    let mut offset = 0usize;
    while offset < 20 {
        sum += u16::from_be_bytes([ip[offset], ip[offset + 1]]) as u32;
        offset += 2;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    if sum != 0xffff {
        return fallback(RedirectFallback::Unsupported);
    }
    match super::redirect_packet::transmit(
        ctx,
        ip,
        route.ifindex,
        route.source_mac,
        route.destination_mac,
    ) {
        Ok(action) => {
            bump(|stats| stats.submitted += 1);
            action
        }
        Err(()) => {
            bump(|stats| stats.mutation_error += 1);
            TC_ACT_SHOT
        }
    }
}
