//! Full per-packet FIB lookup, constrained by userspace admission leases.

use super::redirect_packet;
use aya_ebpf::{
    EbpfContext,
    bindings::{self, TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::bpf_fib_lookup,
    macros::map,
    maps::{HashMap, PerCpuArray},
    programs::TcContext,
};
use edge_lb_common::return_redirect::{
    NATIVE_RETURN_LEASES_CAPACITY, ReturnLease, ReturnLeaseKey, ReturnRedirectStats,
};

#[map]
static NATIVE_RETURN_LEASES: HashMap<ReturnLeaseKey, ReturnLease> =
    HashMap::with_max_entries(NATIVE_RETURN_LEASES_CAPACITY, 0);
#[map]
static NATIVE_RETURN_STATS: PerCpuArray<ReturnRedirectStats> = PerCpuArray::with_max_entries(1, 0);

fn bump(update: impl FnOnce(&mut ReturnRedirectStats)) {
    if let Some(ptr) = NATIVE_RETURN_STATS.get_ptr_mut(0) {
        unsafe { update(&mut *ptr) };
    }
}

pub fn forward(ctx: &mut TcContext, now_ns: u64) -> i32 {
    let Ok(ip) = redirect_packet::read(ctx) else {
        bump(|s| s.unsupported += 1);
        return TC_ACT_PIPE;
    };
    if ip[8] <= 1 {
        bump(|s| s.ttl += 1);
        return TC_ACT_PIPE;
    }
    let source = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
    let destination = u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]);
    if !redirect_packet::unicast_address(source) || !redirect_packet::unicast_address(destination) {
        bump(|s| s.unsupported += 1);
        return TC_ACT_PIPE;
    }
    let Ok(ports) = ctx.load::<[u16; 2]>(34) else {
        bump(|s| s.unsupported += 1);
        return TC_ACT_PIPE;
    };
    // Use the actual overlay hook device, not skb_iif retained from an outer packet.
    let ingress_ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let mut fib: bindings::bpf_fib_lookup = unsafe { core::mem::zeroed() };
    fib.family = 2; // AF_INET
    fib.l4_protocol = ip[9];
    fib.sport = ports[0];
    fib.dport = ports[1];
    fib.ifindex = ingress_ifindex;
    fib.__bindgen_anon_1.tot_len = u16::from_be_bytes([ip[2], ip[3]]);
    fib.__bindgen_anon_2.tos = ip[1];
    fib.__bindgen_anon_3.ipv4_src = source.to_be();
    fib.__bindgen_anon_4.ipv4_dst = destination.to_be();
    // No DIRECT/OUTPUT/SKIP_NEIGH/SRC: preserve full lookup and flow's VIP.
    let result = unsafe {
        bpf_fib_lookup(
            ctx.as_ptr(),
            &mut fib,
            core::mem::size_of_val(&fib) as i32,
            0,
        )
    };
    if result != bindings::BPF_FIB_LKUP_RET_SUCCESS as i64 {
        bump(|s| match result as u32 {
            bindings::BPF_FIB_LKUP_RET_NO_NEIGH => s.neighbor += 1,
            bindings::BPF_FIB_LKUP_RET_FRAG_NEEDED => s.mtu += 1,
            _ => s.route += 1,
        });
        return TC_ACT_PIPE;
    }
    let key = ReturnLeaseKey {
        ingress_ifindex,
        ifindex: fib.ifindex,
        source,
    };
    let Some(lease) = (unsafe { NATIVE_RETURN_LEASES.get(&key) }) else {
        bump(|s| s.policy += 1);
        return TC_ACT_PIPE;
    };
    if lease.expires_ns <= now_ns {
        bump(|s| s.expired += 1);
        return TC_ACT_PIPE;
    }
    if fib.ifindex == 0
        || fib.ifindex == ingress_ifindex
        || !redirect_packet::unicast_mac(fib.smac)
        || !redirect_packet::unicast_mac(fib.dmac)
        || unsafe { fib.__bindgen_anon_5.__bindgen_anon_1.h_vlan_proto != 0 }
    {
        bump(|s| s.unsupported += 1);
        return TC_ACT_PIPE;
    }
    match redirect_packet::transmit(ctx, ip, fib.ifindex, fib.smac, fib.dmac) {
        Ok(action) => {
            bump(|s| s.submitted += 1);
            action
        }
        Err(()) => {
            bump(|s| s.mutation_error += 1);
            TC_ACT_SHOT
        }
    }
}
