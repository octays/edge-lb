//! Backend Redirect-only return path.
//!
//! Ingress on the backend data-plane device learns reply ownership from
//! trusted DSCP requests. Egress on the underlay returns matching replies to
//! the gateway after rewriting only the Ethernet header.

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_REDIRECT, TC_ACT_SHOT},
    helpers::bpf_redirect,
    macros::map,
    maps::{HashMap, LruHashMap, PerCpuArray},
    programs::TcContext,
};
use edge_lb_common::backend_redirect::{
    BACKEND_RETURN_DSCP_CAPACITY, BACKEND_RETURN_FLOW_CAPACITY, BACKEND_RETURN_FLOW_TTL_NS,
    BackendReturnDscp, BackendReturnFlow, BackendReturnFlowKey, BackendReturnStats,
};

#[map]
static BACKEND_RETURN_DSCP: HashMap<u32, BackendReturnDscp> =
    HashMap::with_max_entries(BACKEND_RETURN_DSCP_CAPACITY, 0);

#[map]
static BACKEND_RETURN_FLOWS: LruHashMap<BackendReturnFlowKey, BackendReturnFlow> =
    LruHashMap::with_max_entries(BACKEND_RETURN_FLOW_CAPACITY, 0);

#[map]
static BACKEND_RETURN_STATS: PerCpuArray<BackendReturnStats> = PerCpuArray::with_max_entries(1, 0);

fn bump(update: impl FnOnce(&mut BackendReturnStats)) {
    if let Some(ptr) = BACKEND_RETURN_STATS.get_ptr_mut(0) {
        unsafe { update(&mut *ptr) };
    }
}

#[inline(always)]
fn unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

#[inline(always)]
fn parse(ctx: &TcContext) -> Result<([u8; 14], [u8; 20], u16, u16), ()> {
    let eth = ctx.load::<[u8; 14]>(0).map_err(|_| ())?;
    if u16::from_be_bytes([eth[12], eth[13]]) != 0x0800 {
        return Err(());
    }
    let ip = ctx.load::<[u8; 20]>(14).map_err(|_| ())?;
    if ip[0] != 0x45 || (u16::from_be_bytes([ip[6], ip[7]]) & 0xbfff) != 0 {
        return Err(());
    }
    let min = match ip[9] {
        6 => 40,
        17 => 28,
        _ => return Err(()),
    };
    let len = u16::from_be_bytes([ip[2], ip[3]]) as u32;
    if len < min || len + 14 != ctx.len() {
        return Err(());
    }
    let ports = ctx.load::<[u16; 2]>(34).map_err(|_| ())?;
    Ok((eth, ip, u16::from_be(ports[0]), u16::from_be(ports[1])))
}

pub fn ingress(ctx: &mut TcContext, now_ns: u64) -> i32 {
    let Ok((_eth, ip, sport, dport)) = parse(ctx) else {
        return TC_ACT_PIPE;
    };
    let dscp = u32::from(ip[1] >> 2);
    let Some(contract) = (unsafe { BACKEND_RETURN_DSCP.get(&dscp) }) else {
        bump(|s| s.dscp_miss += 1);
        return TC_ACT_PIPE;
    };
    let contract = *contract;
    if contract.return_ifindex == 0
        || !unicast_mac(contract.source_mac)
        || !unicast_mac(contract.destination_mac)
    {
        bump(|s| s.unsupported += 1);
        return TC_ACT_PIPE;
    }
    let flow = BackendReturnFlow {
        expires_ns: now_ns.saturating_add(BACKEND_RETURN_FLOW_TTL_NS),
        return_ifindex: contract.return_ifindex,
        source_mac: contract.source_mac,
        destination_mac: contract.destination_mac,
        _pad: [0; 2],
    };
    let key = BackendReturnFlowKey {
        src: u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]),
        dst: u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]),
        sport: dport,
        dport: sport,
        proto: ip[9],
        _pad: [0; 3],
    };
    let _ = BACKEND_RETURN_FLOWS.insert(&key, &flow, 0);
    bump(|s| s.learned += 1);
    TC_ACT_PIPE
}

pub fn egress(ctx: &mut TcContext, now_ns: u64) -> i32 {
    let Ok((_eth, ip, sport, dport)) = parse(ctx) else {
        return TC_ACT_PIPE;
    };
    let key = BackendReturnFlowKey {
        src: u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]),
        dst: u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]),
        sport,
        dport,
        proto: ip[9],
        _pad: [0; 3],
    };
    let Some(flow) = (unsafe { BACKEND_RETURN_FLOWS.get(&key) }) else {
        bump(|s| s.flow_miss += 1);
        return TC_ACT_PIPE;
    };
    let flow = *flow;
    if flow.expires_ns <= now_ns {
        let _ = BACKEND_RETURN_FLOWS.remove(&key);
        bump(|s| s.expired += 1);
        return TC_ACT_PIPE;
    }
    if flow.return_ifindex == 0
        || !unicast_mac(flow.source_mac)
        || !unicast_mac(flow.destination_mac)
    {
        bump(|s| s.unsupported += 1);
        return TC_ACT_PIPE;
    }
    let mut macs = [0u8; 12];
    macs[..6].copy_from_slice(&flow.destination_mac);
    macs[6..].copy_from_slice(&flow.source_mac);
    if ctx.store(0, &macs, 0).is_err() {
        bump(|s| s.mutation_error += 1);
        return TC_ACT_SHOT;
    }
    if unsafe { (*ctx.skb.skb).ifindex } == flow.return_ifindex {
        bump(|s| s.submitted += 1);
        return TC_ACT_PIPE;
    }
    let action = unsafe { bpf_redirect(flow.return_ifindex, 0) } as i32;
    if action == TC_ACT_REDIRECT {
        bump(|s| s.submitted += 1);
        action
    } else {
        bump(|s| s.mutation_error += 1);
        TC_ACT_SHOT
    }
}
