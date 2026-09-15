//! TC classifier that pre-marks VIP traffic with a DSCP value.
//!
//! Attached at the gateway ingress before the native edge-lb datapath. Packets
//! whose IPv4 TCP/UDP destination port is listed in `TARGET_PORTS` get
//! `DSCP_CFG` written into the TOS byte (ECN bits are preserved) with an RFC
//! 1624 incremental checksum update, then the program returns `TC_ACT_PIPE` so
//! the native DNAT classifier still sees the packet.
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{__sk_buff, TC_ACT_PIPE},
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::TcContext,
};
use aya_ebpf_cty::c_long;
use edge_lb_common::{
    DEFAULT_DSCP, DSCP_PORT_MAP_CAPACITY, MAX_TARGETS_PER_LISTENER,
    NATIVE_CONSISTENT_HASH_BUCKET_MAP_CAPACITY, NATIVE_LISTENER_ID_CAPACITY,
    NATIVE_SELECT_CONSISTENT_HASH, NATIVE_SELECT_HASH, NATIVE_SELECT_LC, NATIVE_SELECT_PERSIST,
    NATIVE_SELECT_PRIORITY, NATIVE_SELECT_RR, NativeConsistentHashBucketKey,
    NativeConsistentHashBucketValue, NativeFlowEvent, NativeFlowKey, NativeFlowValue,
    NativeListenerLookupKey, NativeListenerLookupValue, NativeTargetKey, NativeTargetLoadKey,
    NativeTargetValue, Stats, native_consistent_flow_bucket,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static TARGET_PORTS: HashMap<u32, u32> = HashMap::with_max_entries(DSCP_PORT_MAP_CAPACITY, 0);

#[map]
static DSCP_CFG: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

#[map]
static NATIVE_LISTENERS: HashMap<NativeListenerLookupKey, NativeListenerLookupValue> =
    HashMap::with_max_entries(4096, 0);

#[map]
static NATIVE_TARGETS: HashMap<NativeTargetKey, NativeTargetValue> =
    HashMap::with_max_entries(16384, 0);

#[map]
static NATIVE_CHASH_BUCKETS: HashMap<
    NativeConsistentHashBucketKey,
    NativeConsistentHashBucketValue,
> = HashMap::with_max_entries(NATIVE_CONSISTENT_HASH_BUCKET_MAP_CAPACITY, 1);

#[map]
static NATIVE_RR_COUNTERS: Array<u32> = Array::with_max_entries(NATIVE_LISTENER_ID_CAPACITY, 0);

#[map]
static NATIVE_ACTIVE_FLOWS: HashMap<NativeTargetLoadKey, u32> = HashMap::with_max_entries(16384, 0);

#[map]
static NATIVE_FLOWS: LruHashMap<NativeFlowKey, NativeFlowValue> =
    LruHashMap::with_max_entries(1048576, 0);

#[map]
static NATIVE_FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static NATIVE_STATS: PerCpuArray<edge_lb_common::NativeDatapathStats> =
    PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
unsafe fn bpf_get_hash_recalc(skb: *mut __sk_buff) -> u32 {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff) -> u32 =
        unsafe { core::mem::transmute(34usize) };
    unsafe { fun(skb) }
}

#[classifier]
pub fn native_dnat_ingress(ctx: TcContext) -> i32 {
    match try_native_dnat_ingress(ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_native_dnat_ingress(mut ctx: TcContext) -> Result<i32, c_long> {
    let eth: EthHdr = ctx.load(0)?;
    if eth.ether_type != EtherType::Ipv4.into() {
        return Ok(TC_ACT_PIPE);
    }
    let ip_off = EthHdr::LEN;
    let ip: Ipv4Hdr = ctx.load(ip_off)?;
    if !ipv4_l4_supported(&ip) {
        return Ok(TC_ACT_PIPE);
    }
    let l4_off = ip_off + ip.ihl() as usize;
    let (dport, sport, l4_csum_off) = match ip.proto {
        IpProto::Tcp => {
            let tcp: TcpHdr = ctx.load(l4_off)?;
            (
                u16::from_be_bytes(tcp.dest),
                u16::from_be_bytes(tcp.source),
                l4_off + 16,
            )
        }
        IpProto::Udp => {
            let udp: UdpHdr = ctx.load(l4_off)?;
            (
                u16::from_be_bytes(udp.dst),
                u16::from_be_bytes(udp.src),
                l4_off + 6,
            )
        }
        _ => return Ok(TC_ACT_PIPE),
    };
    let preserve_zero_udp_checksum =
        ip.proto == IpProto::Udp && u16::from_be(ctx.load::<u16>(l4_csum_off)?) == 0;
    let flow_key = flow_key(&ip, sport, dport);
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(existing) = unsafe { NATIVE_FLOWS.get(&flow_key) } {
        let existing = *existing;
        let reverse_key = flow_key.reverse_for(existing);
        if !flow_expired(existing.last_seen_ns, existing.timeout_secs, now) {
            let mut refreshed = existing;
            refreshed.last_seen_ns = now;
            let _ = NATIVE_FLOWS.insert(&flow_key, &refreshed, 0);
            let _ = NATIVE_FLOWS.insert(&reverse_key, &refreshed, 0);
            rewrite_ipv4_destination(
                &mut ctx,
                ip_off,
                l4_off,
                l4_csum_off,
                // The packet still carries the listener VIP. Reuse the
                // cached backend selection for every packet in the flow, even
                // when the listener map has changed since the flow was
                // created.
                existing.vip,
                existing.target,
                dport,
                existing.target_port,
            )?;
            if preserve_zero_udp_checksum {
                ctx.store(l4_csum_off, &0u16, 0)?;
            }
            native_bump(|stats| stats.listener_hit += 1);
            native_bump(|stats| stats.rewritten += 1);
            return Ok(TC_ACT_PIPE);
        }
        let _ = NATIVE_FLOWS.remove(&flow_key);
        let _ = NATIVE_FLOWS.remove(&reverse_key);
        adjust_active_flows(existing.listener_id, existing.target_id, -1);
        emit_flow_event(flow_key, existing, 2);
        emit_flow_event(reverse_key, existing, 2);
    }
    let listener_key = NativeListenerLookupKey {
        vip: u32::from_be_bytes(ip.dst_addr),
        port: dport.to_be(),
        proto: ip.proto as u8,
        _pad: 0,
    };
    let Some(listener) = (unsafe { NATIVE_LISTENERS.get(&listener_key) }) else {
        native_bump(|stats| stats.listener_miss += 1);
        return Ok(TC_ACT_PIPE);
    };
    if listener.target_count == 0 {
        native_bump(|stats| stats.target_miss += 1);
        return Ok(TC_ACT_PIPE);
    }
    let packet_hash = if listener.select == NATIVE_SELECT_HASH {
        unsafe { bpf_get_hash_recalc(ctx.as_ptr() as *mut __sk_buff) }
    } else {
        0
    };
    let target_id = select_target(&flow_key, listener, packet_hash);
    if target_id >= MAX_TARGETS_PER_LISTENER {
        native_bump(|stats| stats.target_miss += 1);
        return Ok(TC_ACT_PIPE);
    }
    let target_key = NativeTargetKey {
        listener_id: listener.listener_id,
        target_id,
    };
    let Some(target) = (unsafe { NATIVE_TARGETS.get(&target_key) }) else {
        native_bump(|stats| stats.target_miss += 1);
        return Ok(TC_ACT_PIPE);
    };
    if target.flags & 1 == 0 || target.weight == 0 {
        native_bump(|stats| stats.target_miss += 1);
        return Ok(TC_ACT_PIPE);
    }
    let old_dst = u32::from_be_bytes(ip.dst_addr);
    let old_port = dport;
    let new_dst = target.address;
    let new_port = target.port;
    let reverse_key = make_flow_key(
        new_dst,
        u32::from_be_bytes(ip.src_addr),
        new_port,
        sport,
        ip.proto as u8,
    );
    let value = NativeFlowValue {
        listener_id: listener.listener_id,
        target_id,
        vip: old_dst,
        target: new_dst,
        vip_port: old_port.to_be(),
        target_port: new_port,
        timeout_secs: listener.timeout_secs,
        last_seen_ns: now,
    };
    let _ = NATIVE_FLOWS.insert(&flow_key, &value, 0);
    let _ = NATIVE_FLOWS.insert(&reverse_key, &value, 0);
    adjust_active_flows(listener.listener_id, target_id, 1);
    emit_flow_event(flow_key, value, 1);
    emit_flow_event(reverse_key, value, 1);
    rewrite_ipv4_destination(
        &mut ctx,
        ip_off,
        l4_off,
        l4_csum_off,
        old_dst,
        new_dst,
        old_port,
        new_port,
    )?;
    if preserve_zero_udp_checksum {
        ctx.store(l4_csum_off, &0u16, 0)?;
    }
    native_bump(|stats| stats.listener_hit += 1);
    native_bump(|stats| stats.rewritten += 1);
    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn emit_flow_event(key: NativeFlowKey, value: NativeFlowValue, op: u8) {
    let _ = NATIVE_FLOW_EVENTS.output(
        &NativeFlowEvent {
            key,
            value,
            op,
            _pad: [0; 7],
        },
        0,
    );
}

#[classifier]
pub fn native_dnat_return(ctx: TcContext) -> i32 {
    match try_native_dnat_return(ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_native_dnat_return(mut ctx: TcContext) -> Result<i32, c_long> {
    let eth: EthHdr = ctx.load(0)?;
    if eth.ether_type != EtherType::Ipv4.into() {
        return Ok(TC_ACT_PIPE);
    }
    let ip_off = EthHdr::LEN;
    let ip: Ipv4Hdr = ctx.load(ip_off)?;
    if !ipv4_l4_supported(&ip) {
        return Ok(TC_ACT_PIPE);
    }
    let l4_off = ip_off + ip.ihl() as usize;
    let (sport, dport, l4_csum_off) = match ip.proto {
        IpProto::Tcp => {
            let tcp: TcpHdr = ctx.load(l4_off)?;
            (
                u16::from_be_bytes(tcp.source),
                u16::from_be_bytes(tcp.dest),
                l4_off + 16,
            )
        }
        IpProto::Udp => {
            let udp: UdpHdr = ctx.load(l4_off)?;
            (
                u16::from_be_bytes(udp.src),
                u16::from_be_bytes(udp.dst),
                l4_off + 6,
            )
        }
        _ => return Ok(TC_ACT_PIPE),
    };
    let preserve_zero_udp_checksum =
        ip.proto == IpProto::Udp && u16::from_be(ctx.load::<u16>(l4_csum_off)?) == 0;
    let key = make_flow_key(
        u32::from_be_bytes(ip.src_addr),
        u32::from_be_bytes(ip.dst_addr),
        sport,
        dport,
        ip.proto as u8,
    );
    let Some(flow) = (unsafe { NATIVE_FLOWS.get(&key) }) else {
        native_bump(|stats| stats.return_miss += 1);
        return Ok(TC_ACT_PIPE);
    };
    let flow = *flow;
    let now = unsafe { bpf_ktime_get_ns() };
    if flow_expired(flow.last_seen_ns, flow.timeout_secs, now) {
        let _ = NATIVE_FLOWS.remove(&key);
        let forward_key = key.forward_for(flow);
        let _ = NATIVE_FLOWS.remove(&forward_key);
        adjust_active_flows(flow.listener_id, flow.target_id, -1);
        emit_flow_event(key, flow, 2);
        emit_flow_event(forward_key, flow, 2);
        native_bump(|stats| stats.return_miss += 1);
        return Ok(TC_ACT_PIPE);
    }
    let mut refreshed = flow;
    refreshed.last_seen_ns = now;
    let _ = NATIVE_FLOWS.insert(&key, &refreshed, 0);
    let forward_key = key.forward_for(flow);
    let _ = NATIVE_FLOWS.insert(&forward_key, &refreshed, 0);
    rewrite_ipv4_source(
        &mut ctx,
        ip_off,
        l4_off,
        l4_csum_off,
        flow.target,
        flow.vip,
        sport,
        u16::from_be(flow.vip_port),
    )?;
    if preserve_zero_udp_checksum {
        ctx.store(l4_csum_off, &0u16, 0)?;
    }
    native_bump(|stats| stats.rewritten += 1);
    Ok(TC_ACT_PIPE)
}

fn flow_key(ip: &Ipv4Hdr, sport: u16, dport: u16) -> NativeFlowKey {
    make_flow_key(
        u32::from_be_bytes(ip.src_addr),
        u32::from_be_bytes(ip.dst_addr),
        sport,
        dport,
        ip.proto as u8,
    )
}

#[inline(always)]
fn ipv4_l4_supported(ip: &Ipv4Hdr) -> bool {
    if ip.version() != 4 || ip.ihl() < 20 || (ip.proto != IpProto::Tcp && ip.proto != IpProto::Udp)
    {
        return false;
    }
    // Native DNAT/SNAT only rewrites packets where the complete L4 header is
    // present in this skb. Fragmented IPv4 packets need fragment tracking or
    // conntrack assistance, so pass them to the kernel unchanged instead of
    // creating incomplete flow entries.
    if ip.frag_offset() != 0 {
        return false;
    }
    let more_fragments = ip.frag_flags() & 0x1 != 0;
    !more_fragments
}

#[inline(always)]
fn make_flow_key(src: u32, dst: u32, sport: u16, dport: u16, proto: u8) -> NativeFlowKey {
    NativeFlowKey {
        src,
        dst,
        sport: sport.to_be(),
        dport: dport.to_be(),
        proto,
        _pad: [0; 3],
    }
}

fn flow_expired(last_seen_ns: u64, timeout_secs: u32, now_ns: u64) -> bool {
    if last_seen_ns == 0 || timeout_secs == 0 {
        return false;
    }
    now_ns.saturating_sub(last_seen_ns) > timeout_secs as u64 * 1_000_000_000
}

fn select_target(
    key: &NativeFlowKey,
    listener: &NativeListenerLookupValue,
    packet_hash: u32,
) -> u32 {
    if listener.target_count == 0 {
        return MAX_TARGETS_PER_LISTENER;
    }
    let count = if listener.target_count < MAX_TARGETS_PER_LISTENER {
        listener.target_count
    } else {
        MAX_TARGETS_PER_LISTENER
    };
    if listener.weight_total == 0 || listener.target_count == 0 {
        return MAX_TARGETS_PER_LISTENER;
    }
    match listener.select {
        // rr rotates over healthy target slots and ignores weight. Priority is
        // the weighted mode.
        NATIVE_SELECT_RR => select_round_robin(listener, count),
        NATIVE_SELECT_PRIORITY => select_weighted_round_robin(listener, count),
        // hash uses the kernel skb hash modulo target slots.
        NATIVE_SELECT_HASH => select_hash_slot(packet_hash, listener, count),
        // persist is stable per client address, unlike hash which includes
        // transport ports and therefore distributes new client connections.
        NATIVE_SELECT_PERSIST => select_persist_slot(key.src, listener, count),
        // consistent_hash is VIP-independent and uses a precomputed bucket
        // table so the TC path stays constant-time.
        NATIVE_SELECT_CONSISTENT_HASH => select_consistent_hash(key, listener, count),
        // lc chooses the healthy target with the fewest active flows. Ties
        // rotate through the per-listener cursor so an empty listener does not
        // send every first flow to target zero.
        NATIVE_SELECT_LC => select_least_connections(listener, count),
        // Unknown/default selectors fall back to RR. N2/N3 need metadata
        // outside this pure TCP/UDP DNAT model.
        _ => select_round_robin(listener, count),
    }
}

fn select_weighted_hash(hash: u32, listener: &NativeListenerLookupValue, count: u32) -> u32 {
    if listener.weight_total == 0 {
        return MAX_TARGETS_PER_LISTENER;
    }
    let mut cursor = hash % listener.weight_total;
    // Compile-time bound keeps this a bounded loop for the verifier; the
    // runtime-bound while-loop exceeded the kernel's jump-sequence limit.
    let mut index: u32 = 0;
    while index < MAX_TARGETS_PER_LISTENER {
        if index >= count {
            break;
        }
        let target_key = NativeTargetKey {
            listener_id: listener.listener_id,
            target_id: index,
        };
        if let Some(target) = unsafe { NATIVE_TARGETS.get(&target_key) } {
            if target.flags & 1 != 0 && target.weight > 0 {
                if cursor < target.weight as u32 {
                    return index;
                }
                cursor -= target.weight as u32;
            }
        }
        index += 1;
    }
    MAX_TARGETS_PER_LISTENER
}

fn select_hash_slot(hash: u32, listener: &NativeListenerLookupValue, count: u32) -> u32 {
    if count == 0 {
        return MAX_TARGETS_PER_LISTENER;
    }
    let candidate = hash % count;
    if target_slot_is_usable(listener.listener_id, candidate) {
        return candidate;
    }
    first_usable_target(listener.listener_id, count)
}

fn select_persist_slot(client_ip: u32, listener: &NativeListenerLookupValue, count: u32) -> u32 {
    if count == 0 {
        return MAX_TARGETS_PER_LISTENER;
    }
    let primary = ((client_ip & 0xff) ^ ((client_ip >> 24) & 0xff)) % count;
    if target_slot_is_usable(listener.listener_id, primary) {
        return primary;
    }
    let secondary = (((client_ip >> 8) & 0xff) ^ ((client_ip >> 16) & 0xff)) % count;
    if target_slot_is_usable(listener.listener_id, secondary) {
        return secondary;
    }
    first_usable_target(listener.listener_id, count)
}

fn select_weighted_round_robin(listener: &NativeListenerLookupValue, count: u32) -> u32 {
    // Listener IDs start at one, while Array indexes start at zero.
    let index = listener.listener_id.saturating_sub(1);
    let cursor = NATIVE_RR_COUNTERS
        .get_ptr_mut(index)
        .map(|ptr| {
            let current = unsafe { *ptr };
            unsafe { *ptr = current.wrapping_add(1) };
            current
        })
        .unwrap_or(0);
    select_weighted_hash(cursor, listener, count)
}

fn select_round_robin(listener: &NativeListenerLookupValue, count: u32) -> u32 {
    let index = listener.listener_id.saturating_sub(1);
    let cursor = NATIVE_RR_COUNTERS
        .get_ptr_mut(index)
        .map(|ptr| {
            let current = unsafe { *ptr };
            unsafe { *ptr = current.wrapping_add(1) };
            current
        })
        .unwrap_or(0);
    let mut offset = 0u32;
    while offset < MAX_TARGETS_PER_LISTENER {
        if offset >= count {
            break;
        }
        let candidate = cursor.wrapping_add(offset) % count;
        if target_slot_is_usable(listener.listener_id, candidate) {
            return candidate;
        }
        offset += 1;
    }
    MAX_TARGETS_PER_LISTENER
}

fn first_usable_target(listener_id: u32, count: u32) -> u32 {
    let mut index = 0u32;
    while index < MAX_TARGETS_PER_LISTENER {
        if index >= count {
            break;
        }
        if target_slot_is_usable(listener_id, index) {
            return index;
        }
        index += 1;
    }
    MAX_TARGETS_PER_LISTENER
}

fn target_slot_is_usable(listener_id: u32, target_id: u32) -> bool {
    let target_key = NativeTargetKey {
        listener_id,
        target_id,
    };
    if let Some(target) = unsafe { NATIVE_TARGETS.get(&target_key) } {
        target.flags & 1 != 0 && target.weight > 0
    } else {
        false
    }
}

fn select_consistent_hash(
    key: &NativeFlowKey,
    listener: &NativeListenerLookupValue,
    count: u32,
) -> u32 {
    let bucket_key = NativeConsistentHashBucketKey {
        listener_id: listener.listener_id,
        bucket: native_consistent_flow_bucket(key),
    };
    if let Some(value) = unsafe { NATIVE_CHASH_BUCKETS.get(&bucket_key) } {
        native_bump(|stats| stats.chash_bucket_hit += 1);
        let target_id = value.target_id;
        if target_id < count && target_slot_is_usable(listener.listener_id, target_id) {
            return target_id;
        }
        native_bump(|stats| stats.chash_bucket_unusable += 1);
    } else {
        native_bump(|stats| stats.chash_bucket_miss += 1);
    }
    native_bump(|stats| stats.chash_fallback += 1);
    first_usable_target(listener.listener_id, count)
}

fn select_least_connections(listener: &NativeListenerLookupValue, count: u32) -> u32 {
    let mut best = MAX_TARGETS_PER_LISTENER;
    let mut best_load = u32::MAX;
    let cursor = NATIVE_RR_COUNTERS
        .get_ptr_mut(listener.listener_id.saturating_sub(1))
        .map(|ptr| {
            let current = unsafe { *ptr };
            unsafe { *ptr = current.wrapping_add(1) };
            current
        })
        .unwrap_or(0);
    let mut index = 0u32;
    while index < MAX_TARGETS_PER_LISTENER {
        if index < count {
            let candidate = (cursor.wrapping_add(index)) % count;
            let key = NativeTargetKey {
                listener_id: listener.listener_id,
                target_id: candidate,
            };
            if let Some(target) = unsafe { NATIVE_TARGETS.get(&key) }
                && target.flags & 1 != 0
                && target.weight > 0
            {
                let load_key = NativeTargetLoadKey {
                    listener_id: listener.listener_id,
                    target_id: candidate,
                };
                let load = unsafe { NATIVE_ACTIVE_FLOWS.get(&load_key) }
                    .copied()
                    .unwrap_or(0);
                if load < best_load {
                    best = candidate;
                    best_load = load;
                }
            }
        }
        index += 1;
    }
    best
}

fn adjust_active_flows(listener_id: u32, target_id: u32, delta: i32) {
    let key = NativeTargetLoadKey {
        listener_id,
        target_id,
    };
    let current = unsafe { NATIVE_ACTIVE_FLOWS.get(&key) }
        .copied()
        .unwrap_or(0);
    let next = if delta.is_negative() {
        current.saturating_sub(delta.unsigned_abs())
    } else {
        current.saturating_add(delta as u32)
    };
    if next == 0 {
        let _ = NATIVE_ACTIVE_FLOWS.remove(&key);
    } else {
        let _ = NATIVE_ACTIVE_FLOWS.insert(&key, &next, 0);
    }
}

const BPF_F_PSEUDO_HDR: u64 = 1 << 4;

fn rewrite_ipv4_destination(
    ctx: &mut TcContext,
    ip_off: usize,
    l4_off: usize,
    l4_csum_off: usize,
    old_dst: u32,
    new_dst: u32,
    old_port: u16,
    new_port: u16,
) -> Result<(), c_long> {
    let old_dst_be = old_dst.to_be();
    let new_dst_be = new_dst.to_be();
    ctx.store(ip_off + 16, &new_dst_be, 0)?;
    ctx.l3_csum_replace(ip_off + 10, old_dst_be as u64, new_dst_be as u64, 4)?;
    ctx.l4_csum_replace(
        l4_csum_off,
        old_dst_be as u64,
        new_dst_be as u64,
        4 | BPF_F_PSEUDO_HDR,
    )?;
    ctx.store(l4_off + 2, &new_port.to_be(), 0)?;
    ctx.l4_csum_replace(
        l4_csum_off,
        old_port.to_be() as u64,
        new_port.to_be() as u64,
        2,
    )?;
    Ok(())
}

fn rewrite_ipv4_source(
    ctx: &mut TcContext,
    ip_off: usize,
    l4_off: usize,
    l4_csum_off: usize,
    old_src: u32,
    new_src: u32,
    old_port: u16,
    new_port: u16,
) -> Result<(), c_long> {
    let old_src_be = old_src.to_be();
    let new_src_be = new_src.to_be();
    ctx.store(ip_off + 12, &new_src_be, 0)?;
    ctx.l3_csum_replace(ip_off + 10, old_src_be as u64, new_src_be as u64, 4)?;
    ctx.l4_csum_replace(
        l4_csum_off,
        old_src_be as u64,
        new_src_be as u64,
        4 | BPF_F_PSEUDO_HDR,
    )?;
    ctx.store(l4_off, &new_port.to_be(), 0)?;
    ctx.l4_csum_replace(
        l4_csum_off,
        old_port.to_be() as u64,
        new_port.to_be() as u64,
        2,
    )?;
    Ok(())
}

fn native_bump(update: impl FnOnce(&mut edge_lb_common::NativeDatapathStats)) {
    if let Some(ptr) = NATIVE_STATS.get_ptr_mut(0) {
        unsafe {
            update(&mut *ptr);
        }
    }
}

#[classifier]
pub fn dscp_mark(ctx: TcContext) -> i32 {
    match try_dscp_mark(ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_dscp_mark(mut ctx: TcContext) -> Result<i32, c_long> {
    let eth: EthHdr = ctx.load(0)?;
    if eth.ether_type != EtherType::Ipv4.into() {
        return Ok(TC_ACT_PIPE);
    }
    let ip_off = EthHdr::LEN;
    let ip: Ipv4Hdr = ctx.load(ip_off)?;
    if ip.version() != 4 || ip.ihl() < 20 {
        return Ok(TC_ACT_PIPE);
    }
    if ip.proto != IpProto::Tcp && ip.proto != IpProto::Udp {
        return Ok(TC_ACT_PIPE);
    }

    // network-types' ihl() is already byte-quantified ((words & 0xF) << 2).
    let l4_off = ip_off + ip.ihl() as usize;
    let dport = match ip.proto {
        IpProto::Tcp => {
            let tcp: TcpHdr = ctx.load(l4_off)?;
            u16::from_be_bytes(tcp.dest)
        }
        IpProto::Udp => {
            let udp: UdpHdr = ctx.load(l4_off)?;
            u16::from_be_bytes(udp.dst)
        }
        _ => return Ok(TC_ACT_PIPE),
    } as u32;

    if !port_matches(dport) {
        return Ok(TC_ACT_PIPE);
    }
    bump(|s| s.matched += 1);

    let dscp = match DSCP_CFG.get(0) {
        Some(v) if *v < 64 => *v,
        _ => DEFAULT_DSCP,
    };
    let old_tos = ip.tos;
    let new_tos = ((dscp << 2) as u8) | (old_tos & 0x03);
    if old_tos == new_tos {
        return Ok(TC_ACT_PIPE);
    }

    // RFC 1624 incremental update: fold in the two changed 16-bit halves of
    // the old and new TOS byte, keeping the rest of the checksum intact.
    // The first halfword on the wire is [version|ihl_words, tos].
    let old_check = u16::from_be_bytes(ip.check);
    let vihl_words = (ip.version() << 4) | (ip.ihl() >> 2);
    let old_half = (vihl_words as u16) << 8 | old_tos as u16;
    let new_half = (old_half & 0xff00) | new_tos as u16;
    let new_check = incremental_csum(old_check, old_half, new_half);

    ctx.store(ip_off + 1, &new_tos, 0)?;
    ctx.store(ip_off + 10, &new_check.to_be(), 0)?;
    bump(|s| s.changed += 1);

    Ok(TC_ACT_PIPE)
}

fn port_matches(dport: u32) -> bool {
    unsafe { TARGET_PORTS.get(&dport).is_some() }
}

fn incremental_csum(old_check: u16, old_half: u16, new_half: u16) -> u16 {
    let mut sum = (!old_check as u32 & 0xffff) + (!old_half as u32 & 0xffff) + new_half as u32;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

fn bump(update: impl FnOnce(&mut Stats)) {
    if let Some(ptr) = STATS.get_ptr_mut(0) {
        unsafe {
            update(&mut *ptr);
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(not(target_os = "none"))]
compile_error!("The eBPF crate must be built for a bpf*-unknown-none target");
