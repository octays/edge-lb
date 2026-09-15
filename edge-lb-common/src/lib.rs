#![no_std]

#[cfg(feature = "user")]
extern crate std;

/// Maximum number of destination ports the DSCP marker can match.
pub const MAX_PORTS: usize = 16;
/// Room for old and new sets while the marker is updated without clearing it.
pub const DSCP_PORT_MAP_CAPACITY: u32 = (MAX_PORTS * 2) as u32;
/// Default DSCP value. 46 is Expedited Forwarding (tos 0xb8).
pub const DEFAULT_DSCP: u32 = 46;
/// Default source-IP persistence lifetime for `persist` selection.
pub const DEFAULT_PERSIST_TIMEOUT_SECS: u32 = 3 * 60 * 60;
pub const NATIVE_SELECT_RR: u32 = 0;
pub const NATIVE_SELECT_HASH: u32 = 1;
pub const NATIVE_SELECT_PRIORITY: u32 = 2;
pub const NATIVE_SELECT_PERSIST: u32 = 3;
pub const NATIVE_SELECT_LC: u32 = 4;
pub const NATIVE_SELECT_CONSISTENT_HASH: u32 = 5;

/// Name of the TC classifier program inside the eBPF object.
pub const PROGRAM_NAME: &str = "dscp_mark";

/// Hard cap on targets per native listener. Native eBPF selectors iterate a
/// compile-time bound so the verifier sees bounded loops; user space clamps
/// target map writes to the same limit.
pub const MAX_TARGETS_PER_LISTENER: u32 = 64;
pub const NATIVE_CONSISTENT_HASH_BUCKETS: u32 = 1024;
pub const NATIVE_CONSISTENT_HASH_BUCKET_MAP_CAPACITY: u32 = 262_144;
pub const NATIVE_LISTENER_ID_CAPACITY: u32 = 4096;
pub const NATIVE_DNAT_INGRESS_PROGRAM: &str = "native_dnat_ingress";
pub const NATIVE_DNAT_RETURN_PROGRAM: &str = "native_dnat_return";

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Stats {
    pub matched: u64,
    pub changed: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}

/// IPv4 listener lookup key for the native DNAT datapath.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeListenerLookupKey {
    /// IPv4 VIP in network byte order.
    pub vip: u32,
    /// TCP/UDP destination port in network byte order.
    pub port: u16,
    /// IP protocol number: TCP=6, UDP=17.
    pub proto: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeListenerLookupValue {
    pub listener_id: u32,
    pub target_base: u32,
    pub target_count: u32,
    pub weight_total: u32,
    pub select: u32,
    pub flags: u32,
    pub timeout_secs: u32,
    pub dscp: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeTargetKey {
    pub listener_id: u32,
    pub target_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeTargetValue {
    /// IPv4 backend address in network byte order.
    pub address: u32,
    /// TCP/UDP backend target port in host byte order.
    pub port: u16,
    pub weight: u16,
    pub flags: u32,
}

/// Per-listener/target key used by the least-connections scheduler.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeTargetLoadKey {
    pub listener_id: u32,
    pub target_id: u32,
}

/// Precomputed consistent-hash bucket for a native listener.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeConsistentHashBucketKey {
    pub listener_id: u32,
    pub bucket: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeConsistentHashBucketValue {
    pub target_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeFlowKey {
    pub src: u32,
    pub dst: u32,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeFlowValue {
    pub listener_id: u32,
    pub target_id: u32,
    pub vip: u32,
    pub target: u32,
    pub vip_port: u16,
    pub target_port: u16,
    /// Idle timeout copied from the listener when the flow is created.
    pub timeout_secs: u32,
    pub last_seen_ns: u64,
}

impl NativeFlowKey {
    /// Ports in keys and vip_port are network order; target_port is host order.
    #[inline(always)]
    pub fn reverse_for(self, value: NativeFlowValue) -> Self {
        Self {
            src: value.target,
            dst: self.src,
            sport: value.target_port.to_be(),
            dport: self.sport,
            proto: self.proto,
            _pad: [0; 3],
        }
    }

    #[inline(always)]
    pub fn forward_for(self, value: NativeFlowValue) -> Self {
        Self {
            src: self.dst,
            dst: value.vip,
            sport: self.dport,
            dport: value.vip_port,
            proto: self.proto,
            _pad: [0; 3],
        }
    }
}

fn mix32(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb_352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846c_a68b);
    value ^ (value >> 16)
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[inline(always)]
fn hash_step(hash: u32, value: u32) -> u32 {
    hash.wrapping_mul(0x0100_0193) ^ value
}

#[inline(always)]
fn hash_step64(hash: u64, value: u64) -> u64 {
    hash.wrapping_mul(0x0000_0100_0000_01b3) ^ value
}

/// VIP-independent stable flow hash for the `consistent_hash` selector.
///
/// The flow identity is client IPv4, client source port, listener port and
/// protocol. The VIP address is intentionally excluded so the same SIP flow
/// identity maps consistently across VIPs and HA gateways.
#[inline(always)]
pub fn native_consistent_flow_hash(key: &NativeFlowKey) -> u32 {
    let mut hash = 0x811c_9dc5;
    hash = hash_step(hash, key.src);
    hash = hash_step(hash, u32::from(key.sport) << 16 | u32::from(key.dport));
    hash = hash_step(hash, u32::from(key.proto));
    mix32(hash)
}

#[inline(always)]
pub fn native_consistent_flow_bucket(key: &NativeFlowKey) -> u32 {
    native_consistent_flow_hash(key) & (NATIVE_CONSISTENT_HASH_BUCKETS - 1)
}

/// HRW score used by user space to precompute a listener's consistent-hash
/// bucket table. Target identity is target IPv4 and target port; target weight
/// is intentionally ignored.
#[inline(always)]
pub fn native_consistent_bucket_score(bucket: u32, target: &NativeTargetValue) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    hash = hash_step64(hash, u64::from(bucket));
    hash = hash_step64(hash, u64::from(target.address));
    hash = hash_step64(hash, u64::from(target.port));
    mix64(hash)
}

#[cfg(test)]
mod flow_key_tests {
    use super::*;

    #[test]
    fn flow_pair_retains_client_identity_in_both_directions() {
        for proto in [6, 17] {
            let forward = NativeFlowKey {
                src: 0xc000_0201,
                dst: 0xc000_0202,
                sport: 49153u16.to_be(),
                dport: 8080u16.to_be(),
                proto,
                _pad: [0; 3],
            };
            let value = NativeFlowValue {
                vip: forward.dst,
                vip_port: forward.dport,
                target: 0xc000_0203,
                target_port: 9090,
                ..NativeFlowValue::default()
            };
            let reverse = forward.reverse_for(value);
            assert_eq!(reverse.dst, forward.src);
            assert_eq!(reverse.dport, forward.sport);
            assert_eq!(reverse.sport, 9090u16.to_be());
            assert_eq!(reverse.forward_for(value), forward);
        }
    }
}

#[cfg(test)]
mod scheduler_tests {
    use super::{
        NATIVE_CONSISTENT_HASH_BUCKETS, NATIVE_SELECT_CONSISTENT_HASH, NATIVE_SELECT_HASH,
        NATIVE_SELECT_LC, NATIVE_SELECT_PERSIST, NATIVE_SELECT_PRIORITY, NATIVE_SELECT_RR,
        NativeFlowKey, NativeTargetValue, native_consistent_bucket_score,
        native_consistent_flow_bucket,
    };

    fn key(source_port: u16) -> NativeFlowKey {
        NativeFlowKey {
            src: 0x0102_0304,
            dst: 0x0506_0708,
            sport: source_port.to_be(),
            dport: 9999_u16.to_be(),
            proto: 6,
            _pad: [0; 3],
        }
    }

    fn weighted_pick(seed: u32, weights: &[u16], active: &[bool]) -> Option<usize> {
        let total = weights
            .iter()
            .zip(active)
            .filter_map(|(weight, enabled)| enabled.then_some(u32::from(*weight)))
            .sum::<u32>();
        if total == 0 {
            return None;
        }
        let mut cursor = seed % total;
        for (index, (weight, enabled)) in weights.iter().zip(active).enumerate() {
            if *enabled && *weight > 0 {
                if cursor < u32::from(*weight) {
                    return Some(index);
                }
                cursor -= u32::from(*weight);
            }
        }
        None
    }

    fn slot_pick(seed: u32, weights: &[u16], active: &[bool]) -> Option<usize> {
        if active.is_empty() {
            return None;
        }
        let primary = seed as usize % active.len();
        if active[primary] && weights[primary] > 0 {
            return Some(primary);
        }
        active
            .iter()
            .zip(weights)
            .position(|(enabled, weight)| *enabled && *weight > 0)
    }

    fn persist_pick(client_ip: u32, weights: &[u16], active: &[bool]) -> Option<usize> {
        if active.is_empty() {
            return None;
        }
        let primary = ((client_ip & 0xff) ^ ((client_ip >> 24) & 0xff)) as usize % active.len();
        if active[primary] && weights[primary] > 0 {
            return Some(primary);
        }
        let secondary =
            (((client_ip >> 8) & 0xff) ^ ((client_ip >> 16) & 0xff)) as usize % active.len();
        if active[secondary] && weights[secondary] > 0 {
            return Some(secondary);
        }
        active
            .iter()
            .zip(weights)
            .position(|(enabled, weight)| *enabled && *weight > 0)
    }

    fn rr_pick(cursor: u32, weights: &[u16], active: &[bool]) -> Option<usize> {
        if active.is_empty() {
            return None;
        }
        for offset in 0..active.len() {
            let index = (cursor as usize + offset) % active.len();
            if active[index] && weights[index] > 0 {
                return Some(index);
            }
        }
        None
    }

    fn consistent_pick(key: &NativeFlowKey, targets: &[NativeTargetValue]) -> Option<usize> {
        let bucket = native_consistent_flow_bucket(key);
        consistent_bucket_pick(bucket, targets)
    }

    fn consistent_bucket_pick(bucket: u32, targets: &[NativeTargetValue]) -> Option<usize> {
        let mut best = None;
        let mut best_score = 0u64;
        for (index, target) in targets.iter().enumerate() {
            if target.flags & 1 == 0 || target.weight == 0 {
                continue;
            }
            let score = native_consistent_bucket_score(bucket, target);
            if best.is_none() || score > best_score {
                best = Some(index);
                best_score = score;
            }
        }
        best
    }

    fn consistent_target(index: u32) -> NativeTargetValue {
        NativeTargetValue {
            address: 0xc000_020a + index,
            port: 5060,
            weight: 1,
            flags: 1,
        }
    }

    #[test]
    fn weighted_selection_skips_unhealthy_targets() {
        assert_eq!(weighted_pick(0, &[1, 1], &[false, true]), Some(1));
        assert_eq!(weighted_pick(10, &[1, 1], &[false, false]), None);
    }

    #[test]
    fn weighted_selection_respects_weight_ranges() {
        assert_eq!(weighted_pick(0, &[2, 1], &[true, true]), Some(0));
        assert_eq!(weighted_pick(1, &[2, 1], &[true, true]), Some(0));
        assert_eq!(weighted_pick(2, &[2, 1], &[true, true]), Some(1));
    }

    #[test]
    fn hash_selection_uses_target_slots_without_weight_expansion() {
        assert_eq!(slot_pick(0, &[3, 1], &[true, true]), Some(0));
        assert_eq!(slot_pick(1, &[3, 1], &[true, true]), Some(1));
        assert_eq!(slot_pick(2, &[3, 1], &[true, true]), Some(0));
    }

    #[test]
    fn hash_selection_falls_back_to_first_healthy_slot() {
        assert_eq!(slot_pick(0, &[1, 1], &[false, true]), Some(1));
        assert_eq!(slot_pick(0, &[1, 1], &[false, false]), None);
    }

    #[test]
    fn rr_selection_rotates_slots_without_weight_expansion() {
        assert_eq!(rr_pick(0, &[3, 1], &[true, true]), Some(0));
        assert_eq!(rr_pick(1, &[3, 1], &[true, true]), Some(1));
        assert_eq!(rr_pick(2, &[3, 1], &[true, true]), Some(0));
    }

    #[test]
    fn persist_seed_ignores_client_transport_port() {
        let first = key(40000);
        let second = key(40001);
        assert_eq!(first.src, second.src);
        assert_eq!(
            persist_pick(first.src, &[1, 1], &[true, true]),
            persist_pick(second.src, &[1, 1], &[true, true])
        );
    }

    #[test]
    fn persist_selection_uses_source_ip_slots_without_weight_expansion() {
        assert_eq!(persist_pick(0x0102_0304, &[3, 1], &[true, true]), Some(1));
    }

    #[test]
    fn consistent_hash_ignores_vip_address() {
        let first = key(40000);
        let second = NativeFlowKey {
            dst: 0x0a00_0006,
            ..first
        };
        let targets = [
            NativeTargetValue {
                address: 0xc000_020d,
                port: 5060,
                weight: 1,
                flags: 1,
            },
            NativeTargetValue {
                address: 0xc000_020e,
                port: 5060,
                weight: 1,
                flags: 1,
            },
        ];

        assert_eq!(
            consistent_pick(&first, &targets),
            consistent_pick(&second, &targets)
        );
    }

    #[test]
    fn consistent_hash_ignores_weight_values_except_zero_disable() {
        let flow = key(40000);
        let targets = [
            NativeTargetValue {
                address: 0xc000_020d,
                port: 5060,
                weight: 1,
                flags: 1,
            },
            NativeTargetValue {
                address: 0xc000_020e,
                port: 5060,
                weight: 1,
                flags: 1,
            },
        ];
        let weighted = [
            NativeTargetValue {
                weight: 100,
                ..targets[0]
            },
            NativeTargetValue {
                weight: 1,
                ..targets[1]
            },
        ];
        let disabled_first = [
            NativeTargetValue {
                weight: 0,
                ..targets[0]
            },
            targets[1],
        ];

        assert_eq!(
            consistent_pick(&flow, &targets),
            consistent_pick(&flow, &weighted)
        );
        assert_eq!(consistent_pick(&flow, &disabled_first), Some(1));
    }

    #[test]
    fn consistent_hash_is_repeatable_for_the_same_flow() {
        let flow = key(41000);
        let targets = [
            NativeTargetValue {
                address: 0xc000_020d,
                port: 5060,
                weight: 1,
                flags: 1,
            },
            NativeTargetValue {
                address: 0xc000_020e,
                port: 5060,
                weight: 1,
                flags: 1,
            },
            NativeTargetValue {
                address: 0xc000_020f,
                port: 5060,
                weight: 1,
                flags: 1,
            },
        ];

        let expected = consistent_pick(&flow, &targets);
        for _ in 0..128 {
            assert_eq!(consistent_pick(&flow, &targets), expected);
        }
    }

    #[test]
    fn consistent_hash_is_stable_by_target_identity_not_slot_order() {
        let flow = key(42000);
        let first_order = [
            NativeTargetValue {
                address: 0xc000_020d,
                port: 5060,
                weight: 1,
                flags: 1,
            },
            NativeTargetValue {
                address: 0xc000_020e,
                port: 5060,
                weight: 1,
                flags: 1,
            },
            NativeTargetValue {
                address: 0xc000_020f,
                port: 5060,
                weight: 1,
                flags: 1,
            },
        ];
        let second_order = [first_order[2], first_order[0], first_order[1]];

        let first = consistent_pick(&flow, &first_order).map(|index| first_order[index].address);
        let second = consistent_pick(&flow, &second_order).map(|index| second_order[index].address);
        assert_eq!(first, second);
    }

    #[test]
    fn consistent_hash_removing_target_preserves_other_flows() {
        let targets = [
            NativeTargetValue {
                address: 0xc000_020d,
                port: 5060,
                weight: 1,
                flags: 1,
            },
            NativeTargetValue {
                address: 0xc000_020e,
                port: 5060,
                weight: 1,
                flags: 1,
            },
            NativeTargetValue {
                address: 0xc000_020f,
                port: 5060,
                weight: 1,
                flags: 1,
            },
        ];
        let remaining = [targets[0], targets[2]];

        for source_port in 40000..41000 {
            let flow = key(source_port);
            let before = consistent_pick(&flow, &targets).map(|index| targets[index].address);
            let after = consistent_pick(&flow, &remaining).map(|index| remaining[index].address);
            if before != Some(targets[1].address) {
                assert_eq!(after, before);
            }
        }
    }

    #[test]
    fn consistent_hash_adding_target_only_moves_flows_won_by_new_target() {
        let targets = [
            NativeTargetValue {
                address: 0xc000_020d,
                port: 5060,
                weight: 1,
                flags: 1,
            },
            NativeTargetValue {
                address: 0xc000_020e,
                port: 5060,
                weight: 1,
                flags: 1,
            },
        ];
        let expanded = [
            targets[0],
            targets[1],
            NativeTargetValue {
                address: 0xc000_020f,
                port: 5060,
                weight: 1,
                flags: 1,
            },
        ];

        for source_port in 40000..41000 {
            let flow = key(source_port);
            let before = consistent_pick(&flow, &targets).map(|index| targets[index].address);
            let after = consistent_pick(&flow, &expanded).map(|index| expanded[index].address);
            if after != Some(expanded[2].address) {
                assert_eq!(after, before);
            }
        }
    }

    #[test]
    fn consistent_hash_bucket_distribution_is_reasonably_even() {
        let targets = [
            consistent_target(0),
            consistent_target(1),
            consistent_target(2),
            consistent_target(3),
        ];
        let mut counts = [0usize; 4];
        for bucket in 0..NATIVE_CONSISTENT_HASH_BUCKETS {
            let index = consistent_bucket_pick(bucket, &targets).expect("bucket should pick");
            counts[index] += 1;
        }

        let expected = NATIVE_CONSISTENT_HASH_BUCKETS as f64 / counts.len() as f64;
        for count in counts {
            let skew = ((count as f64 - expected) / expected).abs();
            assert!(skew < 0.15, "bucket count {count} skew {skew:.3}");
        }
    }

    #[test]
    fn consistent_hash_adding_target_moves_about_one_new_target_share() {
        let before = [
            consistent_target(0),
            consistent_target(1),
            consistent_target(2),
            consistent_target(3),
        ];
        let after = [
            before[0],
            before[1],
            before[2],
            before[3],
            consistent_target(4),
        ];
        let mut moved = 0usize;
        for bucket in 0..NATIVE_CONSISTENT_HASH_BUCKETS {
            let old = consistent_bucket_pick(bucket, &before).expect("old bucket should pick");
            let new = consistent_bucket_pick(bucket, &after).expect("new bucket should pick");
            if after[new].address != before[old].address {
                moved += 1;
            }
        }

        let moved_ratio = moved as f64 / NATIVE_CONSISTENT_HASH_BUCKETS as f64;
        assert!(
            (0.15..0.25).contains(&moved_ratio),
            "moved ratio {moved_ratio:.3}"
        );
    }

    #[test]
    fn consistent_hash_removing_target_moves_only_removed_target_share() {
        let before = [
            consistent_target(0),
            consistent_target(1),
            consistent_target(2),
            consistent_target(3),
            consistent_target(4),
        ];
        let after = [before[0], before[1], before[3], before[4]];
        let removed = before[2];
        let mut moved = 0usize;
        let mut removed_winners = 0usize;
        for bucket in 0..NATIVE_CONSISTENT_HASH_BUCKETS {
            let old = consistent_bucket_pick(bucket, &before).expect("old bucket should pick");
            let new = consistent_bucket_pick(bucket, &after).expect("new bucket should pick");
            if before[old].address == removed.address {
                removed_winners += 1;
                moved += 1;
            } else {
                assert_eq!(after[new].address, before[old].address);
            }
        }

        assert_eq!(moved, removed_winners);
        let moved_ratio = moved as f64 / NATIVE_CONSISTENT_HASH_BUCKETS as f64;
        assert!(
            (0.15..0.25).contains(&moved_ratio),
            "moved ratio {moved_ratio:.3}"
        );
    }

    #[test]
    fn consistent_hash_bucket_count_is_power_of_two() {
        assert_eq!(NATIVE_CONSISTENT_HASH_BUCKETS, 1024);
        assert_eq!(
            NATIVE_CONSISTENT_HASH_BUCKETS & (NATIVE_CONSISTENT_HASH_BUCKETS - 1),
            0
        );
    }

    #[test]
    fn consistent_hash_bucket_score_uses_64_bits() {
        let target = NativeTargetValue {
            address: 0xc000_020d,
            port: 5060,
            weight: 1,
            flags: 1,
        };
        assert!(native_consistent_bucket_score(17, &target) > u64::from(u32::MAX));
    }

    #[test]
    fn persist_default_timeout_is_three_hours() {
        assert_eq!(super::DEFAULT_PERSIST_TIMEOUT_SECS, 10_800);
    }

    #[test]
    fn selector_codes_match_native_datapath_contract() {
        assert_eq!(NATIVE_SELECT_RR, 0);
        assert_eq!(NATIVE_SELECT_HASH, 1);
        assert_eq!(NATIVE_SELECT_PRIORITY, 2);
        assert_eq!(NATIVE_SELECT_PERSIST, 3);
        assert_eq!(NATIVE_SELECT_LC, 4);
        assert_eq!(NATIVE_SELECT_CONSISTENT_HASH, 5);
    }
}

/// A flow-map mutation emitted by the native datapath.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeFlowEvent {
    pub key: NativeFlowKey,
    pub value: NativeFlowValue,
    pub op: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeDatapathStats {
    pub listener_hit: u64,
    pub listener_miss: u64,
    pub return_miss: u64,
    pub target_miss: u64,
    pub rewritten: u64,
    pub checksum_error: u64,
    pub chash_bucket_hit: u64,
    pub chash_bucket_miss: u64,
    pub chash_bucket_unusable: u64,
    pub chash_fallback: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeListenerLookupKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeListenerLookupValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeTargetKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeTargetLoadKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeTargetValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeConsistentHashBucketKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeConsistentHashBucketValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeFlowKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeFlowValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeFlowEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeDatapathStats {}
