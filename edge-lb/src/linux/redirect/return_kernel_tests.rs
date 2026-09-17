//! Return-path baseline against the real program, before adding FIB redirect.

use aya::{
    Ebpf,
    maps::{HashMap, MapError, PerCpuArray, RingBuf},
};
use edge_lb_common::{
    NATIVE_DNAT_RETURN_PROGRAM, NativeDatapathStats, NativeFlowEvent, NativeFlowKey,
    NativeFlowValue, NativeTargetLoadKey,
};

use super::{
    packet_test_support::{
        TARGET, VIP, checksum, l4_checksum, load_program, packet, repair_checksums, run,
    },
    reconcile::monotonic_ns,
    test_support::load_bpf,
};

fn flow(proto: u8, vip: u32, port: u16) -> (NativeFlowKey, NativeFlowValue) {
    (
        NativeFlowKey {
            src: u32::from_be_bytes([198, 51, 100, 1]),
            dst: vip,
            sport: 40000u16.to_be(),
            dport: port.to_be(),
            proto,
            _pad: [0; 3],
        },
        NativeFlowValue {
            listener_id: 7,
            target_id: 3,
            vip,
            target: TARGET,
            vip_port: port.to_be(),
            target_port: 8080,
            timeout_secs: 60,
            last_seen_ns: monotonic_ns().unwrap().saturating_sub(1_000_000),
        },
    )
}

fn insert_pair(bpf: &mut Ebpf, key: NativeFlowKey, value: NativeFlowValue) {
    let mut flows = HashMap::try_from(bpf.map_mut("NATIVE_FLOWS").unwrap()).unwrap();
    flows.insert(key, value, 0).unwrap();
    flows.insert(key.reverse_for(value), value, 0).unwrap();
}

fn response(key: NativeFlowKey, value: NativeFlowValue, zero: bool) -> Vec<u8> {
    let mut bytes = packet(key.proto, 64, value.target_port, zero);
    bytes[26..30].copy_from_slice(&value.target.to_be_bytes());
    bytes[30..34].copy_from_slice(&key.src.to_be_bytes());
    bytes[36..38].copy_from_slice(&u16::from_be(key.sport).to_be_bytes());
    repair_checksums(&mut bytes, zero);
    bytes
}

fn stats(bpf: &Ebpf) -> NativeDatapathStats {
    let stats =
        PerCpuArray::<_, NativeDatapathStats>::try_from(bpf.map("NATIVE_STATS").unwrap()).unwrap();
    let mut total = NativeDatapathStats::default();
    for value in stats.get(&0, 0).unwrap().iter() {
        total.return_miss += value.return_miss;
        total.rewritten += value.rewritten;
        total.checksum_error += value.checksum_error;
    }
    total
}

fn assert_nat(input: &[u8], output: &[u8], value: NativeFlowValue, zero: bool) {
    let l4 = 14 + usize::from(input[14] & 0x0f) * 4;
    let mut expected = input.to_vec();
    expected[26..30].copy_from_slice(&value.vip.to_be_bytes());
    expected[l4..l4 + 2].copy_from_slice(&u16::from_be(value.vip_port).to_be_bytes());
    repair_checksums(&mut expected, zero);
    assert_eq!(output, expected, "NAT only: L2/TTL/DSCP/ECN stay unchanged");
    assert_eq!(checksum(&output[14..l4]), 0);
    if zero {
        assert_eq!(&output[l4 + 6..l4 + 8], &[0, 0]);
    } else {
        assert_eq!(l4_checksum(output), 0);
    }
}

#[test]
fn return_nat_preserves_headers_and_refreshes_both_flows_without_target_maps() {
    let mut bpf = load_bpf();
    load_program(&mut bpf, NATIVE_DNAT_RETURN_PROGRAM);
    let mut count = 0;
    for (proto, zero) in [(6, false), (17, false), (17, true)] {
        for (vip, port) in [(VIP, 5060), (VIP + 1, 15060)] {
            let (key, value) = flow(proto, vip, port);
            insert_pair(&mut bpf, key, value);
            let input = response(key, value, zero);
            let (action, output) = run(&bpf, NATIVE_DNAT_RETURN_PROGRAM, &input);
            assert_eq!(action, 3);
            assert_nat(&input, &output, value, zero);
            let flows = HashMap::<_, NativeFlowKey, NativeFlowValue>::try_from(
                bpf.map("NATIVE_FLOWS").unwrap(),
            )
            .unwrap();
            let forward = flows.get(&key, 0).unwrap();
            let reverse = flows.get(&key.reverse_for(value), 0).unwrap();
            assert_eq!(forward, reverse);
            assert!(forward.last_seen_ns > value.last_seen_ns);
            assert_eq!(
                forward,
                NativeFlowValue {
                    last_seen_ns: forward.last_seen_ns,
                    ..value
                }
            );
            count += 1;
        }
    }
    assert_eq!(stats(&bpf).rewritten, count);
    assert_eq!(stats(&bpf).return_miss, 0);
    assert_eq!(stats(&bpf).checksum_error, 0);
}

#[test]
fn return_nat_retains_kernel_ttl_and_ipv4_options_handling() {
    let mut bpf = load_bpf();
    load_program(&mut bpf, NATIVE_DNAT_RETURN_PROGRAM);
    for (proto, zero) in [(6, false), (17, false), (17, true)] {
        let (key, value) = flow(proto, VIP, 5060);
        insert_pair(&mut bpf, key, value);
        let mut input = response(key, value, zero);
        input[22] = 1;
        repair_checksums(&mut input, zero);
        let (action, output) = run(&bpf, NATIVE_DNAT_RETURN_PROGRAM, &input);
        assert_eq!(action, 3);
        assert_nat(&input, &output, value, zero);

        input[22] = 64;
        input.splice(34..34, [1, 1, 1, 0]); // Three NOPs, then end of options.
        input[14] = 0x46;
        let length = (input.len() - 14) as u16;
        input[16..18].copy_from_slice(&length.to_be_bytes());
        repair_checksums(&mut input, zero);
        let (action, output) = run(&bpf, NATIVE_DNAT_RETURN_PROGRAM, &input);
        assert_eq!(action, 3);
        assert_nat(&input, &output, value, zero);
    }
    assert_eq!(stats(&bpf).checksum_error, 0);
}

#[test]
fn return_miss_and_parse_failures_do_not_mutate_packets_or_refresh_flows() {
    let mut bpf = load_bpf();
    load_program(&mut bpf, NATIVE_DNAT_RETURN_PROGRAM);
    let (key, value) = flow(17, VIP, 5060);
    let input = response(key, value, false);
    assert_eq!(
        run(&bpf, NATIVE_DNAT_RETURN_PROGRAM, &input),
        (3, input.clone())
    );
    assert_eq!(stats(&bpf).return_miss, 1);
    insert_pair(&mut bpf, key, value);
    let mut fragmented = input.clone();
    fragmented[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    repair_checksums(&mut fragmented, false);
    let mut non_ipv4 = vec![0u8; 14 + 40];
    non_ipv4[..12].copy_from_slice(&input[..12]);
    non_ipv4[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    non_ipv4[14] = 0x60;
    non_ipv4[20] = 59; // IPv6 no-next-header, complete header for test-run.
    non_ipv4[21] = 64;
    for input in [fragmented, non_ipv4, input[..34].to_vec()] {
        assert_eq!(run(&bpf, NATIVE_DNAT_RETURN_PROGRAM, &input), (3, input));
    }
    let flows =
        HashMap::<_, NativeFlowKey, NativeFlowValue>::try_from(bpf.map("NATIVE_FLOWS").unwrap())
            .unwrap();
    assert_eq!(flows.get(&key, 0).unwrap(), value);
    assert_eq!(flows.get(&key.reverse_for(value), 0).unwrap(), value);
    assert_eq!(stats(&bpf).rewritten, 0);
    assert_eq!(stats(&bpf).return_miss, 1);
    assert_eq!(stats(&bpf).checksum_error, 0);
}

#[test]
fn return_expiry_removes_the_pair_and_emits_both_delete_events() {
    let mut bpf = load_bpf();
    load_program(&mut bpf, NATIVE_DNAT_RETURN_PROGRAM);
    let (key, mut value) = flow(6, VIP, 5060);
    assert!(monotonic_ns().unwrap() > 2_000_000_000);
    value.last_seen_ns = 1;
    value.timeout_secs = 1;
    insert_pair(&mut bpf, key, value);
    let target = NativeTargetLoadKey {
        listener_id: value.listener_id,
        target_id: value.target_id,
    };
    HashMap::try_from(bpf.map_mut("NATIVE_ACTIVE_FLOWS").unwrap())
        .unwrap()
        .insert(target, 1u32, 0)
        .unwrap();
    let input = response(key, value, false);
    assert_eq!(run(&bpf, NATIVE_DNAT_RETURN_PROGRAM, &input), (3, input));
    let flows =
        HashMap::<_, NativeFlowKey, NativeFlowValue>::try_from(bpf.map("NATIVE_FLOWS").unwrap())
            .unwrap();
    for key in [key, key.reverse_for(value)] {
        assert!(matches!(flows.get(&key, 0), Err(MapError::KeyNotFound)));
    }
    let active =
        HashMap::<_, NativeTargetLoadKey, u32>::try_from(bpf.map("NATIVE_ACTIVE_FLOWS").unwrap())
            .unwrap();
    assert!(matches!(active.get(&target, 0), Err(MapError::KeyNotFound)));
    let mut events = RingBuf::try_from(bpf.take_map("NATIVE_FLOW_EVENTS").unwrap()).unwrap();
    let mut keys = Vec::new();
    while let Some(bytes) = events.next() {
        assert_eq!(bytes.len(), std::mem::size_of::<NativeFlowEvent>());
        // SAFETY: the kernel record has the exact shared ABI size, all fields
        // permit any bit pattern, and unaligned ring data is copied by value.
        let event = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<NativeFlowEvent>()) };
        assert_eq!(event.op, 2);
        assert_eq!(event.value, value);
        keys.push(event.key);
    }
    assert_eq!(keys, vec![key.reverse_for(value), key]);
    assert_eq!(stats(&bpf).return_miss, 1);
    assert_eq!(stats(&bpf).rewritten, 0);
}
