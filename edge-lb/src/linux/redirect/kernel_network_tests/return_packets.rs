//! Inspect the same return bytecode with real FIB routes and a real UDP flow.

use crate::linux::test_support as net;
use rtnetlink::packet_route::neighbour::NeighbourState;

use super::super::packet_test_support::{checksum, l4_checksum, packet, repair_checksums, run_on};
use aya::Ebpf;
use edge_lb_common::NATIVE_DNAT_RETURN_PROGRAM;

fn response(zero: bool, ttl: u8, payload: usize) -> Vec<u8> {
    let mut bytes = packet(17, ttl, 8080, zero);
    bytes[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    bytes[26..30].copy_from_slice(&[203, 0, 113, 20]);
    bytes[30..34].copy_from_slice(&[198, 51, 100, 2]);
    bytes[36..38].copy_from_slice(&40000u16.to_be_bytes());
    bytes.resize(bytes.len() + payload, 0x5a);
    bytes[16..18].copy_from_slice(&((28 + payload) as u16).to_be_bytes());
    bytes[38..40].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
    repair_checksums(&mut bytes, zero);
    bytes
}

fn expected(mut bytes: Vec<u8>, zero: bool, redirect: bool) -> Vec<u8> {
    bytes[26..30].copy_from_slice(&[203, 0, 113, 100]);
    bytes[34..36].copy_from_slice(&5060u16.to_be_bytes());
    if redirect {
        bytes[22] -= 1;
        bytes[..6].copy_from_slice(&[2, 0, 0, 0, 0, 0x22]);
        bytes[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 0x21]);
    }
    repair_checksums(&mut bytes, zero);
    bytes
}

pub(super) fn verify(bpf: &Ebpf) {
    let index = crate::linux::net::ifindex("edge-hub").unwrap();
    for zero in [false, true] {
        let input = response(zero, 64, 96);
        let (action, output) = run_on(bpf, NATIVE_DNAT_RETURN_PROGRAM, &input, index);
        assert_eq!(action, 7, "real FIB lookup must REDIRECT");
        assert_eq!(output, expected(input, zero, true));
        assert_eq!(checksum(&output[14..34]), 0);
        if zero {
            assert_eq!(&output[40..42], &[0, 0]);
        } else {
            assert_eq!(l4_checksum(&output), 0);
        }
        for input in [response(zero, 1, 96), response(zero, 64, 9000)] {
            let (action, output) = run_on(bpf, NATIVE_DNAT_RETURN_PROGRAM, &input, index);
            assert_eq!(
                action, 3,
                "TTL/MTU fallback must keep reverse NAT but no TTL/L2 changes"
            );
            assert_eq!(output, expected(input, zero, false));
        }
    }
    net::add_route(
        net::route("198.51.100.2/32", "", None)
            .kind(rtnetlink::packet_route::route::RouteType::BlackHole)
            .scope(rtnetlink::packet_route::route::RouteScope::Universe),
    );
    let input = response(false, 64, 96);
    let (action, output) = run_on(bpf, NATIVE_DNAT_RETURN_PROGRAM, &input, index);
    assert_eq!(action, 3);
    assert_eq!(output, expected(input.clone(), false, false));
    net::delete_route(
        "198.51.100.2/32",
        rtnetlink::packet_route::route::RouteType::BlackHole,
    );

    // This known neighbor is reachable, but its output is not in this lease.
    net::neighbor(
        "underlay0",
        "198.18.0.2",
        "02:00:00:00:00:12",
        NeighbourState::Permanent,
    );
    net::add_route(net::route(
        "198.51.100.2/32",
        "underlay0",
        Some("198.18.0.2"),
    ));
    let (action, output) = run_on(bpf, NATIVE_DNAT_RETURN_PROGRAM, &input, index);
    assert_eq!(
        action, 3,
        "FIB success on an unadmitted output must not redirect"
    );
    assert_eq!(output, expected(input, false, false));
    net::delete_route(
        "198.51.100.2/32",
        rtnetlink::packet_route::route::RouteType::Unicast,
    );
}
