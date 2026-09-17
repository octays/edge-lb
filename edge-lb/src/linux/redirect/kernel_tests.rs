//! Execute the real TC program with BPF_PROG_TEST_RUN; no host attachment.

use aya::{Ebpf, maps::HashMap, programs::SchedClassifier};
use edge_lb_common::{
    NATIVE_DNAT_INGRESS_PROGRAM, NativeListenerLookupKey, NativeListenerLookupValue,
    NativeTargetKey, NativeTargetValue,
    redirect::{NATIVE_TARGET_ROUTES_MAP, NativeTargetRoute},
};

use super::packet_test_support::{self, TARGET, VIP, checksum, l4_checksum, packet};

fn run(bpf: &Ebpf, data: &[u8]) -> (u32, Vec<u8>) {
    packet_test_support::run(bpf, NATIVE_DNAT_INGRESS_PROGRAM, data)
}

#[test]
fn forward_redirect_rewrites_and_falls_back_without_partial_l2_or_ttl_changes() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/bpfel-unknown-none/release/edge-lb-ebpf");
    let bytes = std::fs::read(path).expect("run make ebpf before kernel redirect tests");
    let mut bpf = Ebpf::load(&bytes).expect("load BPF maps");
    let key = NativeTargetKey {
        listener_id: 1,
        target_id: 0,
    };
    {
        let mut listeners = HashMap::try_from(bpf.map_mut("NATIVE_LISTENERS").unwrap()).unwrap();
        for proto in [6, 17] {
            listeners
                .insert(
                    NativeListenerLookupKey {
                        vip: VIP,
                        port: 5060u16.to_be(),
                        proto,
                        _pad: 0,
                    },
                    NativeListenerLookupValue {
                        listener_id: 1,
                        target_count: 1,
                        weight_total: 1,
                        timeout_secs: 60,
                        ..Default::default()
                    },
                    0,
                )
                .unwrap();
        }
    }
    {
        let mut targets = HashMap::try_from(bpf.map_mut("NATIVE_TARGETS").unwrap()).unwrap();
        targets
            .insert(
                key,
                NativeTargetValue {
                    address: TARGET,
                    port: 8080,
                    weight: 1,
                    flags: 1,
                },
                0,
            )
            .unwrap();
    }
    let program: &mut SchedClassifier = bpf
        .program_mut(NATIVE_DNAT_INGRESS_PROGRAM)
        .unwrap()
        .try_into()
        .unwrap();
    program.load().expect("TC redirect verifier acceptance");

    let route = NativeTargetRoute {
        expires_ns: u64::MAX,
        target: TARGET,
        ingress_ifindex: 1,
        ifindex: 1,
        mtu: 1450,
        target_port: 8080,
        dscp: 46,
        source_mac: [2, 0, 0, 0, 0, 21],
        destination_mac: [2, 0, 0, 0, 0, 22],
        ..Default::default()
    };
    for (index, (proto, zero)) in [(6, false), (17, false), (17, true)]
        .into_iter()
        .enumerate()
    {
        // First packet follows the normal DNAT path while its route is absent.
        let input = packet(proto, 64, 40000 + index as u16, zero);
        let (action, output) = run(&bpf, &input);
        assert_eq!(action, 3, "missing route must PIPE");
        assert_eq!(&output[..12], &input[..12]);
        assert_eq!(output[22], 64);
        assert_eq!(&output[30..34], &TARGET.to_be_bytes());
        assert_eq!(checksum(&output[14..34]), 0, "DNAT IPv4 checksum");
        let mut routes = HashMap::try_from(bpf.map_mut(NATIVE_TARGET_ROUTES_MAP).unwrap()).unwrap();
        routes.insert(key, route, 0).unwrap();

        // The same flow now exercises the cached-flow branch.
        let (action, output) = run(&bpf, &input);
        let stats: aya::maps::PerCpuArray<_, edge_lb_common::redirect::NativeRedirectStats> =
            aya::maps::PerCpuArray::try_from(
                bpf.map(edge_lb_common::redirect::NATIVE_REDIRECT_STATS_MAP)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            action,
            7,
            "valid route must REDIRECT; stats={:?}; packet={output:?}",
            stats.get(&0, 0).unwrap()
        );
        assert_eq!(output[22], 63);
        assert_eq!(&output[..6], &route.destination_mac);
        assert_eq!(&output[6..12], &route.source_mac);
        assert_eq!(output[15], input[15], "DSCP and ECN must survive");
        assert_eq!(checksum(&output[14..34]), 0);
        if zero {
            assert_eq!(&output[40..42], &[0, 0]);
        } else {
            assert_eq!(l4_checksum(&output), 0);
        }

        // A different client port exercises the new-flow branch with a route.
        assert_eq!(
            run(&bpf, &packet(proto, 64, 41000 + index as u16, zero)).0,
            7
        );
        let source = u32::from_be_bytes([198, 51, 100, 1]);
        let mut locals = HashMap::<_, u32, u32>::try_from(
            bpf.map_mut(edge_lb_common::redirect::NATIVE_LOCAL_ADDRS_MAP)
                .unwrap(),
        )
        .unwrap();
        locals.insert(source, 1, 0).unwrap();
        let (action, output) = run(&bpf, &input);
        assert_eq!(action, 3, "locally owned source must use kernel validation");
        assert_eq!(output[22], 64);
        assert_eq!(&output[..12], &input[..12]);
        HashMap::<_, u32, u32>::try_from(
            bpf.map_mut(edge_lb_common::redirect::NATIVE_LOCAL_ADDRS_MAP)
                .unwrap(),
        )
        .unwrap()
        .remove(&source)
        .unwrap();
        for invalid in [
            NativeTargetRoute {
                expires_ns: 1,
                ..route
            },
            NativeTargetRoute {
                target: TARGET + 1,
                ..route
            },
            NativeTargetRoute {
                target_port: 8081,
                ..route
            },
            NativeTargetRoute { mtu: 0, ..route },
            NativeTargetRoute {
                ingress_ifindex: 2,
                ..route
            },
            NativeTargetRoute { dscp: 40, ..route },
        ] {
            HashMap::try_from(bpf.map_mut(NATIVE_TARGET_ROUTES_MAP).unwrap())
                .unwrap()
                .insert(key, invalid, 0)
                .unwrap();
            let (action, output) = run(&bpf, &input);
            assert_eq!(action, 3);
            assert_eq!(&output[..12], &input[..12]);
            assert_eq!(output[22], 64);
            assert_eq!(checksum(&output[14..34]), 0);
        }
        HashMap::try_from(bpf.map_mut(NATIVE_TARGET_ROUTES_MAP).unwrap())
            .unwrap()
            .insert(key, route, 0)
            .unwrap();
        let (action, output) = run(&bpf, &packet(proto, 1, 40000 + index as u16, zero));
        assert_eq!(action, 3);
        assert_eq!(output[22], 1);
        let mut routes = HashMap::<_, NativeTargetKey, NativeTargetRoute>::try_from(
            bpf.map_mut(NATIVE_TARGET_ROUTES_MAP).unwrap(),
        )
        .unwrap();
        assert_eq!(super::maps::clear_routes(&mut routes).unwrap(), 1);
        assert_eq!(super::maps::clear_routes(&mut routes).unwrap(), 0);
        // Invalidating acceleration must preserve the cached NAT decision.
        let mut targets = HashMap::<_, NativeTargetKey, NativeTargetValue>::try_from(
            bpf.map_mut("NATIVE_TARGETS").unwrap(),
        )
        .unwrap();
        let target = targets.get(&key, 0).unwrap();
        targets.remove(&key).unwrap();
        let (action, output) = run(&bpf, &input);
        assert_eq!(action, 3);
        assert_eq!(&output[30..34], &TARGET.to_be_bytes());
        assert_eq!(&output[36..38], &8080u16.to_be_bytes());
        assert_eq!(output[22], 64);
        assert_eq!(&output[..12], &input[..12]);
        assert_eq!(checksum(&output[14..34]), 0);
        HashMap::try_from(bpf.map_mut("NATIVE_TARGETS").unwrap())
            .unwrap()
            .insert(key, target, 0)
            .unwrap();
    }
}
