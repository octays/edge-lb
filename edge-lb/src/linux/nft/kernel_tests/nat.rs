//! Production TC programs: service address DNAT and VIP reverse NAT round trip.

use crate::{
    config::{
        BackendNode, BackendTarget, Config, FileConfig, LbSelect, Listener, Protocol, TargetGroup,
    },
    linux::test_support::{private_namespace, tc_packet::*},
    provider::native::listeners_from_config,
};
use aya::{Ebpf, maps::HashMap};
use edge_lb_common::*;

#[test]
fn native_dnat_and_reverse_nat_keep_business_target_for_all_selectors() {
    std::thread::spawn(|| {
        private_namespace(false);
        let mut file = FileConfig::default();
        file.network.gateway_ip = std::net::Ipv4Addr::from(VIP).into();
        file.state_dir = "/unused/native-address-regression".into();
        file.backend_nodes.push(BackendNode {
            name: "backend-1".into(),
            public_ip: "198.51.100.20".parse().unwrap(),
            underlay_ip: std::net::Ipv4Addr::from(TARGET).into(),
            overlay_ip: "10.44.0.2/24".into(),
        });
        file.target_groups.push(TargetGroup {
            name: "service".into(),
            targets: vec![BackendTarget {
                backend: Some("backend-1".into()),
                address: std::net::Ipv4Addr::from(TARGET).into(),
                weight: 1,
            }],
            ..TargetGroup::default()
        });
        file.listeners.push(Listener {
            name: "service".into(),
            port: 5060,
            target_port: 8080,
            target_group: "service".into(),
            protocols: vec![Protocol::Tcp, Protocol::Udp],
            ..Listener::default()
        });
        let mut cfg = Config {
            file,
            path: "/unused/test.toml".into(),
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/bpfel-unknown-none/release/edge-lb-ebpf");
        let bytes = std::fs::read(path).expect("run make ebpf first");
        let mut bpf = Ebpf::load(&bytes).unwrap();
        load_program(&mut bpf, NATIVE_DNAT_INGRESS_PROGRAM);
        load_program(&mut bpf, NATIVE_DNAT_RETURN_PROGRAM);
        for (round, select) in [
            LbSelect::Rr,
            LbSelect::Hash,
            LbSelect::ConsistentHash,
            LbSelect::Priority,
            LbSelect::Persist,
            LbSelect::Lc,
        ]
        .into_iter()
        .enumerate()
        {
            cfg.file.listeners[0].select = select;
            for listener in listeners_from_config(&cfg).unwrap() {
                HashMap::try_from(bpf.map_mut("NATIVE_LISTENERS").unwrap())
                    .unwrap()
                    .insert(
                        NativeListenerLookupKey {
                            vip: u32::from(listener.key.vip_ip),
                            port: listener.key.vip_port.to_be(),
                            proto: listener.key.protocol.ip_proto(),
                            _pad: 0,
                        },
                        NativeListenerLookupValue {
                            listener_id: 1,
                            target_base: 0,
                            target_count: 1,
                            weight_total: 1,
                            select: listener.select,
                            flags: 1,
                            timeout_secs: 240,
                            dscp: 46,
                        },
                        0,
                    )
                    .unwrap();
                let target = &listener.targets[0];
                assert_eq!(u32::from(target.address), TARGET);
                HashMap::try_from(bpf.map_mut("NATIVE_TARGETS").unwrap())
                    .unwrap()
                    .insert(
                        NativeTargetKey {
                            listener_id: 1,
                            target_id: 0,
                        },
                        NativeTargetValue {
                            address: u32::from(target.address),
                            port: target.port,
                            weight: 1,
                            flags: 1,
                        },
                        0,
                    )
                    .unwrap();
            }
            if select == LbSelect::ConsistentHash {
                let mut buckets =
                    HashMap::try_from(bpf.map_mut("NATIVE_CHASH_BUCKETS").unwrap()).unwrap();
                for bucket in 0..NATIVE_CONSISTENT_HASH_BUCKETS {
                    buckets
                        .insert(
                            NativeConsistentHashBucketKey {
                                listener_id: 1,
                                bucket,
                            },
                            NativeConsistentHashBucketValue { target_id: 0 },
                            0,
                        )
                        .unwrap();
                }
            }
            for (case, (proto, zero)) in [(6, false), (17, false), (17, true)]
                .into_iter()
                .enumerate()
            {
                let input = packet(proto, 64, 41000 + (round * 3 + case) as u16, zero);
                let (action, forward) = run(&bpf, NATIVE_DNAT_INGRESS_PROGRAM, &input);
                assert_eq!(action, 3);
                assert_eq!(
                    &forward[26..30],
                    &input[26..30],
                    "client source IP preserved"
                );
                assert_eq!(
                    &forward[30..34],
                    &TARGET.to_be_bytes(),
                    "DNAT to business IP"
                );
                assert_eq!(&forward[36..38], &8080u16.to_be_bytes());
                assert_eq!(forward[15], input[15], "DSCP and ECN preserved");
                assert_eq!(checksum(&forward[14..34]), 0);
                if !zero {
                    assert_eq!(l4_checksum(&forward), 0);
                } else {
                    assert_eq!(&forward[40..42], &[0, 0]);
                }

                let mut reply = forward.clone();
                reply[26..30].copy_from_slice(&forward[30..34]);
                reply[30..34].copy_from_slice(&forward[26..30]);
                reply[34..36].copy_from_slice(&forward[36..38]);
                reply[36..38].copy_from_slice(&forward[34..36]);
                repair_checksums(&mut reply, zero);
                let (action, returned) = run(&bpf, NATIVE_DNAT_RETURN_PROGRAM, &reply);
                assert_eq!(action, 3);
                assert_eq!(
                    &returned[26..30],
                    &VIP.to_be_bytes(),
                    "reverse NAT restores VIP"
                );
                assert_eq!(&returned[34..36], &5060u16.to_be_bytes());
                assert_eq!(&returned[30..34], &input[26..30]);
                assert_eq!(&returned[36..38], &input[34..36]);
                assert_eq!(checksum(&returned[14..34]), 0);
                if !zero {
                    assert_eq!(l4_checksum(&returned), 0);
                } else {
                    assert_eq!(&returned[40..42], &[0, 0]);
                }
            }
        }
    })
    .join()
    .unwrap();
}
