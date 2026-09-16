//! Kernel map recreation and flow refill, not process/disk snapshot recovery.

use super::*;
use edge_lb_common::{NativeFlowKey, NativeFlowValue};

fn flows(bpf: &Ebpf) -> Vec<(NativeFlowKey, NativeFlowValue)> {
    HashMap::<_, NativeFlowKey, NativeFlowValue>::try_from(bpf.map("NATIVE_FLOWS").unwrap())
        .unwrap()
        .iter()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn flow_id(bpf: &Ebpf) -> u32 {
    let aya::maps::Map::LruHashMap(data) = bpf.map("NATIVE_FLOWS").unwrap() else {
        panic!("expected LRU flow map");
    };
    data.info().unwrap().id()
}

#[test]
fn tcp_traffic_during_detached_datapath_exposes_reset_window() {
    std::thread::spawn(|| {
        let topology = topology::Topology::new();
        let fs = PrivateBpffs::new();
        let bpf = datapath(&fs);
        let _servers = traffic::Servers::new(&topology);
        let mut clients = traffic::Clients::new(&topology).unwrap();
        clients.exchange_tcp(96);
        std::thread::sleep(Duration::from_millis(200));
        assert!(!flows(&bpf).is_empty());
        drop(bpf);
        // Characterization, not desired hot-restart semantics: without TC NAT,
        // packets reach the gateway's local VIP socket stack and can reset TCP.
        let error = clients
            .try_exchange_tcp(96)
            .expect_err("detached NAT must not appear seamless");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ),
            "expected broken TCP connection, got {error}"
        );
    })
    .join()
    .unwrap();
}

#[test]
fn quiesced_datapath_recreation_restores_sockets_but_not_old_redirect_leases() {
    std::thread::spawn(|| {
        let topology = topology::Topology::new();
        let fs = PrivateBpffs::new();
        let bpf = datapath(&fs);
        let _servers = traffic::Servers::new(&topology);
        let mut clients = traffic::Clients::new(&topology).unwrap();
        let vip = u32::from_be_bytes([203, 0, 113, 100]);
        let pin = fs.0.join(NATIVE_TARGET_ROUTES_MAP);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert_eq!(publish_fixture(&fs), 1);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(stats(&fs).submitted > 0);
        return_tests::publish(&fs, vip);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(return_tests::stats(&fs).submitted > 0);

        // Drain delayed TCP ACKs before detaching: this tests quiesced recovery,
        // not packet handling during the non-atomic detach/attach window.
        std::thread::sleep(Duration::from_millis(200));
        let saved = flows(&bpf);
        assert_eq!(saved.len(), 4, "one TCP and one UDP bidirectional pair");
        let old_flow_id = flow_id(&bpf);
        let (old_token, _) = maps::snapshot(&pin).unwrap();
        drop(bpf);
        // Only this private mount's fixture pins are removed; no host resources.
        for entry in std::fs::read_dir(&fs.0).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        let mut bpf = datapath(&fs);
        assert_ne!(flow_id(&bpf), old_flow_id);
        assert!(flows(&bpf).is_empty());
        assert!(!maps::publish(&pin, old_token, &[], &[], &[], monotonic_ns().unwrap()).unwrap());
        assert_eq!(
            maps::invalidate_routes(&pin).unwrap(),
            0,
            "no leases survive recreation"
        );
        {
            let mut restored = HashMap::<_, NativeFlowKey, NativeFlowValue>::try_from(
                bpf.map_mut("NATIVE_FLOWS").unwrap(),
            )
            .unwrap();
            for (key, value) in &saved {
                restored.insert(*key, *value, 1).unwrap();
            }
        }
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert_eq!(stats(&fs).submitted, 0);
        assert_eq!(return_tests::stats(&fs).submitted, 0);
        assert_eq!(flows(&bpf).len(), saved.len());

        assert_eq!(publish_fixture(&fs), 1);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(stats(&fs).submitted > 0);
        return_tests::publish(&fs, vip);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(return_tests::stats(&fs).submitted > 0);

        {
            let _guard = maps::begin_mutation(&pin).unwrap();
            HashMap::try_from(bpf.map_mut(NATIVE_TARGETS_MAP).unwrap())
                .unwrap()
                .insert(
                    KEY,
                    NativeTargetValue {
                        address: u32::from_be_bytes([203, 0, 113, 21]),
                        port: 8080,
                        weight: 1,
                        flags: 1,
                    },
                    0,
                )
                .unwrap();
        }
        // Reusing the target slot must not move a restored session to its new endpoint.
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        let current = flows(&bpf);
        for (key, value) in saved {
            let restored = current
                .iter()
                .find(|(candidate, _)| *candidate == key)
                .unwrap()
                .1;
            assert_eq!(restored.target, value.target);
            assert_eq!(restored.target_port, value.target_port);
        }
        assert_eq!(stats(&fs).mutation_error, 0);
        assert_eq!(return_tests::stats(&fs).mutation_error, 0);
    })
    .join()
    .unwrap();
}
