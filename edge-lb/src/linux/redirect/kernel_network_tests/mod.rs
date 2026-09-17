//! Real VXLAN/L3 traffic with explicit fixture publication. The veth ingress is
//! intentionally NOT admitted by production check_host; no test switch bypasses it.

use crate::linux::test_support as net;
use rtnetlink::packet_route::neighbour::NeighbourState;

mod reload;
mod return_packets;
mod return_tests;
mod topology;
mod traffic;

use std::{net::Ipv4Addr, path::Path, time::Duration};

use aya::{
    Ebpf,
    maps::{Array, HashMap},
};
use edge_lb_common::{
    NATIVE_DNAT_INGRESS_PROGRAM, NATIVE_DNAT_RETURN_PROGRAM, NATIVE_LISTENERS_MAP,
    NATIVE_TARGETS_MAP, NativeListenerLookupKey, NativeListenerLookupValue, NativeTargetKey,
    NativeTargetValue, PROGRAM_NAME,
    redirect::{
        NATIVE_LOCAL_ADDRS_MAP, NATIVE_REDIRECT_STATS_MAP, NATIVE_TARGET_ROUTES_MAP,
        NativeRedirectStats,
    },
    return_redirect::{NATIVE_RETURN_LEASES_MAP, NATIVE_RETURN_STATS_MAP},
};

use super::{
    admission, maps, netlink, planner,
    reconcile::monotonic_ns,
    test_support::{PrivateBpffs, attach_test_program, load_bpf},
};

const TARGET: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 20);
const KEY: NativeTargetKey = NativeTargetKey {
    listener_id: 1,
    target_id: 0,
};

fn datapath(fs: &PrivateBpffs) -> Ebpf {
    let mut bpf = load_bpf();
    for name in [
        NATIVE_TARGET_ROUTES_MAP,
        NATIVE_REDIRECT_STATS_MAP,
        NATIVE_LOCAL_ADDRS_MAP,
        NATIVE_RETURN_LEASES_MAP,
        NATIVE_RETURN_STATS_MAP,
        NATIVE_LISTENERS_MAP,
        NATIVE_TARGETS_MAP,
        "DSCP_CFG",
    ] {
        bpf.map(name).unwrap().pin(fs.0.join(name)).unwrap();
    }
    Array::try_from(bpf.map_mut("DSCP_CFG").unwrap())
        .unwrap()
        .set(0, 46u32, 0)
        .unwrap();
    HashMap::try_from(bpf.map_mut("TARGET_PORTS").unwrap())
        .unwrap()
        .insert(5060u32, 1u32, 0)
        .unwrap();
    let mut listeners = HashMap::try_from(bpf.map_mut(NATIVE_LISTENERS_MAP).unwrap()).unwrap();
    for proto in [6, 17] {
        listeners
            .insert(
                NativeListenerLookupKey {
                    vip: u32::from(Ipv4Addr::new(203, 0, 113, 100)),
                    port: 5060u16.to_be(),
                    proto,
                    _pad: 0,
                },
                NativeListenerLookupValue {
                    listener_id: 1,
                    target_count: 1,
                    weight_total: 1,
                    timeout_secs: 60,
                    dscp: 46,
                    ..Default::default()
                },
                0,
            )
            .unwrap();
    }
    target(&mut bpf, true);
    for dev in ["ingress0", "edge-hub"] {
        crate::linux::tc::add_clsact_best_effort(dev);
    }
    attach_test_program(&mut bpf, PROGRAM_NAME, "ingress0", 100);
    attach_test_program(&mut bpf, NATIVE_DNAT_INGRESS_PROGRAM, "ingress0", 110);
    attach_test_program(&mut bpf, NATIVE_DNAT_RETURN_PROGRAM, "edge-hub", 111);
    bpf
}

fn target(bpf: &mut Ebpf, active: bool) {
    HashMap::try_from(bpf.map_mut(NATIVE_TARGETS_MAP).unwrap())
        .unwrap()
        .insert(
            KEY,
            NativeTargetValue {
                address: TARGET.into(),
                port: 8080,
                weight: 1,
                flags: u32::from(active),
            },
            0,
        )
        .unwrap();
}

/// Exercise the real snapshot/route/planner/TC/publication pipeline, but state
/// explicitly that this is fixture authorization, not production host admission.
fn publish_fixture(fs: &PrivateBpffs) -> usize {
    let started = monotonic_ns().unwrap();
    let pin = fs.0.join(NATIVE_TARGET_ROUTES_MAP);
    let (token, targets) = maps::snapshot(&pin).unwrap();
    let addresses: Vec<_> = targets.iter().map(|target| target.target).collect();
    let routes = netlink::observe_target_routes(&addresses).unwrap();
    for route in &routes {
        assert_eq!(route.device.as_deref(), Some("edge-hub"));
        assert_eq!(route.next_hop, Some("192.0.2.2".parse().unwrap()));
    }
    let ingress = crate::linux::net::ifindex("ingress0").unwrap();
    let desired = planner::plan(&targets, &routes, ingress, started).unwrap();
    admission::check_tc(
        ingress,
        &desired.iter().map(|(_, route)| route.ifindex).collect(),
        100,
        &pin,
        &fs.0.join("DSCP_CFG"),
    )
    .unwrap();
    assert!(
        maps::publish_routes(
            &pin,
            token,
            &desired,
            &netlink::local_addresses().unwrap(),
            monotonic_ns().unwrap()
        )
        .unwrap()
    );
    desired.len()
}

fn stats(fs: &PrivateBpffs) -> NativeRedirectStats {
    super::stats(&fs.0.join(NATIVE_REDIRECT_STATS_MAP)).unwrap()
}

fn invalidate(pin: &Path) {
    maps::invalidate_routes(pin).unwrap();
}

#[test]
fn vxlan_l3_tcp_udp_keep_sessions_across_redirect_expiry_health_and_neighbor_fallback() {
    std::thread::spawn(|| {
        let topology = topology::Topology::new();
        let fs = PrivateBpffs::new();
        let mut bpf = datapath(&fs);
        let pin = fs.0.join(NATIVE_TARGET_ROUTES_MAP);
        assert!(
            admission::check_host("ingress0")
                .unwrap_err()
                .to_string()
                .contains("unsupported ingress device topology"),
            "veth fixture must not weaken production admission"
        );
        let _servers = traffic::Servers::new(&topology);
        let mut clients = traffic::Clients::new(&topology).unwrap_or_else(|error| {
            topology.diagnose();
            eprintln!("redirect stats: {:?}", stats(&fs));
            let native =
                aya::maps::PerCpuArray::<_, edge_lb_common::NativeDatapathStats>::try_from(
                    bpf.map("NATIVE_STATS").unwrap(),
                )
                .unwrap();
            eprintln!("native stats: {:?}", native.get(&0, 0).unwrap());
            panic!("client connect: {error}");
        });
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert_eq!(
            stats(&fs).submitted,
            0,
            "empty cache is a real working slow path"
        );

        assert_eq!(publish_fixture(&fs), 1);
        let before = stats(&fs);
        clients.exchange_udp(96);
        assert!(
            stats(&fs).submitted > before.submitted,
            "UDP must really redirect: {:?}",
            stats(&fs)
        );
        let before = stats(&fs);
        clients.exchange_tcp(96);
        assert!(
            stats(&fs).submitted > before.submitted,
            "TCP must really redirect: {:?}",
            stats(&fs)
        );

        let before = stats(&fs);
        traffic::new_udp_probe(&topology, 40001, true);
        assert!(
            stats(&fs).submitted > before.submitted,
            "new UDP flow redirects too"
        );

        let before = stats(&fs);
        clients.exchange_tcp(65536);
        assert!(
            stats(&fs).unsupported > before.unsupported,
            "bulk TCP exercises offload fallback"
        );

        // Above the VXLAN L3 MTU: the original kernel path fragments the request.
        let before = stats(&fs);
        clients.exchange_udp(1600);
        assert!(stats(&fs).mtu > before.mtu);

        assert_eq!(publish_fixture(&fs), 1);
        std::thread::sleep(Duration::from_nanos(planner::LEASE_NS + 50_000_000));
        let before = stats(&fs);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(stats(&fs).expired > before.expired);
        assert_eq!(stats(&fs).submitted, before.submitted);

        assert_eq!(publish_fixture(&fs), 1);
        {
            let _mutation = maps::begin_mutation(&pin).unwrap();
            target(&mut bpf, false);
        }
        assert_eq!(
            publish_fixture(&fs),
            0,
            "unhealthy target cannot renew route"
        );
        let before = stats(&fs);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(stats(&fs).route_miss > before.route_miss);
        assert_eq!(stats(&fs).submitted, before.submitted);
        traffic::new_udp_probe(&topology, 40002, false);
        {
            // Production health reconciliation removes the unavailable slot.
            let _mutation = maps::begin_mutation(&pin).unwrap();
            HashMap::<_, NativeTargetKey, NativeTargetValue>::try_from(
                bpf.map_mut(NATIVE_TARGETS_MAP).unwrap(),
            )
            .unwrap()
            .remove(&KEY)
            .unwrap();
        }
        assert_eq!(publish_fixture(&fs), 0);
        let before = stats(&fs);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(stats(&fs).route_miss > before.route_miss);
        assert_eq!(stats(&fs).submitted, before.submitted);
        traffic::new_udp_probe(&topology, 40003, false);
        {
            let _mutation = maps::begin_mutation(&pin).unwrap();
            target(&mut bpf, true);
        }
        invalidate(&pin);
        net::neighbor(
            "edge-hub",
            "192.0.2.2",
            "02:00:00:00:00:02",
            NeighbourState::Stale,
        );
        assert_eq!(
            publish_fixture(&fs),
            0,
            "stale neighbor cannot renew a lease"
        );
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        net::delete_neighbor("edge-hub", "192.0.2.2");
        assert_eq!(
            publish_fixture(&fs),
            0,
            "missing neighbor cannot be published"
        );
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        // The fallback traffic above must have recovered the neighbor by ARP.
        assert_eq!(
            publish_fixture(&fs),
            1,
            "kernel NUD recovery must permit a new lease"
        );
        let before = stats(&fs);
        clients.exchange_udp(96);
        assert!(stats(&fs).submitted > before.submitted);
        assert_eq!(stats(&fs).mutation_error, 0);
        let native = aya::maps::PerCpuArray::<_, edge_lb_common::NativeDatapathStats>::try_from(
            bpf.map("NATIVE_STATS").unwrap(),
        )
        .unwrap();
        let native = native.get(&0, 0).unwrap();
        assert!(
            native.iter().map(|cpu| cpu.target_miss).sum::<u64>() > 0,
            "unhealthy new flow is rejected"
        );
        for cpu in native.iter() {
            assert_eq!(cpu.return_miss, 0);
            assert_eq!(cpu.checksum_error, 0);
        }
    })
    .join()
    .unwrap();
}
