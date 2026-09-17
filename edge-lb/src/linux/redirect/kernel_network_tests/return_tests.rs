//! Actual return FIB/redirect with explicit fixture authorization, not check_host.

use crate::linux::test_support as net;
use rtnetlink::packet_route::neighbour::NeighbourState;

use super::super::{
    admission, maps, model::ReturnContext, netlink, planner, reconcile::monotonic_ns,
    return_planner, test_support::PrivateBpffs,
};
use super::{KEY, datapath, topology, traffic};
use aya::maps::HashMap;
use edge_lb_common::{
    NATIVE_TARGETS_MAP, NativeTargetKey, NativeTargetValue,
    return_redirect::{NATIVE_RETURN_LEASES_MAP, NATIVE_RETURN_STATS_MAP, ReturnRedirectStats},
};
use std::{collections::BTreeSet, time::Duration};

pub(super) fn stats(fs: &PrivateBpffs) -> ReturnRedirectStats {
    super::super::return_stats(&fs.0.join(NATIVE_RETURN_STATS_MAP)).unwrap()
}

pub(super) fn publish(fs: &PrivateBpffs, source: u32) {
    let started = monotonic_ns().unwrap();
    let pin =
        fs.0.join(edge_lb_common::redirect::NATIVE_TARGET_ROUTES_MAP);
    let (token, _) = maps::snapshot(&pin).unwrap();
    let context = ReturnContext {
        ingress: crate::linux::net::ifindex("edge-hub").unwrap(),
        outputs: BTreeSet::from([crate::linux::net::ifindex("ingress0").unwrap()]),
        sources: vec![source],
    };
    admission::check_return_tc(
        context.ingress,
        &context.outputs,
        111,
        &fs.0.join(NATIVE_RETURN_LEASES_MAP),
    )
    .unwrap();
    let desired = return_planner::plan(&context, started).unwrap();
    assert!(
        maps::publish(
            &pin,
            token,
            &[],
            &desired,
            &netlink::local_addresses().unwrap(),
            monotonic_ns().unwrap()
        )
        .unwrap()
    );
}

#[test]
fn return_fib_redirect_survives_expiry_neighbor_recovery_and_unhealthy_target() {
    std::thread::spawn(|| {
        let topology = topology::Topology::new();
        let fs = PrivateBpffs::new();
        let mut bpf = datapath(&fs);
        let _servers = traffic::Servers::new(&topology);
        let mut clients = traffic::Clients::new(&topology).unwrap();
        let vip = u32::from_be_bytes([203, 0, 113, 100]);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert_eq!(stats(&fs).submitted, 0);
        // veth is fixture-only. Production output admission still rejects it.
        assert!(admission::check_host("ingress0").is_err());

        publish(&fs, vip);
        super::return_packets::verify(&bpf);
        let before = stats(&fs);
        clients.exchange_udp(96);
        assert!(
            stats(&fs).submitted > before.submitted,
            "UDP return must redirect: {:?}",
            stats(&fs)
        );
        let before = stats(&fs);
        clients.exchange_tcp(96);
        assert!(
            stats(&fs).submitted > before.submitted,
            "TCP return must redirect: {:?}",
            stats(&fs)
        );
        traffic::new_udp_probe(&topology, 40100, true);
        clients.exchange_tcp(65536);

        publish(&fs, vip + 1);
        let before = stats(&fs);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(stats(&fs).policy > before.policy);
        assert_eq!(stats(&fs).submitted, before.submitted);

        publish(&fs, vip);
        std::thread::sleep(Duration::from_nanos(planner::LEASE_NS + 50_000_000));
        let before = stats(&fs);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(stats(&fs).expired > before.expired);
        assert_eq!(stats(&fs).submitted, before.submitted);

        publish(&fs, vip);
        net::delete_neighbor("ingress0", "198.51.100.2");
        let before = stats(&fs);
        clients.exchange_udp(96);
        assert!(stats(&fs).neighbor > before.neighbor);
        let before = stats(&fs);
        clients.exchange_udp(96);
        assert!(
            stats(&fs).submitted > before.submitted,
            "ARP recovery restores FIB success"
        );

        topology
            .client
            .run(|| net::address("client0", "198.51.100.3/24"));
        net::neighbor(
            "ingress0",
            "198.51.100.3",
            "02:00:00:00:00:22",
            NeighbourState::Permanent,
        );
        net::add_route(net::route(
            "198.51.100.2/32",
            "ingress0",
            Some("198.51.100.3"),
        ));
        publish(&fs, vip);
        let before = stats(&fs);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(
            stats(&fs).submitted > before.submitted,
            "FIB uses a real L3 next hop"
        );

        let pin =
            fs.0.join(edge_lb_common::redirect::NATIVE_TARGET_ROUTES_MAP);
        {
            let _guard = maps::begin_mutation(&pin).unwrap();
            HashMap::<_, NativeTargetKey, NativeTargetValue>::try_from(
                bpf.map_mut(NATIVE_TARGETS_MAP).unwrap(),
            )
            .unwrap()
            .remove(&KEY)
            .unwrap();
        }
        let before = stats(&fs);
        clients.exchange_udp(96);
        assert_eq!(
            stats(&fs).submitted,
            before.submitted,
            "health invalidates return leases too"
        );
        publish(&fs, vip);
        let before = stats(&fs);
        clients.exchange_udp(96);
        clients.exchange_tcp(96);
        assert!(
            stats(&fs).submitted > before.submitted,
            "existing flow return is independent of target health"
        );
        assert_eq!(stats(&fs).mutation_error, 0);
        let ingress = crate::linux::net::ifindex("edge-hub").unwrap();
        let outputs = BTreeSet::from([crate::linux::net::ifindex("ingress0").unwrap()]);
        let lease_pin = fs.0.join(NATIVE_RETURN_LEASES_MAP);
        assert!(admission::check_return_tc(ingress, &outputs, 110, &lease_pin).is_err());
        assert!(
            admission::check_return_tc(ingress, &outputs, 111, &pin).is_err(),
            "wrong map ownership"
        );
        let mut foreign = super::super::test_support::load_bpf();
        super::super::test_support::attach_test_program(
            &mut foreign,
            edge_lb_common::NATIVE_DNAT_RETURN_PROGRAM,
            "edge-hub",
            112,
        );
        assert!(
            admission::check_return_tc(ingress, &outputs, 111, &lease_pin).is_err(),
            "foreign return ingress"
        );
    })
    .join()
    .unwrap();
}
