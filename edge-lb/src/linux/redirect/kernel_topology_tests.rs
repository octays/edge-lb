//! Private namespaces only: never change the host's routes or interfaces.

use crate::linux::test_support as net;
use rtnetlink::packet_route::neighbour::NeighbourState;

use std::time::{Duration, Instant};

use aya::{Ebpf, maps::HashMap};
use edge_lb_common::{
    NativeTargetKey,
    redirect::{NATIVE_TARGET_ROUTES_MAP, NativeTargetRoute},
};

use super::test_support::{PrivateBpffs, attach_test_program, load_bpf, private_namespace};
use super::{events::RouteEvents, model::RouteObservationState, policy::RoutingPolicyState};

fn setup_overlay() {
    net::dummy("underlay0");
    net::address("underlay0", "198.51.100.1/24");
    net::set_link(net::link("underlay0").up());
    net::vxlan("edge-hub", "underlay0", "198.51.100.1", None);
    net::set_link(
        net::link("edge-hub")
            .address(net::mac("02:00:00:00:00:01"))
            .mtu(1450)
            .up(),
    );
    net::address("edge-hub", "192.0.2.10/24");
    net::neighbor(
        "edge-hub",
        "192.0.2.1",
        "02:00:00:00:00:02",
        NeighbourState::Permanent,
    );
    net::add_route(net::route("203.0.113.0/24", "edge-hub", Some("192.0.2.1")));
}

#[test]
fn kernel_l3_next_hop_ecmp_rules_and_notifications() {
    std::thread::spawn(|| {
        private_namespace(false);
        setup_overlay();
        assert_eq!(
            super::observe_routing_policy().unwrap(),
            RoutingPolicyState::StandardRules
        );
        let target = "203.0.113.20".parse().unwrap();
        let observed = super::observe_target_routes(&[target]).unwrap().remove(0);
        assert_eq!(observed.state, RouteObservationState::Resolved);
        assert_eq!(observed.next_hop, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(observed.destination_mac, Some([2, 0, 0, 0, 0, 2]));
        assert_eq!(observed.device.as_deref(), Some("edge-hub"));
        assert_eq!(observed.mtu, Some(1450));

        // Open each observer after the preceding mutation, so previous events
        // cannot satisfy the next operation's notification assertion.
        let events = RouteEvents::open().unwrap();
        net::delete_neighbor("edge-hub", "192.0.2.1");
        assert!(events.changed().unwrap());
        assert_eq!(
            super::observe_target_routes(&[target]).unwrap()[0].state,
            RouteObservationState::MissingNeighbor
        );

        let events = RouteEvents::open().unwrap();
        net::set_link(net::link("edge-hub").mtu(1400));
        assert!(events.changed().unwrap());
        net::neighbor(
            "edge-hub",
            "192.0.2.1",
            "02:00:00:00:00:02",
            NeighbourState::Permanent,
        );
        let events = RouteEvents::open().unwrap();
        net::replace_route(
            net::route("203.0.113.0/24", "", None)
                .scope(rtnetlink::packet_route::route::RouteScope::Universe)
                .multipath(
                    ["192.0.2.1", "192.0.2.2"]
                        .map(|gateway| {
                            rtnetlink::RouteNextHopBuilder::new(
                                rtnetlink::packet_route::AddressFamily::Inet,
                            )
                            .interface(net::index("edge-hub"))
                            .via(gateway.parse().unwrap())
                            .unwrap()
                            .build()
                        })
                        .to_vec(),
                ),
        );
        assert!(events.changed().unwrap());
        assert_eq!(
            super::observe_target_routes(&[target]).unwrap()[0].state,
            RouteObservationState::UnsupportedRoute
        );

        let events = RouteEvents::open().unwrap();
        net::rule(100, 1, 100, None);
        assert!(events.changed().unwrap());
        assert_eq!(
            super::observe_routing_policy().unwrap(),
            RoutingPolicyState::UnsupportedRule
        );
        net::delete_rule(100);
        assert_eq!(
            super::observe_routing_policy().unwrap(),
            RoutingPolicyState::StandardRules
        );
    })
    .join()
    .unwrap();
}

fn insert_route(bpf: &mut Ebpf) {
    let mut routes = HashMap::try_from(bpf.map_mut(NATIVE_TARGET_ROUTES_MAP).unwrap()).unwrap();
    routes
        .insert(
            NativeTargetKey {
                listener_id: 1,
                target_id: 0,
            },
            NativeTargetRoute {
                expires_ns: u64::MAX,
                ..Default::default()
            },
            0,
        )
        .unwrap();
}

fn assert_empty(bpf: &Ebpf) {
    let routes = HashMap::<_, NativeTargetKey, NativeTargetRoute>::try_from(
        bpf.map(NATIVE_TARGET_ROUTES_MAP).unwrap(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if routes.keys().next().is_none() {
            return;
        }
        assert!(Instant::now() < deadline, "route cache was not invalidated");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn worker_invalidates_pinned_maps_at_start_on_events_and_on_stop() {
    use edge_lb_common::return_redirect::{NATIVE_RETURN_LEASES_MAP, ReturnLease, ReturnLeaseKey};
    fn insert_both(bpf: &mut aya::Ebpf) {
        insert_route(bpf);
        HashMap::try_from(bpf.map_mut(NATIVE_RETURN_LEASES_MAP).unwrap())
            .unwrap()
            .insert(
                ReturnLeaseKey {
                    ingress_ifindex: 7,
                    ifindex: 2,
                    source: 0xc000020a,
                },
                ReturnLease {
                    expires_ns: u64::MAX,
                },
                0,
            )
            .unwrap();
    }
    fn assert_both_empty(bpf: &aya::Ebpf) {
        assert_empty(bpf);
        let leases = HashMap::<_, ReturnLeaseKey, ReturnLease>::try_from(
            bpf.map(NATIVE_RETURN_LEASES_MAP).unwrap(),
        )
        .unwrap();
        assert!(
            leases.keys().next().is_none(),
            "return leases were not invalidated"
        );
    }
    std::thread::spawn(|| {
        private_namespace(true);
        let fs = PrivateBpffs::new();
        let mut bpf = load_bpf();
        let pin = fs.0.join(NATIVE_TARGET_ROUTES_MAP);
        bpf.map_mut(NATIVE_TARGET_ROUTES_MAP)
            .unwrap()
            .pin(&pin)
            .unwrap();
        bpf.map(NATIVE_RETURN_LEASES_MAP)
            .unwrap()
            .pin(fs.0.join(NATIVE_RETURN_LEASES_MAP))
            .unwrap();
        insert_both(&mut bpf);
        let worker = super::spawn(super::RedirectContext {
            route_pin: pin.clone(),
            marker_pin: fs.0.join("marker"),
            ingress_device: "lo".into(),
            return_device: "lo".into(),
            marker_priority: 100,
        })
        .unwrap();
        assert_both_empty(&bpf);
        insert_both(&mut bpf);
        net::dummy("test0");
        assert_both_empty(&bpf);
        insert_both(&mut bpf);
        drop(worker);
        assert_both_empty(&bpf);
        assert_eq!(super::invalidate_routes(&pin).unwrap(), 0);
        assert_eq!(super::invalidate_routes(&fs.0.join("absent")).unwrap(), 0);
        assert!(
            super::invalidate_routes(&fs.0).is_err(),
            "wrong pin type must not report success"
        );
        let stats_pin =
            fs.0.join(edge_lb_common::redirect::NATIVE_REDIRECT_STATS_MAP);
        bpf.map_mut(edge_lb_common::redirect::NATIVE_REDIRECT_STATS_MAP)
            .unwrap()
            .pin(&stats_pin)
            .unwrap();
        assert_eq!(
            super::stats(&stats_pin).unwrap(),
            edge_lb_common::redirect::NativeRedirectStats::default()
        );
        assert!(super::stats(&fs.0.join("absent")).is_err());
    })
    .join()
    .unwrap();
}

#[test]
fn netfilter_and_xfrm_policy_changes_are_observed_and_not_bypassed() {
    std::thread::spawn(|| {
        use super::kernel_policy::KernelPolicyState as State;
        private_namespace(false);
        assert_eq!(super::observe_kernel_policy().unwrap(), State::Clear);
        let events = RouteEvents::open().unwrap();
        crate::linux::nftables::create_probe_table("redirect_probe").unwrap();
        assert!(events.changed().unwrap());
        assert_eq!(super::observe_kernel_policy().unwrap(), State::NftTables);
        crate::linux::nftables::delete_named_table("redirect_probe").unwrap();
        assert_eq!(super::observe_kernel_policy().unwrap(), State::Clear);
        let events = RouteEvents::open().unwrap();
        net::xfrm::default_forward(true);
        assert!(events.changed().unwrap());
        assert_eq!(super::observe_kernel_policy().unwrap(), State::XfrmDefault);
        net::xfrm::default_forward(false);
        let events = RouteEvents::open().unwrap();
        net::xfrm::block_forward(true);
        assert!(events.changed().unwrap());
        assert_eq!(super::observe_kernel_policy().unwrap(), State::XfrmPolicies);
        net::xfrm::block_forward(false);
        assert_eq!(super::observe_kernel_policy().unwrap(), State::Clear);
    })
    .join()
    .unwrap();
}

#[test]
fn publication_fences_invalidated_expired_consumed_and_replaced_snapshots() {
    std::thread::spawn(|| {
        use edge_lb_common::{
            NATIVE_LISTENERS_MAP, NATIVE_TARGETS_MAP, redirect::NATIVE_LOCAL_ADDRS_MAP,
        };
        private_namespace(true);
        let fs = PrivateBpffs::new();
        let mut bpf = load_bpf();
        for name in [
            NATIVE_TARGET_ROUTES_MAP,
            NATIVE_LISTENERS_MAP,
            NATIVE_TARGETS_MAP,
            NATIVE_LOCAL_ADDRS_MAP,
        ] {
            bpf.map_mut(name).unwrap().pin(fs.0.join(name)).unwrap();
        }
        let pin = fs.0.join(NATIVE_TARGET_ROUTES_MAP);
        let key = NativeTargetKey {
            listener_id: 1,
            target_id: 0,
        };
        {
            use edge_lb_common::{
                NativeListenerLookupKey, NativeListenerLookupValue, NativeTargetValue,
            };
            let mut listeners =
                HashMap::try_from(bpf.map_mut(NATIVE_LISTENERS_MAP).unwrap()).unwrap();
            listeners
                .insert(
                    NativeListenerLookupKey::default(),
                    NativeListenerLookupValue {
                        listener_id: 1,
                        dscp: 46,
                        ..Default::default()
                    },
                    0,
                )
                .unwrap();
            let mut targets = HashMap::try_from(bpf.map_mut(NATIVE_TARGETS_MAP).unwrap()).unwrap();
            for (listener_id, target_id, flags, weight) in
                [(1, 0, 1, 1), (1, 1, 0, 1), (1, 2, 1, 0), (2, 0, 1, 1)]
            {
                targets
                    .insert(
                        NativeTargetKey {
                            listener_id,
                            target_id,
                        },
                        NativeTargetValue {
                            address: 0xcb007114,
                            port: 8080,
                            flags,
                            weight,
                        },
                        0,
                    )
                    .unwrap();
            }
            let (_, candidates) = super::maps::snapshot(&pin).unwrap();
            assert_eq!(candidates.len(), 1, "only active, weighted, bound targets");
            assert_eq!(candidates[0].key, key);
            assert_eq!(
                candidates[0].target,
                std::net::Ipv4Addr::new(203, 0, 113, 20)
            );
            assert_eq!((candidates[0].port, candidates[0].dscp), (8080, 46));
        }
        let entry = NativeTargetRoute {
            expires_ns: 100,
            ..Default::default()
        };
        let (token, _) = super::maps::snapshot(&pin).unwrap();
        super::invalidate_routes(&pin).unwrap();
        assert!(!super::maps::publish_routes(&pin, token, &[(key, entry)], &[], 50).unwrap());
        assert_empty(&bpf);
        let (token, _) = super::maps::snapshot(&pin).unwrap();
        assert!(
            super::maps::publish_routes(&pin, token, &[(key, entry)], &[0xc0000201], 50).unwrap()
        );
        assert!(
            !super::maps::publish_routes(&pin, token, &[], &[], 50).unwrap(),
            "token is single-use"
        );
        let locals =
            HashMap::<_, u32, u32>::try_from(bpf.map(NATIVE_LOCAL_ADDRS_MAP).unwrap()).unwrap();
        assert_eq!(locals.get(&0xc0000201, 0).unwrap(), 1);
        let (token, _) = super::maps::snapshot(&pin).unwrap();
        assert!(!super::maps::publish_routes(&pin, token, &[(key, entry)], &[], 100).unwrap());
        assert_empty(&bpf);
        let (token, _) = super::maps::snapshot(&pin).unwrap();
        {
            let _mutation = super::begin_mutation(&pin).unwrap();
        }
        assert!(!super::maps::publish_routes(&pin, token, &[(key, entry)], &[], 50).unwrap());

        let (token, _) = super::maps::snapshot(&pin).unwrap();
        std::fs::remove_file(fs.0.join(NATIVE_LOCAL_ADDRS_MAP)).unwrap();
        assert!(super::maps::publish_routes(&pin, token, &[(key, entry)], &[], 50).is_err());
        assert_empty(&bpf);
        assert!(!super::maps::publish_routes(&pin, token, &[(key, entry)], &[], 50).unwrap());

        let (token, _) = super::maps::snapshot(&pin).unwrap();
        std::fs::remove_file(&pin).unwrap();
        let replacement = load_bpf();
        replacement
            .map(NATIVE_TARGET_ROUTES_MAP)
            .unwrap()
            .pin(&pin)
            .unwrap();
        assert!(!super::maps::publish_routes(&pin, token, &[(key, entry)], &[], 50).unwrap());
        assert_empty(&replacement);
    })
    .join()
    .unwrap();
}

#[test]
fn tc_admission_checks_real_program_map_ownership_and_foreign_filters() {
    std::thread::spawn(|| {
        private_namespace(true);
        setup_overlay();
        let fs = PrivateBpffs::new();
        let mut bpf = load_bpf();
        let pin = fs.0.join(NATIVE_TARGET_ROUTES_MAP);
        let marker = fs.0.join("DSCP_CFG");
        bpf.map(NATIVE_TARGET_ROUTES_MAP)
            .unwrap()
            .pin(&pin)
            .unwrap();
        bpf.map("DSCP_CFG").unwrap().pin(&marker).unwrap();
        aya::programs::tc::qdisc_add_clsact("underlay0").unwrap();
        aya::programs::tc::qdisc_add_clsact("edge-hub").unwrap();
        attach_test_program(&mut bpf, edge_lb_common::PROGRAM_NAME, "underlay0", 100);
        attach_test_program(
            &mut bpf,
            edge_lb_common::NATIVE_DNAT_INGRESS_PROGRAM,
            "underlay0",
            110,
        );
        let ingress = crate::linux::net::ifindex("underlay0").unwrap();
        let outputs = [crate::linux::net::ifindex("edge-hub").unwrap()]
            .into_iter()
            .collect();
        super::admission::check_tc(ingress, &outputs, 100, &pin, &marker).unwrap();
        let mut other = load_bpf();
        let wrong = fs.0.join("wrong-marker");
        other.map("DSCP_CFG").unwrap().pin(&wrong).unwrap();
        assert!(super::admission::check_tc(ingress, &outputs, 100, &pin, &wrong).is_err());
        // Aya's automatic attachment uses TCX where available. Both ingress
        // and egress dependencies must be visible independently of TC dumps.
        use aya::programs::{SchedClassifier, TcAttachType};
        for (device, direction) in [
            ("underlay0", TcAttachType::Ingress),
            ("edge-hub", TcAttachType::Egress),
        ] {
            let mut egress = load_bpf();
            let program: &mut SchedClassifier = egress
                .program_mut(edge_lb_common::PROGRAM_NAME)
                .unwrap()
                .try_into()
                .unwrap();
            program.load().unwrap();
            program.attach(device, direction).unwrap();
            assert!(super::admission::check_tc(ingress, &outputs, 100, &pin, &marker).is_err());
        }
        super::admission::check_tc(ingress, &outputs, 100, &pin, &marker).unwrap();
        {
            use aya::programs::tc::{NlOptions, TcAttachOptions};
            let mut egress = load_bpf();
            let program: &mut SchedClassifier = egress
                .program_mut(edge_lb_common::PROGRAM_NAME)
                .unwrap()
                .try_into()
                .unwrap();
            program.load().unwrap();
            program
                .attach_with_options(
                    "edge-hub",
                    TcAttachType::Egress,
                    TcAttachOptions::Netlink(NlOptions {
                        priority: 120,
                        handle: 1.into(),
                        classid: None,
                    }),
                )
                .unwrap();
            assert!(super::admission::check_tc(ingress, &outputs, 100, &pin, &marker).is_err());
        }
        super::admission::check_tc(ingress, &outputs, 100, &pin, &marker).unwrap();
        // Use an actual foreign BPF program, without depending on optional
        // kernel classifiers such as cls_matchall being installed.
        attach_test_program(&mut other, edge_lb_common::PROGRAM_NAME, "underlay0", 120);
        assert!(super::admission::check_tc(ingress, &outputs, 100, &pin, &marker).is_err());
    })
    .join()
    .unwrap();
}
