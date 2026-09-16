use std::net::Ipv4Addr;

use rtnetlink::packet_route::{
    AddressFamily,
    link::{LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage},
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteMetric, RouteType},
};

use super::{
    model::RouteObservationState,
    netlink::route_lookup_request,
    observe_target_routes,
    resolve::{observe_route, unicast_mac},
};
use rtnetlink::{
    packet_core::{NLM_F_DUMP, NetlinkPayload},
    packet_route::{RouteNetlinkMessage, link::InfoKind},
};

fn fixture() -> (Ipv4Addr, RouteMessage, LinkMessage, NeighbourMessage) {
    let target = Ipv4Addr::new(192, 0, 2, 20);
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
    route.header.kind = RouteType::Unicast;
    route.attributes.push(RouteAttribute::Oif(7));
    let mut link = LinkMessage::default();
    link.header.index = 7;
    link.header.flags = LinkFlags::Up;
    link.header.link_layer_type = LinkLayerType::Ether;
    link.attributes = vec![
        LinkAttribute::IfName("edge-hub".into()),
        LinkAttribute::Address(vec![2, 0, 0, 0, 0, 1]),
        LinkAttribute::Mtu(1450),
        LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Vxlan)]),
    ];
    let mut neighbor = NeighbourMessage::default();
    neighbor.header.family = AddressFamily::Inet;
    neighbor.header.ifindex = 7;
    neighbor.header.state = NeighbourState::Reachable;
    neighbor.attributes = vec![
        NeighbourAttribute::Destination(NeighbourAddress::Inet(target)),
        NeighbourAttribute::LinkLocalAddress(vec![2, 0, 0, 0, 0, 2]),
    ];
    (target, route, link, neighbor)
}

#[test]
fn lookup_is_not_a_route_dump() {
    let target = Ipv4Addr::new(192, 0, 2, 20);
    let request = route_lookup_request(target, false);
    assert_eq!(request.header.flags & NLM_F_DUMP, 0);
    let NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetRoute(route)) = request.payload else {
        panic!("expected route query");
    };
    assert_eq!(route.header.destination_prefix_length, 32);
    assert_eq!(
        route.attributes,
        vec![RouteAttribute::Destination(RouteAddress::Inet(target))]
    );
}

#[test]
fn fib_lookup_keeps_multipath_visible_without_dumping_routes() {
    let request = route_lookup_request(Ipv4Addr::new(192, 0, 2, 20), true);
    assert_eq!(request.header.flags & NLM_F_DUMP, 0);
    let NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetRoute(route)) = request.payload else {
        panic!("expected FIB query");
    };
    assert_eq!(route.header.flags, RouteFlags::FibMatch);
    let (target, mut route, link, neighbor) = fixture();
    route.attributes.push(RouteAttribute::MultiPath(Vec::new()));
    assert_eq!(
        observe_route(target, &route, &[link], &[neighbor]).state,
        RouteObservationState::UnsupportedRoute
    );
}

#[test]
fn route_flags_and_tos_cannot_be_ignored() {
    let (target, route, link, neighbor) = fixture();
    assert!(super::resolve::destination_only_fib(std::slice::from_ref(
        &route
    )));
    for flags in [
        RouteFlags::Dead,
        RouteFlags::Linkdown,
        RouteFlags::Unresolved,
        RouteFlags::Equalize,
    ] {
        let mut route = route.clone();
        route.header.flags = flags;
        assert_eq!(
            observe_route(target, &route, &[link.clone()], &[neighbor.clone()]).state,
            RouteObservationState::UnsupportedRoute
        );
    }
    let mut route = route;
    route.header.tos = 184;
    assert!(!super::resolve::destination_only_fib(std::slice::from_ref(
        &route
    )));
    assert_eq!(
        observe_route(target, &route, &[link], &[neighbor]).state,
        RouteObservationState::UnsupportedRoute
    );
}

#[test]
fn direct_overlay_keeps_vxlan_output_and_l3_mtu() {
    let (target, route, link, neighbor) = fixture();
    let observed = observe_route(target, &route, &[link], &[neighbor]);
    assert_eq!(observed.state, RouteObservationState::Resolved);
    assert_eq!(observed.device.as_deref(), Some("edge-hub"));
    assert_eq!(observed.ifindex, Some(7));
    assert_eq!(observed.next_hop, Some(target));
    assert_eq!(observed.mtu, Some(1450));
    assert_eq!(observed.destination_mac, Some([2, 0, 0, 0, 0, 2]));
}

#[test]
fn gateway_route_resolves_next_hop_neighbor_and_minimum_mtu() {
    let (target, mut route, link, mut neighbor) = fixture();
    let gateway = Ipv4Addr::new(192, 0, 2, 1);
    route
        .attributes
        .push(RouteAttribute::Gateway(RouteAddress::Inet(gateway)));
    route
        .attributes
        .push(RouteAttribute::Metrics(vec![RouteMetric::Mtu(1400)]));
    neighbor.attributes[0] = NeighbourAttribute::Destination(NeighbourAddress::Inet(gateway));
    let observed = observe_route(target, &route, &[link], &[neighbor]);
    assert_eq!(observed.state, RouteObservationState::Resolved);
    assert_eq!(observed.next_hop, Some(gateway));
    assert_eq!(observed.mtu, Some(1400));
}

#[test]
fn neighbors_must_match_device_and_family() {
    let (target, route, link, neighbor) = fixture();
    let mut wrong = neighbor.clone();
    wrong.header.ifindex = 8;
    assert_eq!(
        observe_route(target, &route, std::slice::from_ref(&link), &[wrong]).state,
        RouteObservationState::MissingNeighbor
    );
    let mut neighbor = neighbor;
    neighbor.header.family = AddressFamily::Bridge;
    assert_eq!(
        observe_route(target, &route, &[link], &[neighbor]).state,
        RouteObservationState::MissingNeighbor
    );
}

#[test]
fn unresolved_and_failed_neighbors_are_not_usable() {
    let (target, route, link, neighbor) = fixture();
    for state in [
        NeighbourState::Incomplete,
        NeighbourState::Failed,
        NeighbourState::None,
        NeighbourState::Noarp,
    ] {
        let mut neighbor = neighbor.clone();
        neighbor.header.state = state;
        assert_eq!(
            observe_route(target, &route, &[link.clone()], &[neighbor]).state,
            RouteObservationState::UnusableNeighbor
        );
    }
    for state in [
        NeighbourState::Reachable,
        NeighbourState::Stale,
        NeighbourState::Delay,
        NeighbourState::Probe,
        NeighbourState::Permanent,
    ] {
        let mut neighbor = neighbor.clone();
        neighbor.header.state = state;
        assert_eq!(
            observe_route(target, &route, &[link.clone()], &[neighbor]).state,
            RouteObservationState::Resolved
        );
    }
}

#[test]
fn invalid_mac_addresses_are_rejected() {
    for bytes in [
        vec![0; 6],
        vec![255; 6],
        vec![1, 0, 0, 0, 0, 1],
        vec![2; 5],
        vec![2; 8],
    ] {
        assert_eq!(unicast_mac(&bytes), None);
    }
    let (target, route, mut link, mut neighbor) = fixture();
    neighbor.attributes[1] = NeighbourAttribute::LinkLocalAddress(vec![0; 6]);
    assert_eq!(
        observe_route(target, &route, &[link.clone()], &[neighbor.clone()]).state,
        RouteObservationState::InvalidDestinationMac
    );
    link.attributes[1] = LinkAttribute::Address(vec![0; 6]);
    assert_eq!(
        observe_route(target, &route, &[link], &[neighbor]).state,
        RouteObservationState::InvalidSourceMac
    );
}

#[test]
fn local_and_blackhole_routes_are_not_forwarding_candidates() {
    let (target, mut route, link, neighbor) = fixture();
    for kind in [
        RouteType::Local,
        RouteType::BlackHole,
        RouteType::Unreachable,
    ] {
        route.header.kind = kind;
        assert_eq!(
            observe_route(target, &route, &[link.clone()], &[neighbor.clone()]).state,
            RouteObservationState::NonUnicast
        );
    }
}

#[test]
fn missing_down_and_unsupported_devices_are_reported() {
    let (target, route, mut link, neighbor) = fixture();
    assert_eq!(
        observe_route(target, &route, &[], &[neighbor.clone()]).state,
        RouteObservationState::MissingDevice
    );
    link.header.flags = LinkFlags::empty();
    assert_eq!(
        observe_route(target, &route, &[link.clone()], &[neighbor.clone()]).state,
        RouteObservationState::DeviceDown
    );
    link.header.flags = LinkFlags::Up;
    link.attributes[3] = LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Vlan)]);
    assert_eq!(
        observe_route(target, &route, &[link], &[neighbor]).state,
        RouteObservationState::UnsupportedDevice
    );
}

#[test]
fn enslaved_outputs_and_nonphysical_ingress_require_kernel_path() {
    let (target, route, mut link, neighbor) = fixture();
    link.attributes.push(LinkAttribute::Controller(9));
    assert_eq!(
        observe_route(target, &route, &[link.clone()], &[neighbor]).state,
        RouteObservationState::UnsupportedDevice
    );
    assert!(!super::resolve::plain_ingress(&link));
    link.attributes.retain(|attr| {
        !matches!(
            attr,
            LinkAttribute::Controller(_) | LinkAttribute::LinkInfo(_)
        )
    });
    assert!(super::resolve::plain_ingress(&link));
    link.attributes.push(LinkAttribute::Controller(9));
    assert!(!super::resolve::plain_ingress(&link));
}

#[test]
fn multipath_and_unknown_mtu_do_not_produce_candidates() {
    let (target, mut route, mut link, neighbor) = fixture();
    route.attributes.push(RouteAttribute::MultiPath(Vec::new()));
    assert_eq!(
        observe_route(target, &route, &[link.clone()], &[neighbor.clone()]).state,
        RouteObservationState::UnsupportedRoute
    );
    route.attributes.pop();
    link.attributes[2] = LinkAttribute::Mtu(0);
    assert_eq!(
        observe_route(target, &route, &[link], &[neighbor]).state,
        RouteObservationState::InvalidMtu
    );
}

#[test]
fn empty_target_list_requires_no_netlink_connection() {
    assert!(observe_target_routes(&[]).unwrap().is_empty());
}

#[test]
fn local_lookup_uses_kernel_route_response_and_deduplicates() {
    let observations = observe_target_routes(&[Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST])
        .expect("read-only loopback route lookup");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].state, RouteObservationState::NonUnicast);
}

#[tokio::test]
async fn lookup_can_run_from_an_existing_tokio_runtime() {
    let observations = observe_target_routes(&[Ipv4Addr::LOCALHOST])
        .expect("lookup must not nest block_on inside the caller runtime");
    assert_eq!(observations[0].state, RouteObservationState::NonUnicast);
}
