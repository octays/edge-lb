//! Pure interpretation of kernel route/link/neighbor messages; no I/O.

use std::net::Ipv4Addr;

use rtnetlink::packet_route::{
    AddressFamily,
    link::{LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage},
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteMetric, RouteType},
};

use super::{TargetRouteObservation, model::RouteObservationState};

pub(super) fn unicast_mac(bytes: &[u8]) -> Option<[u8; 6]> {
    let mac: [u8; 6] = bytes.try_into().ok()?;
    (mac != [0; 6] && mac[0] & 1 == 0).then_some(mac)
}

pub(super) fn plain_ingress(link: &LinkMessage) -> bool {
    link.header.link_layer_type == LinkLayerType::Ether
        && link.header.flags.contains(LinkFlags::Up)
        && !link.attributes.iter().any(|attr| match attr {
            LinkAttribute::Controller(index) => *index != 0,
            LinkAttribute::LinkInfo(_) => true,
            _ => false,
        })
}

pub(super) fn destination_only_fib(routes: &[RouteMessage]) -> bool {
    routes
        .iter()
        .all(|route| route.header.tos == 0 && route.header.source_prefix_length == 0)
}

pub(super) fn observe_route(
    target: Ipv4Addr,
    route: &RouteMessage,
    links: &[LinkMessage],
    neighbors: &[NeighbourMessage],
) -> TargetRouteObservation {
    use RouteObservationState as State;
    let mut observation = TargetRouteObservation {
        target,
        state: State::NonUnicast,
        ifindex: None,
        device: None,
        mtu: None,
        next_hop: None,
        source_mac: None,
        destination_mac: None,
        neighbor_confirmed: false,
    };
    if route.header.address_family != AddressFamily::Inet || route.header.kind != RouteType::Unicast
    {
        return observation;
    }
    if route.header.source_prefix_length != 0
        || route.header.tos != 0
        || !(route.header.flags & !(RouteFlags::Cloned | RouteFlags::Onlink)).is_empty()
    {
        observation.state = State::UnsupportedRoute;
        return observation;
    }
    observation.next_hop = Some(target);
    let mut route_mtu = None;
    for attribute in &route.attributes {
        match attribute {
            RouteAttribute::Oif(index) => observation.ifindex = Some(*index),
            RouteAttribute::Gateway(RouteAddress::Inet(ip)) => observation.next_hop = Some(*ip),
            RouteAttribute::Metrics(metrics) => {
                for metric in metrics {
                    if let RouteMetric::Mtu(mtu) = metric {
                        route_mtu = Some(*mtu);
                    }
                }
            }
            RouteAttribute::Destination(RouteAddress::Inet(_))
            | RouteAttribute::PrefSource(RouteAddress::Inet(_))
            | RouteAttribute::CacheInfo(_)
            | RouteAttribute::Table(_)
            | RouteAttribute::Uid(_)
            | RouteAttribute::Priority(_) => {}
            _ => {
                observation.state = State::UnsupportedRoute;
                return observation;
            }
        }
    }
    let Some(link) = links
        .iter()
        .find(|link| Some(link.header.index) == observation.ifindex && link.header.index != 0)
    else {
        observation.state = State::MissingDevice;
        return observation;
    };
    if !link.header.flags.contains(LinkFlags::Up) {
        observation.state = State::DeviceDown;
        return observation;
    }
    if link.header.link_layer_type != LinkLayerType::Ether {
        observation.state = State::UnsupportedDevice;
        return observation;
    }
    for attribute in &link.attributes {
        match attribute {
            LinkAttribute::Controller(index) if *index != 0 => {
                observation.state = State::UnsupportedDevice;
                return observation;
            }
            LinkAttribute::IfName(name) => observation.device = Some(name.clone()),
            LinkAttribute::Mtu(mtu) => observation.mtu = Some(*mtu),
            LinkAttribute::Address(mac) => observation.source_mac = unicast_mac(mac),
            LinkAttribute::LinkInfo(infos)
                // Preserve the existing kernel VXLAN path. Other virtual
                // devices need their own forwarding/offload validation.
                if infos.iter().any(|info| {
                    matches!(info, LinkInfo::Kind(kind) if *kind != rtnetlink::packet_route::link::InfoKind::Vxlan)
                }) =>
            {
                observation.state = State::UnsupportedDevice;
                return observation;
            }
            _ => {}
        }
    }
    if let (Some(device_mtu), Some(route_mtu)) = (observation.mtu, route_mtu) {
        observation.mtu = Some(device_mtu.min(route_mtu));
    }
    if !observation.mtu.is_some_and(|mtu| mtu >= 68) {
        observation.state = State::InvalidMtu;
        return observation;
    }
    if observation.source_mac.is_none() {
        observation.state = State::InvalidSourceMac;
        return observation;
    }
    let neighbor = neighbors.iter().find(|neighbor| {
        neighbor.header.family == AddressFamily::Inet
            && neighbor.header.ifindex == link.header.index
            && neighbor.attributes.iter().any(|attribute| {
                matches!(attribute, NeighbourAttribute::Destination(NeighbourAddress::Inet(ip))
                    if Some(*ip) == observation.next_hop)
            })
    });
    let Some(neighbor) = neighbor else {
        observation.state = State::MissingNeighbor;
        return observation;
    };
    if !matches!(
        neighbor.header.state,
        NeighbourState::Reachable
            | NeighbourState::Stale
            | NeighbourState::Delay
            | NeighbourState::Probe
            | NeighbourState::Permanent
    ) {
        observation.state = State::UnusableNeighbor;
        return observation;
    }
    observation.destination_mac = neighbor.attributes.iter().find_map(|attribute| {
        if let NeighbourAttribute::LinkLocalAddress(mac) = attribute {
            unicast_mac(mac)
        } else {
            None
        }
    });
    observation.neighbor_confirmed = matches!(
        neighbor.header.state,
        NeighbourState::Reachable | NeighbourState::Permanent
    );
    observation.state = if observation.destination_mac.is_some() {
        State::Resolved
    } else {
        State::InvalidDestinationMac
    };
    observation
}
