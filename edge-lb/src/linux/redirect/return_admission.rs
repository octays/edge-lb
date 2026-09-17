//! Read-only return path observation. Never obtains authority from forward targets.

use super::{admission, model::ReturnContext, resolve};
use anyhow::{Context, Result, ensure};
use futures_util::TryStreamExt;
use rtnetlink::{
    IpVersion,
    packet_route::{
        AddressFamily,
        address::AddressAttribute,
        link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage},
        neighbour::{NeighbourMessage, NeighbourState},
        route::{RouteAttribute, RouteMessage},
    },
};
use std::{collections::BTreeSet, net::IpAddr, time::Duration};

pub(super) fn overlay(link: &LinkMessage) -> bool {
    let kinds: Vec<_> = link
        .attributes
        .iter()
        .filter_map(|attr| {
            if let LinkAttribute::LinkInfo(infos) = attr {
                Some(infos)
            } else {
                None
            }
        })
        .flatten()
        .filter_map(|info| {
            if let LinkInfo::Kind(kind) = info {
                Some(kind)
            } else {
                None
            }
        })
        .collect();
    link.header.link_layer_type == LinkLayerType::Ether
        && link.header.flags.contains(LinkFlags::Up)
        && kinds == vec![&InfoKind::Vxlan]
        && !link
            .attributes
            .iter()
            .any(|attr| matches!(attr, LinkAttribute::Controller(index) if *index != 0))
}

pub(super) fn output(link: &LinkMessage, neighbors: &[NeighbourMessage]) -> bool {
    resolve::plain_ingress(link)
        && link.attributes.iter().any(|a| matches!(a, LinkAttribute::Mtu(mtu) if *mtu >= 68))
        && link.attributes.iter().any(|a| matches!(a, LinkAttribute::Address(mac) if resolve::unicast_mac(mac).is_some()))
        // FIB accepts STALE but does not perform the normal neighbor output NUD
        // work. Withdraw this device's leases until kernel traffic confirms it.
        && neighbors.iter().filter(|n| n.header.ifindex == link.header.index)
            .all(|n| matches!(n.header.state, NeighbourState::Reachable | NeighbourState::Permanent))
}

fn fib_supported(routes: &[RouteMessage]) -> bool {
    resolve::destination_only_fib(routes)
        && routes.iter().all(|r| {
            r.attributes.iter().all(|a| {
                matches!(
                    a,
                    RouteAttribute::Destination(_)
                        | RouteAttribute::Gateway(_)
                        | RouteAttribute::PrefSource(_)
                        | RouteAttribute::Oif(_)
                        | RouteAttribute::Table(_)
                        | RouteAttribute::Priority(_)
                        | RouteAttribute::Metrics(_)
                        | RouteAttribute::CacheInfo(_)
                        | RouteAttribute::Uid(_)
                )
            })
        })
}

pub(super) fn observe(device: &str) -> Result<ReturnContext> {
    admission::check_network_policy(device)?;
    ensure!(
        admission::read_sysctl(&format!("/proc/sys/net/ipv4/conf/{device}/accept_local"))? == 1,
        "return source VIP requires accept_local on overlay"
    );
    super::super::net::run_netlink(async {
        tokio::time::timeout(Duration::from_millis(500), async {
            let (connection, handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(connection);
            let links: Vec<_> = handle.link().get().execute().try_collect().await?;
            let ingress = links
                .iter()
                .find(|link| {
                    link.attributes
                        .iter()
                        .any(|a| matches!(a, LinkAttribute::IfName(name) if name == device))
                })
                .context("return overlay missing")?;
            ensure!(overlay(ingress), "unsupported return ingress topology");
            let mut query = RouteMessage::default();
            query.header.address_family = AddressFamily::Inet;
            let routes: Vec<_> = handle.route().get(query).execute().try_collect().await?;
            ensure!(fib_supported(&routes), "unsupported return FIB context");
            let neighbors: Vec<_> = handle
                .neighbours()
                .get()
                .set_family(IpVersion::V4)
                .execute()
                .try_collect()
                .await?;
            let outputs = links
                .iter()
                .filter(|l| output(l, &neighbors))
                .map(|l| l.header.index)
                .collect();
            let addresses: Vec<_> = handle.address().get().execute().try_collect().await?;
            let mut sources = BTreeSet::new();
            for address in addresses {
                for attr in address.attributes {
                    if let AddressAttribute::Local(IpAddr::V4(ip)) = attr {
                        let first = ip.octets()[0];
                        if first != 0 && first != 127 && first < 224 && !ip.is_link_local() {
                            sources.insert(u32::from(ip));
                        }
                    }
                }
            }
            Ok(ReturnContext {
                ingress: ingress.header.index,
                outputs,
                sources: sources.into_iter().collect(),
            })
        })
        .await
        .context("return context observation timed out")?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn physical() -> LinkMessage {
        let mut link = LinkMessage::default();
        link.header.index = 2;
        link.header.link_layer_type = LinkLayerType::Ether;
        link.header.flags = LinkFlags::Up;
        link.attributes = vec![
            LinkAttribute::Mtu(1500),
            LinkAttribute::Address(vec![2, 0, 0, 0, 0, 1]),
        ];
        link
    }

    #[test]
    fn only_unenslaved_vxlan_ingress_and_plain_ethernet_outputs_are_candidates() {
        let mut link = physical();
        assert!(output(&link, &[]));
        assert!(!overlay(&link));
        link.attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Vxlan,
            )]));
        assert!(overlay(&link));
        assert!(!output(&link, &[]));
        link.attributes.push(LinkAttribute::Controller(9));
        assert!(!overlay(&link));
        let mut veth = physical();
        veth.attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Veth,
            )]));
        assert!(!output(&veth, &[]));
        assert!(!overlay(&veth));
    }

    #[test]
    fn nonconfirmed_ipv4_neighbor_withdraws_entire_output_until_nud_recovers() {
        let link = physical();
        for state in [
            NeighbourState::Stale,
            NeighbourState::Delay,
            NeighbourState::Probe,
            NeighbourState::Failed,
            NeighbourState::Incomplete,
        ] {
            let mut neighbor = NeighbourMessage::default();
            neighbor.header.ifindex = 2;
            neighbor.header.state = state;
            assert!(!output(&link, &[neighbor.clone()]));
            neighbor.header.ifindex = 3;
            assert!(output(&link, &[neighbor]));
        }
        for state in [NeighbourState::Reachable, NeighbourState::Permanent] {
            let mut neighbor = NeighbourMessage::default();
            neighbor.header.ifindex = 2;
            neighbor.header.state = state;
            assert!(output(&link, &[neighbor]));
        }
    }

    #[test]
    fn return_fib_rejects_selectors_and_multipath_even_with_full_lookup() {
        let mut route = RouteMessage::default();
        assert!(fib_supported(&[route.clone()]));
        route.header.tos = 4;
        assert!(!fib_supported(&[route.clone()]));
        route.header.tos = 0;
        route.header.source_prefix_length = 24;
        assert!(!fib_supported(&[route.clone()]));
        route.header.source_prefix_length = 0;
        route.attributes.push(RouteAttribute::MultiPath(vec![]));
        assert!(!fib_supported(&[route]));
    }
}
