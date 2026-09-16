//! Typed rtnetlink fixtures. Each operation opens its socket in the caller's netns.

use futures_util::TryStreamExt;
use rtnetlink::{
    Handle, LinkBridge, LinkDummy, LinkMessageBuilder, LinkUnspec, LinkVeth, LinkVxlan,
    RouteMessageBuilder,
    packet_route::{
        AddressFamily,
        link::{LinkAttribute, LinkMessage},
        neighbour::{
            NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
        },
        route::{RouteMessage, RouteScope, RouteType},
        rule::{RuleAction, RuleAttribute},
    },
};
use std::{future::Future, net::Ipv4Addr, os::fd::AsRawFd, time::Duration};

pub(in crate::linux) fn netlink<T: Send, F, Fut>(action: F) -> T
where
    F: FnOnce(Handle) -> Fut + Send,
    Fut: Future<Output = anyhow::Result<T>> + Send,
{
    crate::linux::net::run_netlink(async move {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        tokio::time::timeout(Duration::from_secs(3), action(handle)).await?
    })
    .unwrap()
}

pub(in crate::linux) fn index(dev: &str) -> u32 {
    crate::linux::net::ifindex(dev).unwrap()
}
pub(in crate::linux) fn link(dev: &str) -> LinkMessageBuilder<LinkUnspec> {
    LinkUnspec::new_with_index(index(dev))
}
pub(in crate::linux) fn set_link(change: LinkMessageBuilder<LinkUnspec>) {
    netlink(|h| async move { Ok(h.link().set(change.build()).execute().await?) });
}
pub(in crate::linux) fn add_link(message: LinkMessage) {
    netlink(|h| async move { Ok(h.link().add(message).execute().await?) });
}
pub(in crate::linux) fn dummy(dev: &str) {
    add_link(LinkDummy::new(dev).build());
}
pub(in crate::linux) fn bridge(dev: &str) {
    add_link(LinkBridge::new(dev).build());
}
pub(in crate::linux) fn veth(dev: &str, peer: &str) {
    add_link(LinkVeth::new(dev, peer).build());
}
pub(in crate::linux) fn move_link(dev: &str, tid: u32) {
    let ns = std::fs::File::open(format!("/proc/{tid}/ns/net")).unwrap();
    set_link(link(dev).setns_by_fd(ns.as_raw_fd()));
}
pub(in crate::linux) fn vxlan(dev: &str, underlay: &str, local: &str, remote: Option<&str>) {
    let builder = LinkVxlan::new(dev, 42)
        .dev(index(underlay))
        .local(local.parse().unwrap())
        .port(4789)
        .learning(false);
    let builder = if let Some(remote) = remote {
        builder.remote(remote.parse().unwrap())
    } else {
        builder
    };
    add_link(builder.build());
}
pub(in crate::linux) fn mac(value: &str) -> Vec<u8> {
    let bytes: Vec<_> = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).unwrap())
        .collect();
    assert_eq!(bytes.len(), 6);
    bytes
}
fn prefix(cidr: &str) -> (Ipv4Addr, u8) {
    let (address, length) = cidr.split_once('/').unwrap();
    let length = length.parse().unwrap();
    assert!(length <= 32);
    (address.parse().unwrap(), length)
}
pub(in crate::linux) fn address(dev: &str, cidr: &str) {
    let (address, prefix) = prefix(cidr);
    let index = index(dev);
    netlink(|h| async move {
        Ok(h.address()
            .add(index, address.into(), prefix)
            .execute()
            .await?)
    });
}
pub(in crate::linux) fn neighbor(dev: &str, address: &str, lladdr: &str, state: NeighbourState) {
    let index = index(dev);
    let address = address.parse().unwrap();
    let mac = mac(lladdr);
    netlink(|h| async move {
        Ok(h.neighbours()
            .add(index, address)
            .link_local_address(&mac)
            .state(state)
            .replace()
            .execute()
            .await?)
    });
}
pub(in crate::linux) fn delete_neighbor(dev: &str, address: &str) {
    let mut message = NeighbourMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.ifindex = index(dev);
    message
        .attributes
        .push(NeighbourAttribute::Destination(NeighbourAddress::Inet(
            address.parse().unwrap(),
        )));
    netlink(|h| async move { Ok(h.neighbours().del(message).execute().await?) });
}
pub(in crate::linux) fn fdb(dev: &str, lladdr: &str, remote: &str) {
    let index = index(dev);
    let mac = mac(lladdr);
    let remote = remote.parse().unwrap();
    netlink(|h| async move {
        Ok(h.neighbours()
            .add_bridge(index, &mac)
            .destination(remote)
            .flags(NeighbourFlags::Own)
            .replace()
            .execute()
            .await?)
    });
}
pub(in crate::linux) fn route(
    cidr: &str,
    dev: &str,
    via: Option<&str>,
) -> RouteMessageBuilder<Ipv4Addr> {
    let (address, prefix) = prefix(cidr);
    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new().destination_prefix(address, prefix);
    if !dev.is_empty() {
        builder = builder.output_interface(index(dev));
    }
    if let Some(via) = via {
        builder.gateway(via.parse().unwrap())
    } else {
        builder.scope(RouteScope::Link)
    }
}
pub(in crate::linux) fn add_route(builder: RouteMessageBuilder<Ipv4Addr>) {
    netlink(|h| async move { Ok(h.route().add(builder.build()).execute().await?) });
}
pub(in crate::linux) fn replace_route(builder: RouteMessageBuilder<Ipv4Addr>) {
    netlink(|h| async move { Ok(h.route().add(builder.build()).replace().execute().await?) });
}
pub(in crate::linux) fn delete_route(cidr: &str, kind: RouteType) {
    let mut message = route(cidr, "", None).kind(kind).build();
    message.header.scope = RouteScope::NoWhere;
    message.header.protocol = rtnetlink::packet_route::route::RouteProtocol::Unspec;
    netlink(|h| async move { Ok(h.route().del(message).execute().await?) });
}
pub(in crate::linux) fn rule(priority: u32, mark: u32, table: u32, source: Option<&str>) {
    let source = source.map(prefix);
    netlink(|h| async move {
        let mut rule = h
            .rule()
            .add()
            .v4()
            .priority(priority)
            .fw_mark(mark)
            .table_id(table)
            .action(RuleAction::ToTable);
        if let Some((address, prefix)) = source {
            rule = rule.source_prefix(address, prefix);
        }
        rule.message_mut()
            .attributes
            .push(RuleAttribute::FwMask(u32::MAX));
        rule.message_mut().attributes.push(RuleAttribute::Protocol(
            rtnetlink::packet_route::route::RouteProtocol::Static,
        ));
        Ok(rule.execute().await?)
    });
}
pub(in crate::linux) fn delete_rule(priority: u32) {
    netlink(|h| async move {
        let rules: Vec<_> = h
            .rule()
            .get(rtnetlink::IpVersion::V4)
            .execute()
            .try_collect()
            .await?;
        let rules: Vec<_> = rules
            .into_iter()
            .filter(|r| r.attributes.contains(&RuleAttribute::Priority(priority)))
            .collect();
        assert_eq!(rules.len(), 1);
        for rule in rules {
            h.rule().del(rule).execute().await?;
        }
        Ok(())
    });
}
pub(in crate::linux) fn received(dev: &str) -> u64 {
    let index = index(dev);
    netlink(|h| async move {
        let links: Vec<_> = h
            .link()
            .get()
            .match_index(index)
            .execute()
            .try_collect()
            .await?;
        Ok(links[0]
            .attributes
            .iter()
            .find_map(|a| match a {
                LinkAttribute::Stats64(stats) => Some(stats.rx_packets),
                _ => None,
            })
            .unwrap())
    })
}
pub(in crate::linux) fn diagnose(label: &str) {
    netlink(|h| async move {
        let links: Vec<_> = h.link().get().execute().try_collect().await?;
        let routes: Vec<_> = h
            .route()
            .get(RouteMessage::default())
            .execute()
            .try_collect()
            .await?;
        let neighbors: Vec<_> = h.neighbours().get().execute().try_collect().await?;
        eprintln!("{label}: links={links:?} routes={routes:?} neighbors={neighbors:?}");
        Ok(())
    });
}
