//! Bounded, read-only rtnetlink collection. No forwarding policy decisions.

use std::{collections::BTreeSet, net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use futures_util::{StreamExt, TryStreamExt};
use rtnetlink::{
    IpVersion, new_connection,
    packet_core::{NLM_F_REQUEST, NetlinkMessage, NetlinkPayload},
    packet_route::{
        AddressFamily, RouteNetlinkMessage,
        route::{RouteAddress, RouteAttribute, RouteFlags, RouteMessage},
    },
};

use super::{
    TargetRouteObservation,
    model::RouteObservationState,
    policy::{RoutingPolicyState, inspect_rules},
    resolve::observe_route,
};

pub(super) fn check_ingress_and_route_context(ingress: &str) -> Result<()> {
    super::super::net::run_netlink(async {
        tokio::time::timeout(Duration::from_millis(500), async {
            let (connection, handle, _) = new_connection()?;
            tokio::spawn(connection);
            let links: Vec<_> = handle
                .link()
                .get()
                .match_name(ingress.to_owned())
                .execute()
                .try_collect()
                .await?;
            ensure!(
                links.len() == 1 && super::resolve::plain_ingress(&links[0]),
                "unsupported ingress device topology"
            );
            // TOS-specific FIB entries can change forwarding without an RPDB
            // selector. Destination-only cache keys must not hide them.
            let mut query = RouteMessage::default();
            query.header.address_family = AddressFamily::Inet;
            let routes: Vec<_> = handle.route().get(query).execute().try_collect().await?;
            ensure!(
                super::resolve::destination_only_fib(&routes),
                "source/TOS-specific FIB routes"
            );
            Ok(())
        })
        .await
        .context("ingress/FIB context observation timed out")?
    })
}

pub(super) fn local_addresses() -> Result<Vec<u32>> {
    use rtnetlink::packet_route::address::AddressAttribute;
    super::super::net::run_netlink(async {
        tokio::time::timeout(Duration::from_millis(500), async {
            let (connection, handle, _) = new_connection()?;
            tokio::spawn(connection);
            let messages: Vec<_> = handle.address().get().execute().try_collect().await?;
            let mut addresses = BTreeSet::new();
            for message in messages {
                for attr in message.attributes {
                    if let AddressAttribute::Local(std::net::IpAddr::V4(ip))
                    | AddressAttribute::Address(std::net::IpAddr::V4(ip))
                    | AddressAttribute::Broadcast(ip) = attr
                    {
                        addresses.insert(u32::from(ip));
                    }
                }
            }
            Ok(addresses.into_iter().collect())
        })
        .await
        .context("local address observation timed out")?
    })
}

pub fn observe_routing_policy() -> Result<RoutingPolicyState> {
    super::super::net::run_netlink(async {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (connection, handle, _) = new_connection().context("opening rtnetlink")?;
            tokio::spawn(connection);
            let rules: Vec<_> = handle
                .rule()
                .get(IpVersion::V4)
                .execute()
                .try_collect()
                .await?;
            Ok(inspect_rules(&rules))
        })
        .await
        .context("routing policy observation timed out")?
    })
}

/// Snapshot link/neighbor state once and query each distinct destination.
/// The result does not account for the eventual client's source, mark or ports.
pub fn observe_target_routes(targets: &[Ipv4Addr]) -> Result<Vec<TargetRouteObservation>> {
    let targets: BTreeSet<_> = targets.iter().copied().collect();
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    super::super::net::run_netlink(async move {
        tokio::time::timeout(Duration::from_secs(3), async move {
            let (connection, mut handle, _) = new_connection().context("opening rtnetlink")?;
            tokio::spawn(connection);
            let links: Vec<_> = handle.link().get().execute().try_collect().await?;
            let neighbors: Vec<_> = handle
                .neighbours()
                .get()
                .set_family(IpVersion::V4)
                .execute()
                .try_collect()
                .await?;
            let mut observations = Vec::with_capacity(targets.len());
            for target in targets {
                // FIB_MATCH retains multipath/nexthop attributes that an
                // ordinary lookup can collapse to one client-specific path.
                let fib = lookup_route(&mut handle, target, true).await?;
                let fib_observation = observe_route(target, &fib, &links, &neighbors);
                if fib_observation.state != RouteObservationState::Resolved {
                    observations.push(fib_observation);
                    continue;
                }
                let route = lookup_route(&mut handle, target, false).await?;
                let mut observed = observe_route(target, &route, &links, &neighbors);
                if observed.ifindex != fib_observation.ifindex
                    || observed.next_hop != fib_observation.next_hop
                {
                    observed.state = RouteObservationState::UnsupportedRoute;
                }
                observations.push(observed);
            }
            Ok(observations)
        })
        .await
        .context("target route observation timed out")?
    })
}

async fn lookup_route(
    handle: &mut rtnetlink::Handle,
    target: Ipv4Addr,
    fib_match: bool,
) -> Result<RouteMessage> {
    let mut responses = handle.request(route_lookup_request(target, fib_match))?;
    let mut found = None;
    while let Some(response) = responses.next().await {
        match response.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
                if found.replace(route).is_some() {
                    bail!("multiple route lookup results for {target}");
                }
            }
            NetlinkPayload::Error(error) => bail!("route lookup for {target}: {}", error.to_io()),
            _ => bail!("unexpected route lookup response for {target}"),
        }
    }
    found.with_context(|| format!("no route result for {target}"))
}

pub(super) fn route_lookup_request(
    target: Ipv4Addr,
    fib_match: bool,
) -> NetlinkMessage<RouteNetlinkMessage> {
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
    route.header.destination_prefix_length = 32;
    if fib_match {
        route.header.flags = RouteFlags::FibMatch;
    }
    route
        .attributes
        .push(RouteAttribute::Destination(RouteAddress::Inet(target)));
    let mut request = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(route));
    request.header.flags = NLM_F_REQUEST;
    request
}
