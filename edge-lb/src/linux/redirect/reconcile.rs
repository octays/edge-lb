//! Compose observation, admission and guarded cache publication.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};

use super::{admission, events::RouteEvents, maps, netlink, planner};
use super::{return_admission, return_planner};
use edge_lb_common::{
    NativeTargetKey,
    redirect::NativeTargetRoute,
    return_redirect::{NATIVE_RETURN_LEASES_MAP, ReturnLease, ReturnLeaseKey},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectContext {
    pub route_pin: PathBuf,
    pub marker_pin: PathBuf,
    pub ingress_device: String,
    pub return_device: String,
    pub marker_priority: u16,
}

pub(super) fn refresh(context: &RedirectContext, events: &RouteEvents) -> Result<Option<u64>> {
    if !context.route_pin.try_exists()? {
        return Ok(None);
    }
    let started = monotonic_ns()?;
    let (token, targets) = maps::snapshot(&context.route_pin)?;
    admission::check_host(&context.ingress_device)?;
    let ingress = crate::linux::net::ifindex(&context.ingress_device)?;
    let addresses: Vec<_> = targets.iter().map(|target| target.target).collect();
    let routes = netlink::observe_target_routes(&addresses)?;
    let locals = netlink::local_addresses()?;
    let desired = planner::plan(&targets, &routes, ingress, started)?;
    let outputs: BTreeSet<_> = desired.iter().map(|(_, route)| route.ifindex).collect();
    admission::check_tc(
        ingress,
        &outputs,
        context.marker_priority,
        &context.route_pin,
        &context.marker_pin,
    )?;
    let return_context = return_admission::observe(&context.return_device)?;
    let returns = return_planner::plan(&return_context, started)?;
    admission::check_return_tc(
        return_context.ingress,
        &return_context.outputs,
        context
            .marker_priority
            .checked_add(11)
            .context("return priority overflow")?,
        &context
            .route_pin
            .parent()
            .context("cache parent missing")?
            .join(NATIVE_RETURN_LEASES_MAP),
    )?;
    // Notifications queued during a slow observation invalidate its token.
    if events.pending()? {
        maps::invalidate_routes(&context.route_pin)?;
        return Ok(None);
    }
    ensure!(
        monotonic_ns()? < started.saturating_add(planner::LEASE_NS),
        "route observation exceeded lease"
    );
    let digest = publication_digest(&desired, &returns, &locals);
    if maps::publish(
        &context.route_pin,
        token,
        &desired,
        &returns,
        &locals,
        monotonic_ns()?,
    )? {
        Ok(Some(digest))
    } else {
        Ok(None)
    }
}

pub(super) fn monotonic_ns() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time is valid writable timespec storage.
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } == 0,
        "reading monotonic time"
    );
    u64::try_from(time.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|secs| secs.checked_add(time.tv_nsec as u64))
        .context("monotonic clock overflow")
}

pub(super) fn invalidate(pin: &Path) -> Result<()> {
    maps::invalidate_routes(pin).map(|_| ())
}

fn publication_digest(
    desired: &[(NativeTargetKey, NativeTargetRoute)],
    returns: &[(ReturnLeaseKey, ReturnLease)],
    local_addresses: &[u32],
) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325u64;
    fn mix(state: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *state ^= u64::from(*byte);
            *state = state.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    fn mix_u8(state: &mut u64, value: u8) {
        mix(state, &[value]);
    }
    fn mix_u16(state: &mut u64, value: u16) {
        mix(state, &value.to_le_bytes());
    }
    fn mix_u32(state: &mut u64, value: u32) {
        mix(state, &value.to_le_bytes());
    }
    fn mix_len(state: &mut u64, value: usize) {
        mix(state, &(value as u64).to_le_bytes());
    }

    let mut routes = desired.iter().collect::<Vec<_>>();
    routes.sort_by_key(|(key, route)| {
        (
            key.listener_id,
            key.target_id,
            route.target,
            route.target_port,
            route.ingress_ifindex,
            route.ifindex,
        )
    });
    mix_u8(&mut state, b'R');
    mix_len(&mut state, routes.len());
    for (key, route) in routes {
        mix_u32(&mut state, key.listener_id);
        mix_u32(&mut state, key.target_id);
        mix_u32(&mut state, route.target);
        mix_u32(&mut state, route.ingress_ifindex);
        mix_u32(&mut state, route.ifindex);
        mix_u32(&mut state, route.mtu);
        mix_u16(&mut state, route.target_port);
        mix_u8(&mut state, route.dscp);
        mix(&mut state, &route.source_mac);
        mix(&mut state, &route.destination_mac);
    }

    let mut leases = returns.iter().collect::<Vec<_>>();
    leases.sort_by_key(|(key, _)| (key.ingress_ifindex, key.ifindex, key.source));
    mix_u8(&mut state, b'L');
    mix_len(&mut state, leases.len());
    for (key, _) in leases {
        mix_u32(&mut state, key.ingress_ifindex);
        mix_u32(&mut state, key.ifindex);
        mix_u32(&mut state, key.source);
    }

    let mut locals = local_addresses.to_vec();
    locals.sort_unstable();
    mix_u8(&mut state, b'A');
    mix_len(&mut state, locals.len());
    for address in locals {
        mix_u32(&mut state, address);
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(
        listener_id: u32,
        target_id: u32,
        expires_ns: u64,
    ) -> (NativeTargetKey, NativeTargetRoute) {
        (
            NativeTargetKey {
                listener_id,
                target_id,
            },
            NativeTargetRoute {
                expires_ns,
                target: 0xc000_020a + target_id,
                ingress_ifindex: 2,
                ifindex: 7,
                mtu: 1450,
                target_port: 8080,
                dscp: 46,
                source_mac: [2, 0, 0, 0, 0, 1],
                destination_mac: [2, 0, 0, 0, 0, 2],
                _pad: 0,
            },
        )
    }

    fn lease(source: u32, expires_ns: u64) -> (ReturnLeaseKey, ReturnLease) {
        (
            ReturnLeaseKey {
                ingress_ifindex: 9,
                ifindex: 10,
                source,
            },
            ReturnLease { expires_ns },
        )
    }

    #[test]
    fn publication_digest_is_order_stable_and_ignores_lease_deadlines() {
        let left_routes = [route(1, 0, 100), route(1, 1, 100)];
        let right_routes = [route(1, 1, 200), route(1, 0, 200)];
        let left_leases = [lease(0xc000_020a, 100), lease(0xc000_020b, 100)];
        let right_leases = [lease(0xc000_020b, 200), lease(0xc000_020a, 200)];
        assert_eq!(
            publication_digest(&left_routes, &left_leases, &[3, 1, 2]),
            publication_digest(&right_routes, &right_leases, &[2, 3, 1])
        );
    }

    #[test]
    fn publication_digest_changes_when_effective_route_changes() {
        let routes = [route(1, 0, 100)];
        let leases = [lease(0xc000_020a, 100)];
        let baseline = publication_digest(&routes, &leases, &[1]);
        let mut changed = routes;
        changed[0].1.ifindex += 1;
        assert_ne!(baseline, publication_digest(&changed, &leases, &[1]));
        assert_ne!(baseline, publication_digest(&routes, &leases, &[1, 2]));
    }
}
