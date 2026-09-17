//! Compose observation, admission and guarded cache publication.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};

use super::{admission, events::RouteEvents, maps, netlink, planner};
use super::{return_admission, return_planner};
use edge_lb_common::return_redirect::NATIVE_RETURN_LEASES_MAP;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectContext {
    pub route_pin: PathBuf,
    pub marker_pin: PathBuf,
    pub ingress_device: String,
    pub return_device: String,
    pub marker_priority: u16,
}

pub(super) fn refresh(context: &RedirectContext, events: &RouteEvents) -> Result<bool> {
    if !context.route_pin.try_exists()? {
        return Ok(false);
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
        return Ok(false);
    }
    ensure!(
        monotonic_ns()? < started.saturating_add(planner::LEASE_NS),
        "route observation exceeded lease"
    );
    maps::publish(
        &context.route_pin,
        token,
        &desired,
        &returns,
        &locals,
        monotonic_ns()?,
    )?;
    Ok(true)
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
