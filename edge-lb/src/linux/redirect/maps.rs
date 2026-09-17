//! Mutations of the owned redirect cache, independent of route observation.

use std::{
    borrow::BorrowMut,
    path::Path,
    sync::{Mutex, MutexGuard},
};

use anyhow::{Context, Result};
use aya::maps::{HashMap, Map, MapData};
use edge_lb_common::{
    NATIVE_LISTENERS_MAP, NATIVE_TARGETS_MAP, NativeListenerLookupKey, NativeListenerLookupValue,
    NativeTargetKey, NativeTargetValue,
    redirect::{NATIVE_LOCAL_ADDRS_MAP, NativeTargetRoute},
};

use super::planner::TargetCandidate;
use super::return_maps;
use edge_lb_common::return_redirect::{ReturnLease, ReturnLeaseKey};

// Business mutations, invalidators and publication share one ownership lock;
// no packet-path lock is involved.
static CACHE_WRITER: Mutex<u64> = Mutex::new(0);

/// Held across business map updates as well as cache publication.
pub struct MutationGuard {
    _writer: MutexGuard<'static, u64>,
}

pub fn begin_mutation(pin: &Path) -> Result<MutationGuard> {
    let mut writer = CACHE_WRITER
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *writer = writer
        .checked_add(1)
        .context("redirect revision exhausted")?;
    clear_pinned(pin)?;
    Ok(MutationGuard { _writer: writer })
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SnapshotToken {
    revision: u64,
    map_id: u32,
    return_map_id: Option<u32>,
}

pub(super) fn snapshot(pin: &Path) -> Result<(SnapshotToken, Vec<TargetCandidate>)> {
    let writer = CACHE_WRITER
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let map_id = MapData::from_pin(pin)?.info()?.id();
    let token = SnapshotToken {
        revision: *writer,
        map_id,
        return_map_id: return_maps::identity(pin)?,
    };
    let parent = pin.parent().context("route cache has no parent")?;
    let listeners: HashMap<_, NativeListenerLookupKey, NativeListenerLookupValue> =
        HashMap::try_from(Map::from_map_data(MapData::from_pin(
            parent.join(NATIVE_LISTENERS_MAP),
        )?)?)?;
    let targets: HashMap<_, NativeTargetKey, NativeTargetValue> = HashMap::try_from(
        Map::from_map_data(MapData::from_pin(parent.join(NATIVE_TARGETS_MAP))?)?,
    )?;
    let mut dscps = std::collections::HashMap::new();
    for entry in listeners.iter() {
        let (_, listener) = entry?;
        if let Some(previous) = dscps.insert(listener.listener_id, listener.dscp) {
            anyhow::ensure!(
                previous == listener.dscp,
                "listener ID has conflicting DSCP values"
            );
        }
    }
    let mut candidates = Vec::new();
    for entry in targets.iter() {
        let (key, target) = entry?;
        if target.flags & 1 != 0
            && target.weight > 0
            && let Some(dscp) = dscps.get(&key.listener_id)
        {
            candidates.push(TargetCandidate {
                key,
                target: target.address.into(),
                port: target.port,
                dscp: u8::try_from(*dscp)?,
            });
        }
    }
    Ok((token, candidates))
}

/// Returns false when observation raced with invalidation or map replacement.
/// Only the reconciler may call this after complete packet-path admission.
#[cfg(test)]
pub(super) fn publish_routes(
    pin: &Path,
    token: SnapshotToken,
    desired: &[(NativeTargetKey, NativeTargetRoute)],
    local_addresses: &[u32],
    now_ns: u64,
) -> Result<bool> {
    publish(pin, token, desired, &[], local_addresses, now_ns)
}

pub(super) fn publish(
    pin: &Path,
    token: SnapshotToken,
    desired: &[(NativeTargetKey, NativeTargetRoute)],
    returns: &[(ReturnLeaseKey, ReturnLease)],
    local_addresses: &[u32],
    now_ns: u64,
) -> Result<bool> {
    let mut writer = CACHE_WRITER
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if *writer != token.revision {
        return Ok(false);
    }
    let data = MapData::from_pin(pin).context("opening route cache for publication")?;
    if data.info()?.id() != token.map_id || return_maps::identity(pin)? != token.return_map_id {
        return Ok(false);
    }
    let mut routes = HashMap::try_from(Map::from_map_data(data)?)?;
    if desired.iter().any(|(_, route)| route.expires_ns <= now_ns)
        || returns.iter().any(|(_, lease)| lease.expires_ns <= now_ns)
    {
        *writer = writer
            .checked_add(1)
            .context("redirect revision exhausted")?;
        clear_pinned(pin)?;
        return Ok(false);
    }
    let result = (|| -> Result<()> {
        return_maps::clear(pin)?;
        clear_routes(&mut routes)?;
        let local_pin = pin
            .parent()
            .context("route cache has no parent")?
            .join(NATIVE_LOCAL_ADDRS_MAP);
        let mut locals: HashMap<_, u32, u32> =
            HashMap::try_from(Map::from_map_data(MapData::from_pin(local_pin)?)?)?;
        // Keep former local addresses until object replacement. Deleting them
        // could race with a packet already holding an old route; retention
        // only causes conservative fallback. Capacity exhaustion fails closed.
        for address in local_addresses {
            locals.insert(*address, 1, 0)?;
        }
        for (key, value) in desired {
            routes
                .insert(*key, *value, 0)
                .context("publishing redirect route")?;
        }
        return_maps::write(pin, returns)?;
        Ok(())
    })();
    if let Err(error) = result {
        *writer = writer
            .checked_add(1)
            .context("redirect revision exhausted")?;
        clear_pinned(pin).context(format!("{error:#}; clearing partially published routes"))?;
        return Err(error);
    }
    *writer = writer
        .checked_add(1)
        .context("redirect revision exhausted")?;
    Ok(true)
}

pub fn invalidate_routes(pin: &Path) -> Result<usize> {
    let mut writer = CACHE_WRITER
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *writer = writer
        .checked_add(1)
        .context("redirect revision exhausted")?;
    clear_pinned(pin)
}

fn clear_pinned(pin: &Path) -> Result<usize> {
    // Attempt both even if one ABI/read fails; never leave the other direction trusted.
    let returns = return_maps::clear(pin);
    let routes = clear_forward(pin);
    Ok(returns? + routes?)
}

fn clear_forward(pin: &Path) -> Result<usize> {
    if !pin.try_exists().context("checking redirect route pin")? {
        return Ok(0);
    }
    let data = MapData::from_pin(pin).context("opening redirect route cache")?;
    let map = Map::from_map_data(data).context("reading redirect route map type")?;
    let mut routes = HashMap::try_from(map).context("redirect route ABI mismatch")?;
    clear_routes(&mut routes)
}

pub(super) fn clear_routes<T: BorrowMut<MapData>>(
    routes: &mut HashMap<T, NativeTargetKey, NativeTargetRoute>,
) -> Result<usize> {
    // Collect before deleting: deleting the iterator's previous key can
    // restart BPF_MAP_GET_NEXT_KEY and yield duplicate entries.
    let keys = routes
        .keys()
        .collect::<Result<Vec<_>, _>>()
        .context("enumerating redirect route cache")?;
    for key in &keys {
        routes
            .remove(key)
            .context("invalidating redirect route cache")?;
    }
    Ok(keys.len())
}
