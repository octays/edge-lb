//! Return lease map I/O. Called only under maps::CACHE_WRITER.

use anyhow::{Context, Result};
use aya::maps::{HashMap, Map, MapData};
use edge_lb_common::return_redirect::{NATIVE_RETURN_LEASES_MAP, ReturnLease, ReturnLeaseKey};
use std::path::Path;

fn path(route_pin: &Path) -> Result<std::path::PathBuf> {
    Ok(route_pin
        .parent()
        .context("cache parent missing")?
        .join(NATIVE_RETURN_LEASES_MAP))
}

pub(super) fn identity(route_pin: &Path) -> Result<Option<u32>> {
    let pin = path(route_pin)?;
    if !pin.try_exists()? {
        return Ok(None);
    }
    Ok(Some(MapData::from_pin(pin)?.info()?.id()))
}

pub(super) fn clear(route_pin: &Path) -> Result<usize> {
    let pin = path(route_pin)?;
    if !pin.try_exists()? {
        return Ok(0);
    }
    let mut map: HashMap<_, ReturnLeaseKey, ReturnLease> =
        HashMap::try_from(Map::from_map_data(MapData::from_pin(pin)?)?)?;
    let keys = map.keys().collect::<Result<Vec<_>, _>>()?;
    for key in &keys {
        map.remove(key)?;
    }
    Ok(keys.len())
}

pub(super) fn write(route_pin: &Path, desired: &[(ReturnLeaseKey, ReturnLease)]) -> Result<()> {
    if desired.is_empty() {
        return Ok(());
    }
    let mut map: HashMap<_, ReturnLeaseKey, ReturnLease> =
        HashMap::try_from(Map::from_map_data(MapData::from_pin(path(route_pin)?)?)?)?;
    for (key, value) in desired {
        map.insert(*key, *value, 0)?;
    }
    Ok(())
}
