//! Read-only per-CPU counters; never walk the flow or route cache on scrape.

use std::path::Path;

use anyhow::{Context, Result};
use aya::maps::{Map, MapData, PerCpuArray};
use edge_lb_common::redirect::NativeRedirectStats;
use edge_lb_common::return_redirect::ReturnRedirectStats;

pub fn return_stats(pin: &Path) -> Result<ReturnRedirectStats> {
    let data = MapData::from_pin(pin).context("opening return redirect stats")?;
    let counters: PerCpuArray<MapData, ReturnRedirectStats> =
        Map::from_map_data(data)?.try_into()?;
    Ok(sum_return(counters.get(&0, 0)?.iter()))
}

fn sum_return<'a>(
    values: impl IntoIterator<Item = &'a ReturnRedirectStats>,
) -> ReturnRedirectStats {
    values
        .into_iter()
        .fold(ReturnRedirectStats::default(), |mut total, value| {
            total.submitted = total.submitted.saturating_add(value.submitted);
            total.policy = total.policy.saturating_add(value.policy);
            total.expired = total.expired.saturating_add(value.expired);
            total.route = total.route.saturating_add(value.route);
            total.neighbor = total.neighbor.saturating_add(value.neighbor);
            total.ttl = total.ttl.saturating_add(value.ttl);
            total.mtu = total.mtu.saturating_add(value.mtu);
            total.unsupported = total.unsupported.saturating_add(value.unsupported);
            total.mutation_error = total.mutation_error.saturating_add(value.mutation_error);
            total
        })
}

pub fn stats(pin: &Path) -> Result<NativeRedirectStats> {
    let data = MapData::from_pin(pin).context("opening redirect stats map")?;
    let counters: PerCpuArray<MapData, NativeRedirectStats> =
        Map::from_map_data(data)?.try_into()?;
    Ok(sum(counters.get(&0, 0)?.iter()))
}

fn sum<'a>(values: impl IntoIterator<Item = &'a NativeRedirectStats>) -> NativeRedirectStats {
    values
        .into_iter()
        .fold(NativeRedirectStats::default(), |mut total, value| {
            total.submitted = total.submitted.saturating_add(value.submitted);
            total.route_miss = total.route_miss.saturating_add(value.route_miss);
            total.route_invalid = total.route_invalid.saturating_add(value.route_invalid);
            total.expired = total.expired.saturating_add(value.expired);
            total.target_changed = total.target_changed.saturating_add(value.target_changed);
            total.ttl = total.ttl.saturating_add(value.ttl);
            total.mtu = total.mtu.saturating_add(value.mtu);
            total.unsupported = total.unsupported.saturating_add(value.unsupported);
            total.mutation_error = total.mutation_error.saturating_add(value.mutation_error);
            total
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_counters_sum_saturates_without_scanning_leases() {
        let value = ReturnRedirectStats {
            submitted: u64::MAX,
            policy: 1,
            expired: 2,
            route: 3,
            neighbor: 4,
            ttl: 5,
            mtu: 6,
            unsupported: 7,
            mutation_error: 8,
        };
        assert_eq!(
            sum_return([&value, &value]),
            ReturnRedirectStats {
                submitted: u64::MAX,
                policy: 2,
                expired: 4,
                route: 6,
                neighbor: 8,
                ttl: 10,
                mtu: 12,
                unsupported: 14,
                mutation_error: 16
            }
        );
        assert_eq!(sum_return([]), ReturnRedirectStats::default());
    }

    #[test]
    fn all_per_cpu_counters_are_summed_without_wrapping() {
        let value = NativeRedirectStats {
            submitted: u64::MAX,
            route_miss: 2,
            route_invalid: 3,
            expired: 4,
            target_changed: 5,
            ttl: 6,
            mtu: 7,
            unsupported: 8,
            mutation_error: 9,
        };
        let total = sum([&value, &value]);
        assert_eq!(
            total,
            NativeRedirectStats {
                submitted: u64::MAX,
                route_miss: 4,
                route_invalid: 6,
                expired: 8,
                target_changed: 10,
                ttl: 12,
                mtu: 14,
                unsupported: 16,
                mutation_error: 18,
            }
        );
        assert_eq!(sum([]), NativeRedirectStats::default());
    }
}
