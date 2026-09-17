//! Pure construction of short-lived route entries from admitted observations.

use std::{collections::BTreeMap, net::Ipv4Addr};

use anyhow::{Result, ensure};
use edge_lb_common::{
    NativeTargetKey,
    redirect::{NATIVE_TARGET_ROUTES_CAPACITY, NativeTargetRoute},
};

use super::{TargetRouteObservation, model::RouteObservationState};

pub(super) const LEASE_NS: u64 = 2_000_000_000;

#[derive(Clone, Copy)]
pub(super) struct TargetCandidate {
    pub key: NativeTargetKey,
    pub target: Ipv4Addr,
    pub port: u16,
    pub dscp: u8,
}

pub(super) fn plan(
    targets: &[TargetCandidate],
    observations: &[TargetRouteObservation],
    ingress_ifindex: u32,
    started_ns: u64,
) -> Result<Vec<(NativeTargetKey, NativeTargetRoute)>> {
    ensure!(ingress_ifindex != 0, "missing ingress interface");
    let by_address: BTreeMap<_, _> = observations
        .iter()
        .map(|route| (route.target, route))
        .collect();
    let expires_ns = started_ns
        .checked_add(LEASE_NS)
        .ok_or_else(|| anyhow::anyhow!("route lease overflow"))?;
    let mut desired = Vec::new();
    for target in targets {
        let Some(route) = by_address.get(&target.target) else {
            continue;
        };
        if route.state != RouteObservationState::Resolved
            || !route.neighbor_confirmed
            || target.dscp > 63
        {
            continue;
        }
        let (Some(ifindex), Some(mtu), Some(source_mac), Some(destination_mac)) = (
            route.ifindex,
            route.mtu,
            route.source_mac,
            route.destination_mac,
        ) else {
            continue;
        };
        desired.push((
            target.key,
            NativeTargetRoute {
                expires_ns,
                target: target.target.into(),
                target_port: target.port,
                ingress_ifindex,
                ifindex,
                mtu,
                dscp: target.dscp,
                _pad: 0,
                source_mac,
                destination_mac,
            },
        ));
    }
    ensure!(
        desired.len() <= NATIVE_TARGET_ROUTES_CAPACITY as usize,
        "redirect cache capacity exceeded"
    );
    Ok(desired)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (TargetCandidate, TargetRouteObservation) {
        let target = TargetCandidate {
            key: NativeTargetKey {
                listener_id: 1,
                target_id: 2,
            },
            target: "192.0.2.20".parse().unwrap(),
            port: 8080,
            dscp: 46,
        };
        let route = TargetRouteObservation {
            target: target.target,
            state: RouteObservationState::Resolved,
            ifindex: Some(7),
            device: Some("edge-hub".into()),
            mtu: Some(1450),
            next_hop: Some("192.0.2.1".parse().unwrap()),
            source_mac: Some([2, 0, 0, 0, 0, 1]),
            destination_mac: Some([2, 0, 0, 0, 0, 2]),
            neighbor_confirmed: true,
        };
        (target, route)
    }

    #[test]
    fn lease_starts_at_observation_and_keeps_actual_target_binding() {
        let (target, route) = fixture();
        let desired = plan(&[target], &[route], 3, 100).unwrap();
        assert_eq!(desired[0].0, target.key);
        assert_eq!(desired[0].1.expires_ns, 100 + LEASE_NS);
        assert_eq!(desired[0].1.target, u32::from(target.target));
        assert_eq!(desired[0].1.target_port, 8080);
        assert_eq!(desired[0].1.ifindex, 7);
    }

    #[test]
    fn stale_neighbors_and_incomplete_observations_are_not_renewed() {
        let (target, route) = fixture();
        for change in 0..4 {
            let mut route = route.clone();
            match change {
                0 => route.neighbor_confirmed = false,
                1 => route.state = RouteObservationState::MissingNeighbor,
                2 => route.destination_mac = None,
                _ => route.target = "192.0.2.21".parse().unwrap(),
            }
            assert!(plan(&[target], &[route], 3, 100).unwrap().is_empty());
        }
        assert!(plan(&[target], &[], 3, 100).unwrap().is_empty());
    }

    #[test]
    fn capacity_and_invalid_epoch_fail_closed() {
        let (target, route) = fixture();
        assert!(plan(&[target], &[route.clone()], 0, 100).is_err());
        assert!(plan(&[target], &[route.clone()], 3, u64::MAX).is_err());
        assert!(
            plan(
                &vec![target; NATIVE_TARGET_ROUTES_CAPACITY as usize + 1],
                &[route],
                3,
                100
            )
            .is_err()
        );
    }
}
