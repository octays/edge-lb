//! Pure construction of bounded source/interface admission leases.

use super::{model::ReturnContext, planner::LEASE_NS};
use anyhow::{Result, ensure};
use edge_lb_common::return_redirect::{NATIVE_RETURN_LEASES_CAPACITY, ReturnLease, ReturnLeaseKey};

pub(super) fn plan(
    context: &ReturnContext,
    started: u64,
) -> Result<Vec<(ReturnLeaseKey, ReturnLease)>> {
    ensure!(
        started != 0 && context.ingress != 0,
        "invalid return lease context"
    );
    let expires_ns = started
        .checked_add(LEASE_NS)
        .ok_or_else(|| anyhow::anyhow!("return lease overflow"))?;
    ensure!(
        context
            .sources
            .len()
            .checked_mul(context.outputs.len())
            .is_some_and(|n| n <= NATIVE_RETURN_LEASES_CAPACITY as usize),
        "return lease capacity exceeded"
    );
    let mut desired = Vec::new();
    for &ifindex in &context.outputs {
        ensure!(
            ifindex != 0 && ifindex != context.ingress,
            "invalid return output"
        );
        for &source in &context.sources {
            desired.push((
                ReturnLeaseKey {
                    ingress_ifindex: context.ingress,
                    ifindex,
                    source,
                },
                ReturnLease { expires_ns },
            ));
        }
    }
    Ok(desired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn context() -> ReturnContext {
        ReturnContext {
            ingress: 7,
            outputs: BTreeSet::from([2, 3]),
            sources: vec![0xc0000201, 0xc0000202],
        }
    }

    #[test]
    fn leases_bind_source_and_both_interfaces_without_target_health() {
        let desired = plan(&context(), 100).unwrap();
        assert_eq!(desired.len(), 4);
        for (key, lease) in desired {
            assert_eq!(key.ingress_ifindex, 7);
            assert!([2, 3].contains(&key.ifindex));
            assert!([0xc0000201, 0xc0000202].contains(&key.source));
            assert_eq!(lease.expires_ns, 100 + LEASE_NS);
        }
    }

    #[test]
    fn invalid_context_and_capacity_do_not_publish_partial_policy() {
        assert!(plan(&context(), 0).is_err());
        assert!(plan(&context(), u64::MAX).is_err());
        let mut context = context();
        context.outputs.insert(context.ingress);
        assert!(plan(&context, 1).is_err());
        context.outputs = BTreeSet::from([2]);
        context.sources = vec![1; NATIVE_RETURN_LEASES_CAPACITY as usize + 1];
        assert!(plan(&context, 1).is_err());
        context.sources.clear();
        assert!(plan(&context, 1).unwrap().is_empty());
    }
}
