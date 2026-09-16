//! Native redirect observation, conservative admission and guarded publication.
//!
//! A destination lookup is not permission to bypass forwarding policy. These
//! observations authorize a cache lease only after host and TC admission.
//! Observers never mutate maps; reconciliation owns publication and invalidation.

mod admission;
mod events;
mod kernel_policy;
mod maps;
mod model;
mod netlink;
mod planner;
mod policy;
mod reconcile;
mod resolve;
mod return_admission;
mod return_maps;
mod return_planner;
mod stats;
mod worker;

pub use kernel_policy::observe_kernel_policy;
pub use maps::begin_mutation;
#[cfg(test)]
pub use maps::invalidate_routes;
pub use model::TargetRouteObservation;
pub use netlink::{observe_routing_policy, observe_target_routes};
pub use reconcile::RedirectContext;
pub use stats::{return_stats, stats};
pub use worker::spawn;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod kernel_tests;

#[cfg(test)]
mod packet_test_support;

#[cfg(test)]
mod return_kernel_tests;

#[cfg(test)]
mod return_publication_tests;

#[cfg(test)]
mod kernel_topology_tests;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod kernel_network_tests;
