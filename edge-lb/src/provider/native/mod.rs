//! Native edge-lb datapath facade.
//!
//! Native user-space datapath and proxy implementation.
//! It owns listener-to-datapath conversion and runtime state. Linux eBPF/TC
//! attachment stays in `linux`, and HTTP handlers should call this facade
//! instead of manipulating maps directly.

mod api_model;
pub mod flow_persistence;
pub mod ha;
mod model;
pub mod probe;
mod store;
pub mod xsync;

#[allow(unused_imports)]
pub use api_model::{
    HealthProbeConfig, NativeListenerSpec, NativeListenerStateEntry, NativeListenerStateList,
    NativeListenerTarget, TargetHealthEntry, TargetHealthList,
};
#[allow(unused_imports)]
pub use model::{
    NativeListener, NativeListenerKey, NativeProtocol, NativeTarget, NativeTargetState,
    effective_vip_ips, listeners_from_config,
};
#[allow(unused_imports)]
pub use probe::run_worker as run_probe_worker;
#[allow(unused_imports)]
pub use store::{
    default_external_ip, delete_listener, hydrate_proxy_config_from_api, mark_state_dirty,
    native_listeners_state, reconcile_listener_state, take_state_dirty, target_groups_native,
    target_health, target_health_native,
};
