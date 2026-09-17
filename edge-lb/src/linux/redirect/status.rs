//! Bounded userspace status for redirect admission and publication.

use std::{
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectAdmissionStatus {
    pub state: &'static str,
    pub reason: &'static str,
    pub map_digest: u64,
    pub updated_unix_seconds: u64,
}

impl Default for RedirectAdmissionStatus {
    fn default() -> Self {
        Self {
            state: "unknown",
            reason: "startup",
            map_digest: 0,
            updated_unix_seconds: 0,
        }
    }
}

static STATUS: OnceLock<Mutex<RedirectAdmissionStatus>> = OnceLock::new();

pub fn current() -> RedirectAdmissionStatus {
    status()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

pub(super) fn record_published(map_digest: u64) {
    record("published", "none", Some(map_digest));
}

pub(super) fn record_blocked(error: &str) {
    record("blocked", classify_error(error), None);
}

fn record(state: &'static str, reason: &'static str, map_digest: Option<u64>) {
    let mut status = status()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous_digest = status.map_digest;
    *status = RedirectAdmissionStatus {
        state,
        reason,
        map_digest: map_digest.unwrap_or(previous_digest),
        updated_unix_seconds: now_unix_seconds(),
    };
}

fn status() -> &'static Mutex<RedirectAdmissionStatus> {
    STATUS.get_or_init(|| Mutex::new(RedirectAdmissionStatus::default()))
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn classify_error(error: &str) -> &'static str {
    let error = error.to_ascii_lowercase();
    if error.contains("rp_filter") {
        "rp_filter"
    } else if error.contains("forwarding") {
        "forwarding"
    } else if error.contains("nonstandard routing") || error.contains("fib") {
        "routing_policy"
    } else if error.contains("netfilter")
        || error.contains("xfrm")
        || error.contains("security module")
        || error.contains("lsm")
    {
        "kernel_policy"
    } else if error.contains("tc") || error.contains("tcx") {
        "tc"
    } else if error.contains("lease") {
        "lease"
    } else if error.contains("neighbor") {
        "neighbor"
    } else if error.contains("route") {
        "route"
    } else if error.contains("cache") || error.contains("map") {
        "cache"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_errors_are_bounded_reasons() {
        assert_eq!(
            classify_error("rp_filter requires kernel path"),
            "rp_filter"
        );
        assert_eq!(
            classify_error("nonstandard routing rules"),
            "routing_policy"
        );
        assert_eq!(
            classify_error("netfilter/XFRM policy present"),
            "kernel_policy"
        );
        assert_eq!(classify_error("route observation exceeded lease"), "lease");
        assert_eq!(classify_error("unexpected TC priority"), "tc");
        assert_eq!(classify_error("something surprising"), "other");
    }
}
