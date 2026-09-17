use anyhow::{Context, Result, bail};

use crate::config::{Config, Listener, Protocol, TargetGroup};

use super::api_model::{
    HealthProbeConfig, NativeListenerSpec, NativeListenerStateEntry, NativeListenerStateList,
    NativeListenerTarget, TargetHealthEntry, TargetHealthList,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct NativeProxyState {
    #[serde(default)]
    listeners: Vec<NativeListenerStateEntry>,
    #[serde(default)]
    target_health: Vec<TargetHealthEntry>,
}

/// The probe worker and API handlers mutate the same state file from
/// different threads; every read-modify-write takes this lock.
static STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set whenever desired proxy state or target health changes on disk.
/// The gateway run loop consumes it to refresh the native datapath maps —
/// without this, CRUD only reached the kernel when some unrelated trigger
/// (boot, config reload, subscription churn) happened to fire.
static PROXY_STATE_DIRTY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn mark_state_dirty() {
    PROXY_STATE_DIRTY.store(true, std::sync::atomic::Ordering::Release);
}

/// One-shot: true when proxy state changed since the last check.
pub fn take_state_dirty() -> bool {
    PROXY_STATE_DIRTY.swap(false, std::sync::atomic::Ordering::AcqRel)
}

/// Mutate observed target health records under the state lock. Desired listener
/// configuration is untouched; this is the probe worker's write path.
pub fn mutate_target_health<F>(cfg: &Config, mutate: F) -> Result<()>
where
    F: FnOnce(&mut Vec<TargetHealthEntry>),
{
    let _guard = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut state = load_state(cfg)?;
    let previous = state.target_health.clone();
    mutate(&mut state.target_health);
    if previous == state.target_health {
        return Ok(());
    }
    save_state(cfg, &state)
}

fn with_state_lock<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    let _guard = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

pub fn native_listeners_state(cfg: &Config) -> Result<NativeListenerStateList> {
    let mut entries = Vec::new();
    for entry in load_state(cfg)?.listeners {
        if let Some(existing) =
            entries
                .iter_mut()
                .find(|existing: &&mut NativeListenerStateEntry| {
                    same_listener_identity(existing, &entry)
                })
        {
            for ip in &entry.spec.vip_ips {
                if !existing.spec.vip_ips.contains(ip) {
                    existing.spec.vip_ips.push(ip.clone());
                }
            }
            merge_protocols(existing, &entry);
        } else {
            entries.push(entry);
        }
    }
    Ok(NativeListenerStateList { listeners: entries })
}

pub fn target_health_native(cfg: &Config) -> Result<TargetHealthList> {
    Ok(TargetHealthList {
        entries: load_state(cfg)?.target_health,
    })
}

pub fn target_health(cfg: &Config) -> Result<Vec<TargetHealthEntry>> {
    Ok(load_state(cfg)?.target_health)
}

pub fn target_groups_native(cfg: &Config) -> Result<Vec<TargetGroup>> {
    Ok(crate::storage::proxy_config::load(cfg)?.target_groups)
}

/// Refresh the disposable projection as a whole. It never writes canonical
/// documents or re-arms the dirty flag that caused this reconciliation.
pub fn reconcile_listener_state(cfg: &Config) -> Result<()> {
    with_state_lock(|| {
        let mut state = load_state(cfg)?;
        rebuild_listener_state(cfg, &mut state)?;
        save_state_if_changed(cfg, &mut state)?;
        Ok(())
    })
}

fn rebuild_listener_state(cfg: &Config, state: &mut NativeProxyState) -> Result<()> {
    let mut entries = Vec::new();
    for listener in &cfg.listeners {
        let group = cfg
            .target_groups
            .iter()
            .find(|group| group.name == listener.target_group)
            .with_context(|| format!("target group {} not found", listener.target_group))?;
        for mut entry in listener_entries(cfg, listener, group)? {
            entry.spec.vip_ips =
                crate::provider::native::effective_vip_ips(cfg, &listener.vip_ips)?
                    .into_iter()
                    .map(|ip| ip.to_string())
                    .collect();
            normalize_entry(&mut entry);
            if let Some(probe) = target_group_probe(group).filter(HealthProbeConfig::enabled) {
                ensure_probe_health_records(state, &entry, &probe);
            } else {
                ensure_default_health_records(state, &entry);
            }
            entries.push(entry);
        }
    }
    let mut desired = std::collections::HashSet::new();
    for entry in &entries {
        for protocol in listener_protocols(entry) {
            for target in &entry.targets {
                desired.insert(target_health_key(
                    &entry.target_group,
                    &target.address,
                    &protocol,
                    target.target_port,
                ));
            }
        }
    }
    state
        .target_health
        .retain(|health| desired.contains(&health.name));
    state.listeners = entries;
    Ok(())
}

fn expanded_native_listener_entries(
    cfg: &Config,
    entry: &NativeListenerStateEntry,
) -> Vec<NativeListenerStateEntry> {
    let ips = if entry.spec.vip_ips.is_empty() {
        default_external_ips(cfg)
    } else {
        entry
            .spec
            .vip_ips
            .iter()
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty())
            .collect()
    };
    let protocols = if entry.protocols.is_empty() {
        vec![entry.spec.protocol.clone()]
    } else {
        entry.protocols.clone()
    };
    ips.into_iter()
        .flat_map(|ip| {
            protocols.iter().map(move |protocol| {
                let mut next = entry.clone();
                next.spec.vip_ips = vec![ip.clone()];
                next.spec.protocol = protocol.clone();
                next.protocols = vec![protocol.clone()];
                next
            })
        })
        .collect()
}

pub fn delete_listener(cfg: &Config, name: &str) -> Result<bool> {
    with_state_lock(|| {
        let mut state = load_state(cfg)?;
        let before = state.listeners.len();
        state.listeners.retain(|lb| listener_name(lb) != name);
        let changed = before != state.listeners.len();
        if changed {
            save_state(cfg, &state)?;
            mark_state_dirty();
        }
        Ok(changed)
    })
}

pub fn hydrate_proxy_config_from_api(cfg: &mut Config) -> Result<()> {
    crate::storage::proxy_config::hydrate(cfg)
}

pub fn default_external_ip(cfg: &Config) -> String {
    default_external_ips(cfg)
        .into_iter()
        .next()
        .unwrap_or_else(|| cfg.network().gateway_ip.to_string())
}

fn default_external_ips(cfg: &Config) -> Vec<String> {
    crate::provider::native::effective_vip_ips(cfg, &[])
        .map(|values| values.into_iter().map(|value| value.to_string()).collect())
        .unwrap_or_else(|_| vec![cfg.network().gateway_ip.to_string()])
}

fn listener_entries(
    cfg: &Config,
    listener: &Listener,
    group: &TargetGroup,
) -> Result<Vec<NativeListenerStateEntry>> {
    if listener.target_port == 0 {
        bail!(
            "listener {} target_port must be in range 1..=65535",
            listener.name
        );
    }
    let targets = group
        .targets
        .iter()
        .map(|target| NativeListenerTarget {
            address: cfg.resolve_backend_target_address(target).to_string(),
            // Target groups own backend membership and health probing. The
            // listener owns the forwarding port, so a backend target
            // may legitimately have no port of its own.
            target_port: listener.target_port,
            weight: target.weight,
            state: Some("active".to_string()),
            counter: Some("0:0".to_string()),
        })
        .collect::<Vec<_>>();
    // A target group may be empty while automation is waiting for a matching
    // backend. Keep the listener configuration valid; the native datapath
    // will install no forwarding entry until a target is available.
    let protocol = listener
        .protocols
        .first()
        .copied()
        .context("listener must select at least one protocol")?;
    let mut args = spec(
        &listener.name,
        listener.port,
        protocol,
        listener.select.code(),
        listener.mode.code(),
        group.monitor,
        listener.inactive_timeout.unwrap_or(240),
    );
    args.probetype = group.probe_type.clone();
    args.probeport = group.probe_port;
    args.probereq = group.probe_req.clone();
    args.proberesp = group.probe_resp.clone();
    args.probe_timeout = group.period_secs;
    args.probe_retries = group.retries;
    Ok(vec![NativeListenerStateEntry {
        target_group: group.name.clone(),
        spec: args,
        protocols: listener
            .protocols
            .iter()
            .map(|protocol| protocol.as_str().to_string())
            .collect(),
        targets,
    }])
}

fn spec(
    name: &str,
    port: u16,
    protocol: Protocol,
    select: u32,
    mode: u32,
    monitor: bool,
    inactive_timeout: u32,
) -> NativeListenerSpec {
    NativeListenerSpec {
        vip_ips: Vec::new(),
        port,
        protocol: protocol.as_str().to_string(),
        sel: select,
        mode,
        monitor,
        inactive_timeout,
        name: Some(name.to_string()),
        ..NativeListenerSpec::default()
    }
}

fn target_group_probe(group: &TargetGroup) -> Option<HealthProbeConfig> {
    group.monitor.then(|| HealthProbeConfig {
        probe_type: group.probe_type.clone(),
        probe_port: group.probe_port,
        probe_req: group.probe_req.clone(),
        probe_resp: group.probe_resp.clone(),
        skip_tls_verify: group.probe_skip_tls_verify,
        probe_duration: group.period_secs,
        inactive_retries: group.retries,
    })
}

fn ensure_probe_health_records(
    state: &mut NativeProxyState,
    lb: &NativeListenerStateEntry,
    probe: &HealthProbeConfig,
) {
    let protocols = listener_protocols(lb);
    for protocol in protocols {
        for target in &lb.targets {
            let probe_type = probe
                .probe_type
                .as_deref()
                .unwrap_or(&protocol)
                .to_ascii_lowercase();
            let probe_port = probe.probe_port.unwrap_or(target.target_port);
            let name = target_health_key(
                &lb.target_group,
                &target.address,
                &protocol,
                target.target_port,
            );
            // Preserve observed health from the probe worker (see
            // ensure_default_health_records).
            let current_state = state
                .target_health
                .iter()
                .find(|item| item.name == name)
                .and_then(|item| item.current_state.clone())
                .unwrap_or_else(|| "unknown".to_string());
            upsert_health_entry(
                &mut state.target_health,
                TargetHealthEntry {
                    target_group: lb.target_group.clone(),
                    host_name: target.address.clone(),
                    name,
                    inactive_retries: probe.inactive_retries,
                    probe_type: Some(probe_type),
                    probe_req: probe.probe_req.clone(),
                    probe_resp: probe.probe_resp.clone(),
                    probe_duration: probe.probe_duration,
                    probe_port: Some(probe_port),
                    current_state: Some(current_state),
                    ..TargetHealthEntry::default()
                },
            );
        }
    }
}

fn ensure_default_health_records(state: &mut NativeProxyState, lb: &NativeListenerStateEntry) {
    let protocols = listener_protocols(lb);
    for protocol in protocols {
        for target in &lb.targets {
            let name = target_health_key(
                &lb.target_group,
                &target.address,
                &protocol,
                target.target_port,
            );
            // Disabling monitoring removes the old probe's unhealthy verdict.
            let current_state = "ok".to_string();
            upsert_health_entry(
                &mut state.target_health,
                TargetHealthEntry {
                    target_group: lb.target_group.clone(),
                    host_name: target.address.clone(),
                    name,
                    inactive_retries: Some(0),
                    probe_type: Some("none".to_string()),
                    probe_duration: Some(0),
                    probe_port: Some(target.target_port),
                    current_state: Some(current_state),
                    ..TargetHealthEntry::default()
                },
            );
        }
    }
}

fn listener_protocols(lb: &NativeListenerStateEntry) -> Vec<String> {
    if lb.protocols.is_empty() {
        vec![lb.spec.protocol.to_ascii_lowercase()]
    } else {
        lb.protocols
            .iter()
            .map(|protocol| protocol.to_ascii_lowercase())
            .collect()
    }
}

fn normalize_entry(entry: &mut NativeListenerStateEntry) {
    entry.spec.protocol = entry.spec.protocol.to_ascii_lowercase();
    if entry.protocols.is_empty() {
        entry.protocols = vec![entry.spec.protocol.clone()];
    } else {
        entry.protocols = entry
            .protocols
            .iter()
            .map(|protocol| protocol.to_ascii_lowercase())
            .collect();
        entry.protocols.dedup();
        if let Some(protocol) = entry.protocols.first() {
            entry.spec.protocol = protocol.clone();
        }
    }
    entry.spec.vip_ips.retain_mut(|ip| {
        *ip = ip.trim().to_string();
        !ip.is_empty()
    });
    if entry.spec.inactive_timeout == 0 {
        entry.spec.inactive_timeout = 240;
    }
    for target in &mut entry.targets {
        target.weight = target.weight.max(1);
        target.state.get_or_insert_with(|| "active".to_string());
        target.counter.get_or_insert_with(|| "0:0".to_string());
    }
}

fn merge_protocols(existing: &mut NativeListenerStateEntry, incoming: &NativeListenerStateEntry) {
    let existing_protocols = if existing.protocols.is_empty() {
        vec![existing.spec.protocol.clone()]
    } else {
        existing.protocols.clone()
    };
    let incoming_protocols = if incoming.protocols.is_empty() {
        vec![incoming.spec.protocol.clone()]
    } else {
        incoming.protocols.clone()
    };
    existing.protocols = existing_protocols;
    for protocol in incoming_protocols {
        if !existing
            .protocols
            .iter()
            .any(|current| current.eq_ignore_ascii_case(&protocol))
        {
            existing.protocols.push(protocol.to_ascii_lowercase());
        }
    }
    if is_generated_listener_name(existing.spec.name.as_deref(), existing.spec.port)
        && is_generated_listener_name(incoming.spec.name.as_deref(), incoming.spec.port)
    {
        existing.spec.name = Some(format!(
            "{}-{}",
            existing.protocols.join("-"),
            existing.spec.port
        ));
    }
}

fn is_generated_listener_name(name: Option<&str>, port: u16) -> bool {
    let Some(name) = name.map(str::trim) else {
        return true;
    };
    ["tcp", "udp", "tcp-udp", "udp-tcp"].iter().any(|protocol| {
        name == format!("{protocol}-{port}") || name == format!("auto-{protocol}-{port}")
    })
}

fn upsert_health_entry(items: &mut Vec<TargetHealthEntry>, entry: TargetHealthEntry) {
    if let Some(existing) = items.iter_mut().find(|item| item.name == entry.name) {
        *existing = entry;
    } else {
        items.push(entry);
    }
}

fn listener_name(lb: &NativeListenerStateEntry) -> String {
    lb.spec
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let protocols = if lb.protocols.is_empty() {
                vec![lb.spec.protocol.clone()]
            } else {
                lb.protocols.clone()
            };
            format!("{}-{}", protocols.join("-"), lb.spec.port)
        })
}

fn target_health_key(group: &str, ip: &str, protocol: &str, port: u16) -> String {
    format!(
        "{}:{}_{}_{}",
        group,
        ip.trim(),
        protocol.trim().to_ascii_lowercase(),
        port
    )
}

fn same_listener_identity(a: &NativeListenerStateEntry, b: &NativeListenerStateEntry) -> bool {
    let a = &a.spec;
    let b = &b.spec;
    a.vip_ips
        .iter()
        .any(|ip| b.vip_ips.iter().any(|other| ip == other))
        && a.port == b.port
        && (a.name.as_deref().unwrap_or("").trim() == b.name.as_deref().unwrap_or("").trim()
            || (is_generated_listener_name(a.name.as_deref(), a.port)
                && is_generated_listener_name(b.name.as_deref(), b.port)))
}

fn load_state(_cfg: &Config) -> Result<NativeProxyState> {
    match crate::storage::repository()?.get("native_proxy_state", "config")? {
        Some(payload) => {
            serde_json::from_str(&payload).context("parsing stored native proxy state")
        }
        None => Ok(NativeProxyState::default()),
    }
}

fn save_state(_cfg: &Config, state: &NativeProxyState) -> Result<()> {
    let payload = serde_json::to_string(state).context("serializing native proxy state")?;
    crate::storage::repository()?.put(
        "native_proxy_state",
        "config",
        crate::storage::next_revision(),
        payload,
    )
}

/// Serialize and write only when the canonical form differs from disk;
/// returns whether a write happened.
fn save_state_if_changed(_cfg: &Config, state: &mut NativeProxyState) -> Result<bool> {
    let text = serde_json::to_string_pretty(&*state).context("serializing native proxy state")?;
    if let Some(existing) = crate::storage::repository()?.get("native_proxy_state", "config")? {
        // Compare decoded state rather than JSON formatting. Formatting-only
        // differences must never re-arm the gateway datapath reconcile loop.
        if serde_json::from_str::<NativeProxyState>(&existing)
            .map(|current| current == *state)
            .unwrap_or(false)
        {
            return Ok(false);
        }
    }
    crate::storage::repository()?.put(
        "native_proxy_state",
        "config",
        crate::storage::next_revision(),
        text,
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_preserves_health_and_removes_deleted_listener_state() {
        let mut cfg = Config {
            path: "/tmp/edge-projection-test.toml".into(),
            file: Default::default(),
        };
        cfg.file.listeners.push(Listener {
            name: "tcp-8080".into(),
            port: 8080,
            target_port: 18080,
            target_group: "web".into(),
            vip_ips: vec!["192.0.2.10".parse().unwrap()],
            ..Default::default()
        });
        cfg.file.target_groups.push(TargetGroup {
            name: "web".into(),
            monitor: true,
            probe_type: Some("tcp".into()),
            probe_port: Some(18081),
            targets: vec![crate::config::BackendTarget {
                address: "198.51.100.10".parse().unwrap(),
                ..Default::default()
            }],
            ..Default::default()
        });
        let mut state = NativeProxyState::default();
        rebuild_listener_state(&cfg, &mut state).unwrap();
        assert!(
            state.listeners[0]
                .spec
                .vip_ips
                .contains(&"192.0.2.10".to_string())
        );
        assert_eq!(state.listeners[0].targets[0].target_port, 18080);
        assert_eq!(state.target_health[0].probe_port, Some(18081));
        state.target_health[0].current_state = Some("ok".into());
        let before = state.clone();
        rebuild_listener_state(&cfg, &mut state).unwrap();
        assert_eq!(state, before);
        cfg.file.listeners.clear();
        rebuild_listener_state(&cfg, &mut state).unwrap();
        assert!(state.listeners.is_empty());
        assert!(state.target_health.is_empty());
    }

    #[test]
    fn aggregate_listener_expands_to_both_transport_keys() {
        let entry = NativeListenerStateEntry {
            spec: NativeListenerSpec {
                vip_ips: vec!["192.0.2.10".to_string()],
                port: 9999,
                protocol: "tcp".to_string(),
                ..NativeListenerSpec::default()
            },
            protocols: vec!["tcp".to_string(), "udp".to_string()],
            ..NativeListenerStateEntry::default()
        };

        let expanded = expanded_native_listener_entries(
            &Config {
                file: crate::config::FileConfig::default(),
                path: crate::config::DEFAULT_CONFIG_PATH.into(),
            },
            &entry,
        );

        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0].spec.protocol, "tcp");
        assert_eq!(expanded[1].spec.protocol, "udp");
        assert_eq!(expanded[0].protocols, vec!["tcp"]);
        assert_eq!(expanded[1].protocols, vec!["udp"]);
    }
}
