use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

#[cfg(not(test))]
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::{
    config::Config,
    runtime::{
        ha::{self, VipBindDevice, VipProvider},
        ka_hook::KaHookEvent,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedHookState {
    state: &'static str,
    vip: String,
}

static LAST_MANAGED_HOOK_STATE: OnceLock<Mutex<BTreeMap<PathBuf, ManagedHookState>>> =
    OnceLock::new();
#[cfg(test)]
static TEST_HOOK_FAILURE: OnceLock<Mutex<Option<&'static str>>> = OnceLock::new();
#[cfg(test)]
static TEST_PEER_ACTIVATE_FAILURE: OnceLock<Mutex<Option<String>>> = OnceLock::new();
#[cfg(test)]
static TEST_PEER_ACTIVATE_LOG: OnceLock<Mutex<Option<Vec<String>>>> = OnceLock::new();

#[derive(Debug, Clone, Serialize)]
pub struct NativeHaState {
    pub node: String,
    pub active_gateway: Option<String>,
    pub active_revision: Option<i64>,
    pub state: String,
    pub enabled: bool,
    pub peer_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SwitchActiveResult {
    pub gateway: String,
    pub vip: Option<String>,
    pub garp_announced: bool,
    pub vip_bound: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LocalHaRoleResult {
    pub garp_announced: bool,
    pub vip_bound: bool,
}

pub fn state(cfg: &Config) -> Result<NativeHaState> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    let active = cfg
        .active_gateway()
        .ok()
        .map(|gateway| gateway.name.clone());
    let local_active = cfg.active_gateway().ok().is_some_and(|gateway| {
        gateway.name == cfg.node_name || gateway.underlay_ip == cfg.underlay_ip
    });
    let state = if !ha_cfg.enabled {
        "disabled"
    } else if local_active {
        "MASTER"
    } else {
        "BACKUP"
    };
    Ok(NativeHaState {
        node: cfg.node_name.clone(),
        active_gateway: active,
        active_revision: cfg.active_gateway_revision().ok().flatten(),
        state: state.to_string(),
        enabled: ha_cfg.enabled,
        peer_count: ha_cfg.peers.len(),
    })
}

/// Reconcile the local L2 VIP with the currently selected gateway.
///
/// Binding is checked before changing anything, so the periodic gateway
/// watcher does not emit gratuitous ARP on every pass. A newly promoted local
/// gateway binds first and then announces the VIP on the underlay device.
pub fn reconcile_vip(cfg: &Config) -> Result<bool> {
    reconcile_vip_inner(cfg, false)
}

pub fn reconcile_vip_after_activation(cfg: &Config) -> Result<bool> {
    reconcile_vip_inner(cfg, true)
}

fn reconcile_vip_inner(cfg: &Config, force_hook: bool) -> Result<bool> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    if ha_cfg.enabled && matches!(ha_cfg.vip.provider, VipProvider::Hook) {
        let role = if local_gateway_is_active(cfg) {
            "MASTER"
        } else {
            "BACKUP"
        };
        return apply_managed_hook_state(cfg, &ha_cfg, role, None, force_hook);
    }
    let Some(vip_text) = ha_cfg.vip.private_vip.as_deref() else {
        return Ok(false);
    };
    let vip = vip_text
        .parse()
        .with_context(|| format!("bad private VIP {vip_text}"))?;
    let device = vip_device(cfg, ha_cfg.vip.bind_device);
    let bound = crate::linux::addr::vip_bound_on_device(cfg, vip, &device);
    let should_bind = ha_cfg.enabled
        && matches!(ha_cfg.vip.provider, VipProvider::L2)
        && local_gateway_is_active(cfg);
    if should_bind && !bound {
        crate::linux::addr::bind_vip_on_device(cfg, vip, &device)?;
        crate::runtime::ka_hook::announce_vip(cfg, vip, &ha_cfg.vip)?;
        tracing::info!(
            "[ha] VIP {} bound to {} and announced with GARP",
            vip,
            device
        );
        return Ok(true);
    }
    if !should_bind && bound {
        crate::linux::addr::release_vip_on_device(cfg, vip, &device)?;
        tracing::info!("[ha] VIP {} released from {}", vip, device);
        return Ok(true);
    }
    Ok(false)
}

pub fn release_local_vip(cfg: &Config) -> Result<bool> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    if !ha_cfg.enabled {
        return Ok(false);
    }
    if matches!(ha_cfg.vip.provider, VipProvider::Hook) {
        return apply_managed_hook_state(cfg, &ha_cfg, "BACKUP", None, true);
    }
    if !matches!(ha_cfg.vip.provider, VipProvider::L2) {
        return Ok(false);
    }
    let Some(vip_text) = ha_cfg.vip.private_vip.as_deref() else {
        return Ok(false);
    };
    let vip = vip_text
        .parse()
        .with_context(|| format!("bad private VIP {vip_text}"))?;
    let device = vip_device(cfg, ha_cfg.vip.bind_device);
    if !crate::linux::addr::vip_bound_on_device(cfg, vip, &device) {
        return Ok(false);
    }
    crate::linux::addr::release_vip_on_device(cfg, vip, &device)?;
    tracing::info!("[ha] VIP {} released from {}", vip, device);
    Ok(true)
}

pub fn handoff_or_release_on_shutdown(cfg: &Config) -> Result<()> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    if !ha_cfg.enabled || !matches!(ha_cfg.vip.provider, VipProvider::L2 | VipProvider::Hook) {
        return Ok(());
    }
    let local_master = state(cfg)?.state == "MASTER";
    if local_master && let Some(peer) = ha_cfg.peers.first() {
        match switch_active_gateway(cfg, &peer.name) {
            Ok(result) => {
                tracing::info!(
                    "[ha] graceful shutdown handed active gateway to {} vip_bound={} garp={}",
                    result.gateway,
                    result.vip_bound,
                    result.garp_announced
                );
                return Ok(());
            }
            Err(error) => {
                tracing::warn!(
                    "[ha] graceful shutdown handoff to {} failed: {error:#}; releasing local VIP",
                    peer.name
                );
            }
        }
    }
    release_local_vip(cfg)?;
    Ok(())
}

pub fn switch_active_gateway(cfg: &Config, target_key: &str) -> Result<SwitchActiveResult> {
    switch_active_gateway_inner(cfg, target_key, false)
}

pub fn switch_active_gateway_coordinated(
    cfg: &Config,
    target_key: &str,
) -> Result<SwitchActiveResult> {
    switch_active_gateway_inner(cfg, target_key, true)
}

fn switch_active_gateway_inner(
    cfg: &Config,
    target_key: &str,
    coordinate_local_takeover: bool,
) -> Result<SwitchActiveResult> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    let target = cfg
        .gateway_by_key(target_key)
        .cloned()
        .or_else(|| {
            ha_cfg.peers.iter().find_map(|peer| {
                if peer.name != target_key && peer.underlay_ip != target_key {
                    return None;
                }
                let underlay_ip = peer.underlay_ip.parse().ok()?;
                Some(crate::config::GatewayNode {
                    name: peer.name.clone(),
                    public_ip: peer
                        .public_ip
                        .as_deref()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(underlay_ip),
                    underlay_ip,
                    overlay_ip: peer
                        .overlay_ip
                        .clone()
                        .unwrap_or_else(|| cfg.gateway_cfg().overlay_ip.clone()),
                })
            })
        })
        .with_context(|| format!("unknown gateway {target_key:?}"))?;

    let target_is_local = target.name == cfg.node_name || target.underlay_ip == cfg.underlay_ip;
    let target_underlay = target.underlay_ip.to_string();
    let previous_active = cfg
        .active_gateway()
        .ok()
        .map(|gateway| gateway.name.clone());
    if ha_cfg.enabled
        && !target_is_local
        && !ha_cfg
            .peers
            .iter()
            .any(|peer| peer.name == target.name || peer.underlay_ip == target_underlay)
    {
        bail!("failover target is not the configured HA peer");
    }
    let mut peer_notified_for_local_takeover = false;
    if ha_cfg.enabled
        && coordinate_local_takeover
        && target_is_local
        && !local_gateway_is_active(cfg)
    {
        notify_peers_of_active_gateway(cfg, &ha_cfg, &target.name)?;
        peer_notified_for_local_takeover = true;
    }

    let mut garp_announced = false;
    let mut vip_now_bound = false;
    let vip = ha_cfg.vip.private_vip.clone();

    if ha_cfg.enabled {
        if target_is_local {
            let applied = match apply_local_ha_role(cfg, &ha_cfg, true, true) {
                Ok(applied) => applied,
                Err(error) if peer_notified_for_local_takeover => {
                    restore_peer_after_failed_local_takeover(
                        cfg,
                        &ha_cfg,
                        previous_active.as_deref(),
                        &target.name,
                        error,
                    )?;
                    unreachable!("restore_peer_after_failed_local_takeover always returns Err");
                }
                Err(error) => return Err(error),
            };
            garp_announced = applied.garp_announced;
            vip_now_bound = applied.vip_bound;
            write_active_gateway(cfg, &target.name)?;
        } else {
            apply_local_ha_role(cfg, &ha_cfg, false, true)?;
            if let Err(error) = notify_peers_of_active_gateway(cfg, &ha_cfg, &target.name) {
                restore_local_master_after_failed_handoff(cfg, &ha_cfg, &target.name, error)?;
            }
            write_active_gateway(cfg, &target.name)?;
        }
    } else {
        write_active_gateway(cfg, &target.name)?;
    }

    Ok(SwitchActiveResult {
        gateway: target.name.clone(),
        vip,
        garp_announced,
        vip_bound: vip_now_bound,
    })
}

fn notify_peers_of_active_gateway(
    cfg: &Config,
    ha_cfg: &ha::GatewayHaRuntimeConfig,
    active_gateway: &str,
) -> Result<()> {
    let mut matched_peer = false;
    for peer in &ha_cfg.peers {
        matched_peer = matched_peer || peer.name == active_gateway;
        #[cfg(test)]
        if take_test_peer_activate_failure(peer, active_gateway) {
            bail!("test peer active-gateway sync failure");
        }
        #[cfg(test)]
        if record_test_peer_activate(peer, active_gateway) {
            continue;
        }
        let response = crate::runtime::ha_write::post_peer_json(
            cfg,
            peer,
            "/api/v1/ha/peer/activate",
            &serde_json::json!({ "gateway": active_gateway }),
        )?;
        if !(200..300).contains(&response.status) {
            bail!(
                "peer active-gateway sync to {} failed with HTTP {}: {}",
                peer.name,
                response.status,
                response.body
            );
        }
    }
    if !ha_cfg.peers.is_empty() && active_gateway != cfg.node_name && !matched_peer {
        bail!("failover target is not the configured HA peer");
    }
    Ok(())
}

fn restore_local_master_after_failed_handoff(
    cfg: &Config,
    ha_cfg: &ha::GatewayHaRuntimeConfig,
    target_name: &str,
    handoff_error: anyhow::Error,
) -> Result<()> {
    tracing::warn!(
        "[ha] peer handoff to {} failed after local demotion: {handoff_error:#}; restoring local role",
        target_name
    );
    if let Err(rollback_error) = apply_local_ha_role(cfg, ha_cfg, true, true) {
        bail!(
            "peer active-gateway sync to {target_name} failed after local demotion: {handoff_error:#}; local role restore also failed: {rollback_error:#}"
        );
    }
    Err(handoff_error)
}

fn restore_peer_after_failed_local_takeover(
    cfg: &Config,
    ha_cfg: &ha::GatewayHaRuntimeConfig,
    previous_active: Option<&str>,
    target_name: &str,
    takeover_error: anyhow::Error,
) -> Result<()> {
    let Some(previous_active) = previous_active else {
        return Err(takeover_error);
    };
    tracing::warn!(
        "[ha] local takeover of {} failed after peer demotion: {takeover_error:#}; restoring peer active {}",
        target_name,
        previous_active
    );
    if let Err(rollback_error) = notify_peers_of_active_gateway(cfg, ha_cfg, previous_active) {
        bail!(
            "local takeover of {target_name} failed after peer demotion: {takeover_error:#}; peer role restore to {previous_active} also failed: {rollback_error:#}"
        );
    }
    Err(takeover_error)
}

pub(crate) fn apply_local_ha_role(
    cfg: &Config,
    ha_cfg: &ha::GatewayHaRuntimeConfig,
    local_active: bool,
    force_hook: bool,
) -> Result<LocalHaRoleResult> {
    if !ha_cfg.enabled {
        return Ok(LocalHaRoleResult::default());
    }
    if matches!(ha_cfg.vip.provider, VipProvider::Hook) {
        let role = if local_active { "MASTER" } else { "BACKUP" };
        apply_managed_hook_state(cfg, ha_cfg, role, None, force_hook)?;
        return Ok(LocalHaRoleResult::default());
    }
    if !matches!(ha_cfg.vip.provider, VipProvider::L2) {
        return Ok(LocalHaRoleResult::default());
    }
    let Some(vip_text) = ha_cfg.vip.private_vip.as_deref() else {
        return Ok(LocalHaRoleResult::default());
    };
    let vip = vip_text
        .parse()
        .with_context(|| format!("bad private VIP {vip_text}"))?;
    let device = vip_device(cfg, ha_cfg.vip.bind_device);
    let bound = crate::linux::addr::vip_bound_on_device(cfg, vip, &device);
    if local_active {
        if !bound {
            crate::linux::addr::bind_vip_on_device(cfg, vip, &device)?;
            crate::runtime::ka_hook::announce_vip(cfg, vip, &ha_cfg.vip)?;
            tracing::info!(
                "[ha] VIP {} bound to {} and announced with GARP",
                vip,
                device
            );
            return Ok(LocalHaRoleResult {
                garp_announced: true,
                vip_bound: true,
            });
        }
        return Ok(LocalHaRoleResult {
            vip_bound: true,
            ..LocalHaRoleResult::default()
        });
    }
    if bound {
        crate::linux::addr::release_vip_on_device(cfg, vip, &device)?;
        tracing::info!("[ha] VIP {} released from {}", vip, device);
        return Ok(LocalHaRoleResult::default());
    }
    Ok(LocalHaRoleResult::default())
}

pub fn handle_ka_hook_event(cfg: &Config, event: &KaHookEvent) -> Result<()> {
    match event.state.trim().to_ascii_uppercase().as_str() {
        "MASTER" => {
            write_active_gateway(cfg, &cfg.node_name)?;
            let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
            if matches!(ha_cfg.vip.provider, VipProvider::Hook) {
                apply_managed_hook_state(cfg, &ha_cfg, "MASTER", non_empty(&event.vip), true)?;
                return Ok(());
            }
            if !event.vip.trim().is_empty() {
                let vip = event
                    .vip
                    .parse()
                    .with_context(|| format!("bad ka_hook VIP {}", event.vip))?;
                // BFD-driven promotion must bind the address too — GARP alone
                // leaves the VPC dropping VIP ingress on this node.
                let device = vip_device(cfg, ha_cfg.vip.bind_device);
                crate::linux::addr::bind_vip_on_device(cfg, vip, &device)?;
                crate::runtime::ka_hook::announce_vip(cfg, vip, &ha_cfg.vip)?;
            }
            Ok(())
        }
        "BACKUP" | "STOP" => {
            let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
            if matches!(ha_cfg.vip.provider, VipProvider::Hook) {
                apply_managed_hook_state(cfg, &ha_cfg, "BACKUP", non_empty(&event.vip), true)?;
                return Ok(());
            }
            if !event.vip.trim().is_empty() {
                let vip = event
                    .vip
                    .parse()
                    .with_context(|| format!("bad ka_hook VIP {}", event.vip))?;
                let device = vip_device(cfg, ha_cfg.vip.bind_device);
                crate::linux::addr::release_vip_on_device(cfg, vip, &device)?;
            }
            Ok(())
        }
        other => bail!("unsupported HA hook state {other:?}"),
    }
}

fn local_gateway_is_active(cfg: &Config) -> bool {
    cfg.active_gateway()
        .map(|gateway| gateway.name == cfg.node_name || gateway.underlay_ip == cfg.underlay_ip)
        .unwrap_or(false)
}

/// HA ownership does not change listeners, targets, or synchronized flow state.
pub(crate) fn write_active_gateway(cfg: &Config, gateway: &str) -> Result<()> {
    cfg.write_active_gateway(gateway)
}

fn apply_managed_hook_state(
    cfg: &Config,
    ha_cfg: &ha::GatewayHaRuntimeConfig,
    state: &'static str,
    vip_override: Option<String>,
    force: bool,
) -> Result<bool> {
    let vip = vip_override
        .or_else(|| ha_cfg.vip.private_vip.clone())
        .unwrap_or_default();
    let desired = ManagedHookState {
        state,
        vip: vip.clone(),
    };
    let key = cfg.state_dir.clone();
    let lock = LAST_MANAGED_HOOK_STATE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if !force {
        let last = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if last.get(&key) == Some(&desired) {
            return Ok(false);
        }
    }

    run_managed_hook_state(cfg, ha_cfg, state, &vip)?;
    let mut last = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    last.insert(key, desired);
    Ok(true)
}

fn run_managed_hook_state(
    cfg: &Config,
    ha_cfg: &ha::GatewayHaRuntimeConfig,
    state: &'static str,
    vip: &str,
) -> Result<()> {
    #[cfg(not(test))]
    ha::ensure_managed_hook_scripts()?;
    let (action, path) = match state {
        "MASTER" => (
            "promote",
            ha_cfg
                .vip
                .promote_hook
                .clone()
                .unwrap_or_else(ha::default_promote_hook),
        ),
        "BACKUP" => (
            "demote",
            ha_cfg
                .vip
                .demote_hook
                .clone()
                .unwrap_or_else(ha::default_demote_hook),
        ),
        other => bail!("unsupported managed HA hook state {other:?}"),
    };
    run_hook_program(cfg, &path, action, state, vip)?;
    let verify_hook = ha_cfg
        .vip
        .verify_hook
        .clone()
        .unwrap_or_else(ha::default_verify_hook);
    run_hook_program(cfg, &verify_hook, "verify", state, vip)?;
    tracing::info!(
        "[ha] managed hook state={} action={} vip={}",
        state,
        action,
        if vip.is_empty() { "-" } else { vip }
    );
    Ok(())
}

#[cfg(not(test))]
fn run_hook_program(
    cfg: &Config,
    path: &PathBuf,
    action: &str,
    state: &str,
    vip: &str,
) -> Result<()> {
    let status = Command::new(path)
        .arg(vip)
        .env("EDGE_LB_HA_ACTION", action)
        .env("EDGE_LB_HA_STATE", state)
        .env("EDGE_LB_VIP", vip)
        .env("EDGE_LB_NODE", &cfg.node_name)
        .env("EDGE_LB_UNDERLAY_IP", cfg.underlay_ip.to_string())
        .env("EDGE_LB_STATE_DIR", cfg.state_dir.as_os_str())
        .status()
        .with_context(|| format!("executing managed HA {action} hook {}", path.display()))?;
    if !status.success() {
        bail!(
            "managed HA {action} hook {} failed with {status}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
fn run_hook_program(
    cfg: &Config,
    path: &PathBuf,
    action: &str,
    state: &str,
    vip: &str,
) -> Result<()> {
    let _ = cfg;
    test_hook_events().lock().unwrap().push(format!(
        "{}:{}:{}:{}",
        path.display(),
        action,
        state,
        vip
    ));
    let mut failure = TEST_HOOK_FAILURE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap();
    if failure.as_deref() == Some(action) {
        *failure = None;
        bail!("test managed HA {action} hook failure");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_test_hook_failure(action: Option<&'static str>) {
    *TEST_HOOK_FAILURE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = action;
}

#[cfg(test)]
fn set_test_peer_activate_failure(peer_name: Option<&str>) {
    *TEST_PEER_ACTIVATE_FAILURE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = peer_name.map(ToOwned::to_owned);
}

#[cfg(test)]
fn start_test_peer_activate_log() {
    *TEST_PEER_ACTIVATE_LOG
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = Some(Vec::new());
}

#[cfg(test)]
fn take_test_peer_activate_log() -> Vec<String> {
    TEST_PEER_ACTIVATE_LOG
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .take()
        .unwrap_or_default()
}

#[cfg(test)]
fn take_test_peer_activate_failure(peer: &ha::GatewayHaPeer, active_gateway: &str) -> bool {
    let mut failure = TEST_PEER_ACTIVATE_FAILURE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap();
    let Some(name) = failure.as_deref() else {
        return false;
    };
    if name != peer.name && name != peer.underlay_ip && name != active_gateway {
        return false;
    }
    *failure = None;
    true
}

#[cfg(test)]
fn record_test_peer_activate(peer: &ha::GatewayHaPeer, active_gateway: &str) -> bool {
    let mut log = TEST_PEER_ACTIVATE_LOG
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap();
    let Some(entries) = log.as_mut() else {
        return false;
    };
    entries.push(format!("{}:{active_gateway}", peer.name));
    true
}

#[cfg(test)]
fn test_hook_events() -> &'static Mutex<Vec<String>> {
    static EVENTS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    EVENTS.get_or_init(|| Mutex::new(Vec::new()))
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn vip_device(cfg: &Config, bind_device: VipBindDevice) -> String {
    match bind_device {
        VipBindDevice::Underlay => cfg.network().underlay_dev.clone(),
        VipBindDevice::Loopback => "lo".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::SystemTime};

    use crate::{
        config::{
            ActiveSource, Config, FileConfig, GatewayNode, HaConfig, NetworkConfig, NodeRole,
        },
        provider::native::take_state_dirty,
        runtime::{
            ha::{GatewayHaPeer, GatewayHaRuntimeConfig, VipConfig, VipProvider},
            ka_hook::KaHookEvent,
        },
    };

    use super::*;

    fn reset_test_hooks() {
        if let Some(lock) = LAST_MANAGED_HOOK_STATE.get() {
            lock.lock().unwrap().clear();
        }
        set_test_hook_failure(None);
        set_test_peer_activate_failure(None);
        take_test_peer_activate_log();
        test_hook_events().lock().unwrap().clear();
    }

    #[test]
    fn switch_active_gateway_preserves_clean_datapath_when_owner_changes() {
        let (cfg, dir) = test_gateway_config("switch");
        save_hook_ha_config(&dir);
        fs::write(&cfg.ha.active_state_file, "gateway-b\n").unwrap();
        let _ = take_state_dirty();

        let result = switch_active_gateway(&cfg, "gateway-a").unwrap();

        assert_eq!(result.gateway, "gateway-a");
        assert_eq!(cfg.active_gateway().unwrap().name, "gateway-a");
        assert!(!take_state_dirty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn hook_reconcile_runs_role_hook_then_verify_only_on_state_change() {
        reset_test_hooks();
        let (cfg, dir) = test_gateway_config("hook-reconcile");
        save_hook_ha_config_with_vip(&dir, "192.0.2.200");
        cfg.write_active_gateway("gateway-a").unwrap();
        let _ = take_state_dirty();

        assert!(reconcile_vip(&cfg).unwrap());
        assert!(!reconcile_vip(&cfg).unwrap());
        cfg.write_active_gateway("gateway-b").unwrap();
        assert!(reconcile_vip(&cfg).unwrap());

        let events: Vec<_> = test_hook_events()
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.ends_with(":192.0.2.200"))
            .cloned()
            .collect();
        assert_eq!(
            events,
            vec![
                "/usr/local/bin/edge-lb-promote:promote:MASTER:192.0.2.200",
                "/usr/local/bin/edge-lb-verify-vip:verify:MASTER:192.0.2.200",
                "/usr/local/bin/edge-lb-demote:demote:BACKUP:192.0.2.200",
                "/usr/local/bin/edge-lb-verify-vip:verify:BACKUP:192.0.2.200",
            ]
        );
        assert!(!take_state_dirty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn explicit_activation_forces_hook_and_verify_even_when_role_is_unchanged() {
        reset_test_hooks();
        let (cfg, dir) = test_gateway_config("hook-force-activation");
        save_hook_ha_config_with_vip(&dir, "192.0.2.200");
        cfg.write_active_gateway("gateway-a").unwrap();
        let _ = take_state_dirty();

        assert!(reconcile_vip(&cfg).unwrap());
        assert!(!reconcile_vip(&cfg).unwrap());
        assert!(reconcile_vip_after_activation(&cfg).unwrap());

        let events: Vec<_> = test_hook_events()
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.ends_with(":192.0.2.200"))
            .cloned()
            .collect();
        assert_eq!(
            events,
            vec![
                "/usr/local/bin/edge-lb-promote:promote:MASTER:192.0.2.200",
                "/usr/local/bin/edge-lb-verify-vip:verify:MASTER:192.0.2.200",
                "/usr/local/bin/edge-lb-promote:promote:MASTER:192.0.2.200",
                "/usr/local/bin/edge-lb-verify-vip:verify:MASTER:192.0.2.200",
            ]
        );
        assert!(!take_state_dirty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn explicit_local_switch_forces_hook_and_verify_even_when_role_is_unchanged() {
        reset_test_hooks();
        let (cfg, dir) = test_gateway_config("hook-force-local-switch");
        save_hook_ha_config_with_vip(&dir, "192.0.2.200");
        cfg.write_active_gateway("gateway-a").unwrap();
        let _ = take_state_dirty();

        assert!(reconcile_vip(&cfg).unwrap());
        assert!(!reconcile_vip(&cfg).unwrap());
        let result = switch_active_gateway(&cfg, "gateway-a").unwrap();

        assert_eq!(result.gateway, "gateway-a");
        let events: Vec<_> = test_hook_events()
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.ends_with(":192.0.2.200"))
            .cloned()
            .collect();
        assert_eq!(
            events,
            vec![
                "/usr/local/bin/edge-lb-promote:promote:MASTER:192.0.2.200",
                "/usr/local/bin/edge-lb-verify-vip:verify:MASTER:192.0.2.200",
                "/usr/local/bin/edge-lb-promote:promote:MASTER:192.0.2.200",
                "/usr/local/bin/edge-lb-verify-vip:verify:MASTER:192.0.2.200",
            ]
        );
        assert!(!take_state_dirty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn local_switch_does_not_commit_active_state_when_promote_hook_fails() {
        reset_test_hooks();
        let (cfg, dir) = test_gateway_config("hook-fail-promote");
        save_hook_ha_config_with_vip(&dir, "192.0.2.200");
        cfg.write_active_gateway("gateway-b").unwrap();
        set_test_hook_failure(Some("promote"));

        let error = switch_active_gateway(&cfg, "gateway-a").unwrap_err();

        assert!(format!("{error:#}").contains("test managed HA promote hook failure"));
        assert_eq!(cfg.active_gateway().unwrap().name, "gateway-b");
        let events = test_hook_events().lock().unwrap().clone();
        assert_eq!(
            events,
            vec!["/usr/local/bin/edge-lb-promote:promote:MASTER:192.0.2.200"]
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn remote_switch_does_not_commit_active_state_when_demote_hook_fails() {
        reset_test_hooks();
        let (cfg, dir) = test_gateway_config("hook-fail-demote");
        save_hook_ha_config_with_vip(&dir, "192.0.2.200");
        cfg.write_active_gateway("gateway-a").unwrap();
        set_test_hook_failure(Some("demote"));

        let error = switch_active_gateway(&cfg, "gateway-b").unwrap_err();

        assert!(format!("{error:#}").contains("test managed HA demote hook failure"));
        assert_eq!(cfg.active_gateway().unwrap().name, "gateway-a");
        let events = test_hook_events().lock().unwrap().clone();
        assert_eq!(
            events,
            vec!["/usr/local/bin/edge-lb-demote:demote:BACKUP:192.0.2.200"]
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn remote_switch_restores_local_role_when_peer_activation_fails_after_demote() {
        reset_test_hooks();
        let (cfg, dir) = test_gateway_config("peer-activate-fails-after-demote");
        save_hook_ha_config_with_vip(&dir, "192.0.2.200");
        cfg.write_active_gateway("gateway-a").unwrap();
        set_test_peer_activate_failure(Some("gateway-b"));

        let error = switch_active_gateway(&cfg, "gateway-b").unwrap_err();

        assert!(format!("{error:#}").contains("test peer active-gateway sync failure"));
        assert_eq!(cfg.active_gateway().unwrap().name, "gateway-a");
        let events = test_hook_events().lock().unwrap().clone();
        assert_eq!(
            events,
            vec![
                "/usr/local/bin/edge-lb-demote:demote:BACKUP:192.0.2.200",
                "/usr/local/bin/edge-lb-verify-vip:verify:BACKUP:192.0.2.200",
                "/usr/local/bin/edge-lb-promote:promote:MASTER:192.0.2.200",
                "/usr/local/bin/edge-lb-verify-vip:verify:MASTER:192.0.2.200",
            ]
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn coordinated_local_switch_restores_peer_when_local_promote_fails_after_peer_demote() {
        reset_test_hooks();
        let (cfg, dir) = test_gateway_config("local-promote-fails-after-peer-demote");
        save_hook_ha_config_with_vip(&dir, "192.0.2.200");
        cfg.write_active_gateway("gateway-b").unwrap();
        start_test_peer_activate_log();
        set_test_hook_failure(Some("promote"));

        let error = switch_active_gateway_coordinated(&cfg, "gateway-a").unwrap_err();

        assert!(format!("{error:#}").contains("test managed HA promote hook failure"));
        assert_eq!(cfg.active_gateway().unwrap().name, "gateway-b");
        assert_eq!(
            take_test_peer_activate_log(),
            vec!["gateway-b:gateway-a", "gateway-b:gateway-b"]
        );
        let events = test_hook_events().lock().unwrap().clone();
        assert_eq!(
            events,
            vec!["/usr/local/bin/edge-lb-promote:promote:MASTER:192.0.2.200"]
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn ka_hook_active_events_preserve_clean_datapath_when_owner_changes() {
        reset_test_hooks();
        let (cfg, dir) = test_gateway_config("ka-hook");
        save_hook_ha_config(&dir);
        fs::write(&cfg.ha.active_state_file, "gateway-b\n").unwrap();
        let _ = take_state_dirty();

        handle_ka_hook_event(
            &cfg,
            &KaHookEvent {
                instance: "edge-lb".to_string(),
                state: "MASTER".to_string(),
                vip: String::new(),
            },
        )
        .unwrap();

        assert_eq!(cfg.active_gateway().unwrap().name, "gateway-a");
        assert!(!take_state_dirty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn ownership_write_preserves_pending_business_reconcile() {
        let (cfg, dir) = test_gateway_config("ownership-pending-business");
        crate::provider::native::mark_state_dirty();
        write_active_gateway(&cfg, "gateway-b").unwrap();
        assert_eq!(cfg.active_gateway().unwrap().name, "gateway-b");
        assert!(take_state_dirty());
        fs::remove_dir_all(dir).ok();
    }

    fn save_hook_ha_config(dir: &std::path::Path) {
        save_hook_ha_config_with_vip(dir, "");
    }

    fn save_hook_ha_config_with_vip(dir: &std::path::Path, private_vip: &str) {
        ha::save_for_state_dir(
            dir,
            &GatewayHaRuntimeConfig {
                enabled: true,
                peers: vec![GatewayHaPeer {
                    name: "gateway-b".to_string(),
                    underlay_ip: "192.0.2.16".to_string(),
                    ..GatewayHaPeer::default()
                }],
                vip: VipConfig {
                    provider: VipProvider::Hook,
                    private_vip: if private_vip.is_empty() {
                        None
                    } else {
                        Some(private_vip.to_string())
                    },
                    ..VipConfig::default()
                },
                ..GatewayHaRuntimeConfig::default()
            },
        )
        .unwrap();
    }

    fn test_gateway_config(name: &str) -> (Config, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "edge-lb-ha-datapath-contract-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let active_state_file = dir.join("active-gateway");
        let file = FileConfig {
            node_role: NodeRole::Gateway,
            node_name: "gateway-a".to_string(),
            public_ip: "198.51.100.12".parse().unwrap(),
            underlay_ip: "192.0.2.12".parse().unwrap(),
            state_dir: dir.clone(),
            ha: HaConfig {
                active_source: ActiveSource::File,
                active_state_file,
                ..HaConfig::default()
            },
            network: NetworkConfig {
                gateway_public_ip: "198.51.100.12".parse().unwrap(),
                gateway_ip: "192.0.2.12".parse().unwrap(),
                underlay_dev: "eth0".to_string(),
                vxlan_dev: "edge-hub".to_string(),
                overlay_cidr: "10.255.12.0/24".to_string(),
                dscp: 46,
                ..NetworkConfig::default()
            },
            gateway_nodes: vec![
                GatewayNode {
                    name: "gateway-a".to_string(),
                    public_ip: "198.51.100.12".parse().unwrap(),
                    underlay_ip: "192.0.2.12".parse().unwrap(),
                    overlay_ip: "10.255.12.1/24".to_string(),
                },
                GatewayNode {
                    name: "gateway-b".to_string(),
                    public_ip: "198.51.100.16".parse().unwrap(),
                    underlay_ip: "192.0.2.16".parse().unwrap(),
                    overlay_ip: "10.255.16.1/24".to_string(),
                },
            ],
            ..FileConfig::default()
        };
        (
            Config {
                file,
                path: dir.join("config.toml"),
            },
            dir,
        )
    }
}
