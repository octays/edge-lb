use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    api::response::Reply,
    config::{Config, NodeRole},
    events::{self, EdgeEvent, Severity},
    runtime::ha::{self, GatewayHaPeer, GatewayHaRuntimeConfig},
};

#[derive(Debug, serde::Serialize)]
struct HaStatusResponse {
    config: Value,
    session_token: Value,
    native: crate::provider::native::ha::NativeHaState,
    bfd: crate::runtime::bfd::BfdStatus,
    xsync: crate::provider::native::xsync::XsyncStatus,
}

#[derive(Debug, Deserialize)]
struct PairRequestBody {
    #[serde(alias = "xds_addr", alias = "peer_xds_addr")]
    endpoint: String,
    #[serde(alias = "token", alias = "pairing_token")]
    bootstrap_token: String,
    #[serde(default)]
    config: Option<GatewayHaRuntimeConfig>,
}

pub(in crate::api) fn get_config(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    match ha::load_for_state_dir(Path::new(&*cfg.state_dir)) {
        Ok(value) => Reply::json(200, serde_json::to_value(value).unwrap()),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn put_config(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let value: GatewayHaRuntimeConfig = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad HA config JSON: {e}")),
    };
    let value = ha::normalize_runtime_config(value);
    if let Err(e) = ha::validate(&value) {
        return Reply::error(400, format!("invalid HA config: {e:#}"));
    }
    if let Err(e) = ha::save_for_state_dir(Path::new(&*cfg.state_dir), &value) {
        return Reply::error(500, format!("{e:#}"));
    }
    Reply::json(
        200,
        json!({
            "status": "saved",
            "storage": "sqlite",
            "datapath_refresh_required": datapath_refresh_required(&value),
        }),
    )
}

pub(in crate::api) fn pair(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let body: PairRequestBody = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad HA pair JSON: {e}")),
    };
    let mut desired = match body.config {
        Some(value) => value,
        None => match ha::load_for_state_dir(Path::new(&*cfg.state_dir)) {
            Ok(value) => value,
            Err(e) => return Reply::error(500, format!("{e:#}")),
        },
    };
    desired = ha::normalize_runtime_config(desired);
    desired.self_index = 0;
    desired.preferred_active = Some(cfg.node_name.clone());
    match crate::control::pair_gateway(cfg, &body.endpoint, &body.bootstrap_token, &desired) {
        Ok(result) => {
            publish(
                cfg,
                events::HA_PAIR_SUCCEEDED,
                Severity::Info,
                "HA pairing succeeded",
                format!(
                    "Gateway paired with {} ({})",
                    result.peer.name, result.peer.underlay_ip
                ),
                json!({ "peer": &result.peer }),
            );
            Reply::json(200, serde_json::to_value(result).unwrap())
        }
        Err(e) => {
            publish(
                cfg,
                events::HA_PAIR_FAILED,
                Severity::Warning,
                "HA pairing failed",
                format!("{e:#}"),
                json!({ "endpoint": body.endpoint }),
            );
            Reply::error(500, format!("{e:#}"))
        }
    }
}

pub(in crate::api) fn unpair(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    match ha::unpair_for_state_dir(Path::new(&*cfg.state_dir)) {
        Ok((_value, deleted_secret, restart_required)) => {
            publish(
                cfg,
                events::HA_UNPAIRED,
                Severity::Info,
                "HA peer unpaired",
                "Gateway HA peer information was removed.",
                json!({
                    "secret_deleted": deleted_secret,
                    "datapath_refresh_required": restart_required,
                }),
            );
            Reply::json(
                200,
                json!({
                    "status": "unpaired",
                    "storage": "sqlite",
                    "secret_deleted": deleted_secret,
                    "datapath_refresh_required": restart_required,
                }),
            )
        }
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn status(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let config = match ha::load_for_state_dir(Path::new(&*cfg.state_dir)) {
        Ok(mut value) => {
            refresh_peer_metadata_for_status(cfg, &mut value);
            serde_json::to_value(value).unwrap()
        }
        Err(e) => json!({ "error": format!("{e:#}") }),
    };
    let session_token = match ha::load_secrets_for_state_dir(Path::new(&*cfg.state_dir)) {
        Ok(Some(value)) => json!({
            "present": true,
            "peer_name": value.peer_name,
            "peer_underlay_ip": value.peer_underlay_ip,
            "session_token_id": value.session_token_id,
            "updated_at_unix": value.updated_at_unix,
        }),
        Ok(None) => json!({ "present": false }),
        Err(e) => json!({ "present": false, "error": format!("{e:#}") }),
    };
    let response = HaStatusResponse {
        config,
        session_token,
        native: native_ha_state(cfg),
        bfd: crate::runtime::bfd::snapshot(),
        xsync: crate::provider::native::xsync::snapshot(),
    };
    Reply::json(200, serde_json::to_value(response).unwrap())
}

fn refresh_peer_metadata_for_status(cfg: &Config, ha_config: &mut GatewayHaRuntimeConfig) {
    if !ha_config.enabled {
        return;
    }
    for peer in &mut ha_config.peers {
        let response = match crate::runtime::ha_write::get_peer(cfg, peer, "/api/v1/ha/peer/status")
        {
            Ok(response) if response.status == 200 => response,
            Ok(response) => {
                tracing::debug!(
                    "[ha] peer metadata refresh from {} skipped: HTTP {}",
                    peer.name,
                    response.status
                );
                continue;
            }
            Err(error) => {
                tracing::debug!(
                    "[ha] peer metadata refresh from {} failed: {error:#}",
                    peer.name
                );
                continue;
            }
        };
        let Ok(value) = serde_json::from_str::<Value>(&response.body) else {
            tracing::debug!(
                "[ha] peer metadata refresh from {} returned bad JSON",
                peer.name
            );
            continue;
        };
        update_peer_from_status_value(peer, &value);
    }
}

fn update_peer_from_status_value(peer: &mut GatewayHaPeer, value: &Value) -> bool {
    let Some(node) = value.get("node").and_then(Value::as_object) else {
        return false;
    };
    let name = node.get("name").and_then(Value::as_str).unwrap_or_default();
    let underlay_ip = node
        .get("underlay_ip")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if name != peer.name && underlay_ip != peer.underlay_ip {
        return false;
    }

    if !name.is_empty() {
        peer.name = name.to_string();
    }
    if !underlay_ip.is_empty() {
        peer.underlay_ip = underlay_ip.to_string();
    }
    replace_optional_string(node, "public_ip", &mut peer.public_ip);
    replace_optional_string(node, "api_addr", &mut peer.api_addr);
    replace_optional_string(node, "xds_addr", &mut peer.xds_addr);
    replace_optional_string(node, "overlay_cidr", &mut peer.overlay_cidr);
    replace_optional_string(node, "overlay_ip", &mut peer.overlay_ip);
    replace_optional_string(node, "version", &mut peer.version);
    replace_optional_u32(node, "dscp", &mut peer.dscp);
    replace_optional_u32(node, "vni", &mut peer.vni);
    replace_optional_u16(node, "vxlan_port", &mut peer.vxlan_port);
    replace_optional_u32(node, "mtu", &mut peer.mtu);
    if let Some(capabilities) = node.get("capabilities").and_then(Value::as_array) {
        peer.capabilities = capabilities
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect();
    }
    true
}

fn replace_optional_string(
    node: &serde_json::Map<String, Value>,
    field: &str,
    dest: &mut Option<String>,
) {
    if let Some(value) = node
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        *dest = Some(value.to_string());
    }
}

fn replace_optional_u32(
    node: &serde_json::Map<String, Value>,
    field: &str,
    dest: &mut Option<u32>,
) {
    if let Some(value) = node
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
    {
        *dest = Some(value);
    }
}

fn replace_optional_u16(
    node: &serde_json::Map<String, Value>,
    field: &str,
    dest: &mut Option<u16>,
) {
    if let Some(value) = node
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
    {
        *dest = Some(value);
    }
}

pub(in crate::api) fn peer_status(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let identity = ha::local_identity(cfg);
    let ha_config = match ha::load_for_state_dir(Path::new(&*cfg.state_dir)) {
        Ok(value) => value,
        Err(e) => return Reply::error(500, format!("{e:#}")),
    };
    Reply::json(
        200,
        json!({
            "node": {
                "name": identity.name,
                "underlay_ip": identity.underlay_ip,
                "public_ip": identity.public_ip,
                "api_addr": identity.api_addr,
                "xds_addr": identity.xds_addr,
                "overlay_cidr": identity.overlay_cidr,
                "overlay_ip": identity.overlay_ip,
                "dscp": identity.dscp,
                "vni": identity.vni,
                "vxlan_port": identity.vxlan_port,
                "mtu": identity.mtu,
                "version": identity.version,
                "capabilities": identity.capabilities,
            },
            "ha": {
                "enabled": ha_config.enabled,
                "mode": ha_config.mode,
                "self_index": ha_config.self_index,
                "connection_sync": ha_config.connection_sync,
                "failover": ha_config.failover,
                "vip": ha_config.vip,
                "peer_count": ha_config.peers.len(),
            },
            "native": native_ha_state(cfg),
        }),
    )
}

/// Apply a coordinated manual promotion requested by the paired gateway.
pub(in crate::api) fn peer_activate(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let value: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad activation JSON: {e}")),
    };
    let Some(target) = value.get("gateway").and_then(Value::as_str) else {
        return Reply::error(400, "body must be {\"gateway\": \"<name or ip>\"}");
    };
    let Some(local) = cfg.gateway_by_key(target) else {
        return Reply::error(409, "activation target is not a configured gateway");
    };
    if local.name != cfg.node_name && local.underlay_ip != cfg.underlay_ip {
        return Reply::error(409, "activation target is not this gateway");
    }
    if let Err(e) = crate::provider::native::ha::write_active_gateway(cfg, &cfg.node_name) {
        return Reply::error(500, format!("writing active gateway: {e:#}"));
    }
    let ha_cfg = match ha::load_for_state_dir(Path::new(&*cfg.state_dir)) {
        Ok(value) => value,
        Err(e) => return Reply::error(500, format!("loading HA config: {e:#}")),
    };
    let mut garp_announced = false;
    let mut vip_bound = false;
    if ha_cfg.enabled {
        let changed = match crate::provider::native::ha::reconcile_vip_after_activation(cfg) {
            Ok(changed) => changed,
            Err(e) => return Reply::error(500, format!("applying HA takeover state: {e:#}")),
        };
        if matches!(ha_cfg.vip.provider, ha::VipProvider::L2)
            && let Some(vip_text) = ha_cfg.vip.private_vip.as_deref()
        {
            let vip = match vip_text.parse() {
                Ok(vip) => vip,
                Err(e) => return Reply::error(400, format!("bad private VIP {vip_text}: {e}")),
            };
            let device = match ha_cfg.vip.bind_device {
                ha::VipBindDevice::Loopback => "lo".to_string(),
                ha::VipBindDevice::Underlay => cfg.network().underlay_dev.clone(),
            };
            vip_bound = crate::linux::addr::vip_bound_on_device(cfg, vip, &device);
            garp_announced = changed && vip_bound;
        }
    }
    Reply::json(
        200,
        json!({
            "status": "active",
            "gateway": cfg.node_name,
            "garp_announced": garp_announced,
            "vip_bound": vip_bound,
        }),
    )
}

pub(in crate::api) fn failover(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let value: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad JSON: {e}")),
    };
    let Some(target) = value
        .get("gateway")
        .or_else(|| value.get("target"))
        .and_then(|value| value.as_str())
    else {
        return Reply::error(400, "body must be {\"gateway\": \"<name or ip>\"}");
    };
    publish(
        cfg,
        events::HA_SWITCHOVER_STARTED,
        Severity::Info,
        "HA switchover started",
        format!("Requested active gateway target: {target}."),
        json!({ "target": target }),
    );
    match crate::provider::native::ha::switch_active_gateway(cfg, target) {
        Ok(result) => {
            publish(
                cfg,
                events::HA_SWITCHOVER_SUCCEEDED,
                Severity::Info,
                "HA switchover succeeded",
                format!("Active gateway switched to {}.", result.gateway),
                json!({ "result": &result }),
            );
            Reply::json(200, serde_json::to_value(result).unwrap())
        }
        Err(e) => {
            publish(
                cfg,
                events::HA_SWITCHOVER_FAILED,
                Severity::Critical,
                "HA switchover failed",
                format!("{e:#}"),
                json!({ "target": target }),
            );
            Reply::error(500, format!("{e:#}"))
        }
    }
}

fn publish(
    cfg: &Config,
    kind: &str,
    severity: Severity,
    title: impl Into<String>,
    text: impl Into<String>,
    details: Value,
) {
    events::publish(
        EdgeEvent::new(kind, severity, &cfg.node_name, "gateway", title, text)
            .with_details(details),
    );
}

fn require_gateway(cfg: &Config) -> Option<Reply> {
    if matches!(cfg.node_role, NodeRole::Gateway) {
        None
    } else {
        Some(Reply::error(
            403,
            "HA API is only available on gateway nodes",
        ))
    }
}

fn datapath_refresh_required(value: &GatewayHaRuntimeConfig) -> bool {
    value.enabled && value.connection_sync
}

fn native_ha_state(cfg: &Config) -> crate::provider::native::ha::NativeHaState {
    match crate::provider::native::ha::state(cfg) {
        Ok(value) => value,
        Err(error) => crate::provider::native::ha::NativeHaState {
            node: cfg.node_name.clone(),
            active_gateway: None,
            active_revision: None,
            state: format!("error: {error:#}"),
            enabled: false,
            peer_count: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_status_refresh_updates_matching_peer_metadata() {
        let mut peer = GatewayHaPeer {
            name: "gateway-b".to_string(),
            underlay_ip: "192.168.0.16".to_string(),
            version: Some("0.1.3".to_string()),
            ..GatewayHaPeer::default()
        };
        let value = json!({
            "node": {
                "name": "gateway-b",
                "underlay_ip": "192.168.0.16",
                "public_ip": "198.51.100.16",
                "api_addr": "192.168.0.16:18080",
                "xds_addr": "192.168.0.16:22222",
                "overlay_cidr": "10.255.16.0/24",
                "overlay_ip": "10.255.16.1/24",
                "dscp": 40,
                "vni": 100,
                "vxlan_port": 4789,
                "mtu": 1450,
                "version": "0.1.6",
                "capabilities": ["ha.active_backup", "ha.peer_token"]
            }
        });

        assert!(update_peer_from_status_value(&mut peer, &value));
        assert_eq!(peer.version.as_deref(), Some("0.1.6"));
        assert_eq!(peer.public_ip.as_deref(), Some("198.51.100.16"));
        assert_eq!(peer.xds_addr.as_deref(), Some("192.168.0.16:22222"));
        assert_eq!(peer.dscp, Some(40));
        assert_eq!(peer.vxlan_port, Some(4789));
        assert_eq!(
            peer.capabilities,
            vec!["ha.active_backup".to_string(), "ha.peer_token".to_string()]
        );
    }

    #[test]
    fn peer_status_refresh_ignores_unmatched_peer_identity() {
        let mut peer = GatewayHaPeer {
            name: "gateway-b".to_string(),
            underlay_ip: "192.168.0.16".to_string(),
            version: Some("0.1.3".to_string()),
            ..GatewayHaPeer::default()
        };
        let value = json!({
            "node": {
                "name": "gateway-c",
                "underlay_ip": "192.168.0.17",
                "version": "0.1.6"
            }
        });

        assert!(!update_peer_from_status_value(&mut peer, &value));
        assert_eq!(peer.version.as_deref(), Some("0.1.3"));
    }
}
