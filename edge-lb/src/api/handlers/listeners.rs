use std::{collections::HashSet, net::IpAddr};

use anyhow::bail;
use serde::{Deserialize, Serialize};

use crate::{
    api::response::Reply,
    config::{Config, LbMode, LbSelect, Listener, Protocol},
};

use super::{
    common::{paginate_json, require_gateway_role},
    proxy_config::{self, ProxyConfigOperation},
};

/// Stable control-plane representation. This is intentionally independent of
/// the native datapath representation: listeners bind target groups, while
/// backend targets and probes live under `/api/v1/target-groups`.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ListenerConfigResource {
    #[serde(default)]
    name: String,
    vip_ips: Vec<IpAddr>,
    port: u16,
    target_port: u16,
    protocols: Vec<Protocol>,
    target_group: String,
    select: LbSelect,
    inactive_timeout: Option<u32>,
}

impl From<&Listener> for ListenerConfigResource {
    fn from(value: &Listener) -> Self {
        Self {
            name: value.name.clone(),
            vip_ips: value.vip_ips.clone(),
            port: value.port,
            target_port: value.target_port,
            protocols: value.protocols.clone(),
            target_group: value.target_group.clone(),
            select: value.select,
            inactive_timeout: value.inactive_timeout,
        }
    }
}

impl From<ListenerConfigResource> for Listener {
    fn from(value: ListenerConfigResource) -> Self {
        let mut protocols = if value.protocols.is_empty() {
            vec![Protocol::Tcp]
        } else {
            value.protocols
        };
        let mut deduped_protocols = Vec::new();
        for protocol in protocols {
            if !deduped_protocols.contains(&protocol) {
                deduped_protocols.push(protocol);
            }
        }
        protocols = deduped_protocols;
        let generated_name = native_generated_listener_name(
            &protocols
                .iter()
                .map(|protocol| protocol.as_str())
                .collect::<Vec<_>>()
                .join("-"),
            value.port,
        );
        let auto_prefix = value.name.trim().starts_with("auto-");
        Self {
            name: if auto_prefix {
                format!("auto-{generated_name}")
            } else {
                generated_name
            },
            vip_ips: value.vip_ips,
            port: value.port,
            target_port: value.target_port,
            protocols,
            target_group: value.target_group,
            select: value.select,
            mode: LbMode::Default,
            inactive_timeout: value.inactive_timeout,
        }
    }
}

pub(in crate::api) fn list_configs(cfg: &Config, query: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    match persisted_listeners(cfg) {
        Ok(listeners) => Reply::json(
            200,
            paginate_json(
                listeners
                    .into_iter()
                    .map(|listener| serde_json::to_value(listener).unwrap())
                    .collect(),
                query,
            ),
        ),
        Err(e) => Reply::error(500, format!("loading listeners: {e:#}")),
    }
}

pub(in crate::api) fn export_configs(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    match persisted_listeners(cfg) {
        Ok(listeners) => Reply::json(
            200,
            serde_json::json!({ "version": 1, "listeners": listeners }),
        ),
        Err(error) => Reply::error(500, format!("loading listeners: {error:#}")),
    }
}

pub(in crate::api) fn import_configs(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        ProxyConfigOperation::ListenerImport {
            body: body.to_string(),
        },
    )
}

pub(in crate::api) fn import_configs_local(cfg: &Config, body: &str) -> Reply {
    use crate::storage::proxy_config::{Rejection, mutate};
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad listener import JSON: {e}")),
    };
    let entries = value.get("listeners").cloned().unwrap_or(value);
    let entries: Vec<ListenerConfigResource> = match serde_json::from_value(entries) {
        Ok(entries) => entries,
        Err(e) => return Reply::error(400, format!("bad listener import payload: {e}")),
    };
    let listeners: Vec<Listener> = entries.into_iter().map(Into::into).collect();
    match mutate(cfg, |state| {
        let mut names = HashSet::new();
        for listener in &listeners {
            if !names.insert(&listener.name) {
                return Err(Rejection::new(
                    400,
                    format!("duplicate listener {} in import", listener.name),
                ));
            }
            let mutation = if state
                .listeners
                .iter()
                .any(|item| item.name == listener.name)
            {
                ListenerMutation::Update(listener.name.as_str())
            } else {
                ListenerMutation::Create
            };
            edit_snapshot(cfg, state, listener, &mutation)?;
        }
        Ok(())
    }) {
        Ok(((), changed)) => {
            if changed {
                crate::provider::native::mark_state_dirty();
            }
            Reply::json(
                200,
                serde_json::json!({ "status": "imported", "count": listeners.len() }),
            )
        }
        Err(error) => proxy_config::mutation_error(error),
    }
}

pub(in crate::api) fn create_config(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        ProxyConfigOperation::ListenerCreate {
            body: body.to_string(),
        },
    )
}

pub(in crate::api) fn update_config(cfg: &Config, name: &str, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        ProxyConfigOperation::ListenerUpdate {
            name: name.to_string(),
            body: body.to_string(),
        },
    )
}

pub(in crate::api) fn delete_config(cfg: &Config, name: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        ProxyConfigOperation::ListenerDelete {
            name: name.to_string(),
        },
    )
}

fn persisted_listeners(cfg: &Config) -> anyhow::Result<Vec<ListenerConfigResource>> {
    Ok(crate::storage::proxy_config::load(cfg)?
        .listeners
        .iter()
        .map(ListenerConfigResource::from)
        .collect())
}

pub(crate) fn load_for_runtime(cfg: &Config) -> anyhow::Result<Vec<Listener>> {
    Ok(crate::storage::proxy_config::load(cfg)?.listeners)
}

enum ListenerMutation<'a> {
    Create,
    Update(&'a str),
}

fn edit_snapshot(
    cfg: &Config,
    state: &mut crate::storage::proxy_config::ProxyConfig,
    listener: &Listener,
    operation: &ListenerMutation<'_>,
) -> Result<(), crate::storage::proxy_config::Rejection> {
    use crate::storage::proxy_config::Rejection;
    let old_name = match operation {
        ListenerMutation::Create => None,
        ListenerMutation::Update(name) => {
            if !state.listeners.iter().any(|item| item.name == *name) {
                return Err(Rejection::new(404, format!("no listener {name}")));
            }
            Some(*name)
        }
    };
    validate_listener_config(
        cfg,
        listener,
        old_name,
        &state.listeners,
        &state.target_groups,
    )
    .map_err(|error| Rejection::new(400, format!("invalid listener config: {error:#}")))?;
    let mut listeners = state.listeners.clone();
    if let Some(existing) = listeners
        .iter_mut()
        .find(|item| Some(item.name.as_str()) == old_name)
    {
        *existing = listener.clone();
    } else {
        listeners.push(listener.clone());
    }
    validate_consistent_hash_listener_capacity(cfg, &listeners)
        .map_err(|error| Rejection::new(400, format!("invalid listener config: {error:#}")))?;
    state.listeners = listeners;
    Ok(())
}

fn write_listener(cfg: &Config, body: &str, operation: ListenerMutation<'_>) -> Reply {
    use crate::storage::proxy_config::mutate;
    let resource: ListenerConfigResource = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(error) => return Reply::error(400, format!("bad listener config JSON: {error}")),
    };
    let listener: Listener = resource.into();
    let result = mutate(cfg, |state| {
        edit_snapshot(cfg, state, &listener, &operation)
    });
    match result {
        Ok(((), changed)) => {
            if changed {
                crate::provider::native::mark_state_dirty();
            }
            Reply::json(
                if matches!(operation, ListenerMutation::Create) {
                    201
                } else {
                    200
                },
                serde_json::to_value(ListenerConfigResource::from(&listener)).unwrap(),
            )
        }
        Err(error) => proxy_config::mutation_error(error),
    }
}

pub(in crate::api) fn create_config_local(cfg: &Config, body: &str) -> Reply {
    write_listener(cfg, body, ListenerMutation::Create)
}

pub(in crate::api) fn update_config_local(cfg: &Config, name: &str, body: &str) -> Reply {
    write_listener(cfg, body, ListenerMutation::Update(name))
}

pub(in crate::api) fn delete_config_local(cfg: &Config, name: &str) -> Reply {
    use crate::storage::proxy_config::{Rejection, mutate};
    match mutate(cfg, |state| {
        let before = state.listeners.len();
        state.listeners.retain(|item| item.name != name);
        if state.listeners.len() == before {
            return Err(Rejection::new(404, format!("no listener {name}")));
        }
        Ok(())
    }) {
        Ok(((), changed)) => {
            if changed {
                crate::provider::native::mark_state_dirty();
            }
            Reply::json(
                200,
                serde_json::json!({ "status": "deleted", "name": name }),
            )
        }
        Err(error) => proxy_config::mutation_error(error),
    }
}

fn validate_listener_config(
    cfg: &Config,
    listener: &Listener,
    old_name: Option<&str>,
    existing: &[Listener],
    groups: &[crate::config::TargetGroup],
) -> anyhow::Result<()> {
    if listener.name.trim().is_empty() {
        bail!("listener name is required");
    }
    if listener.port == 0 {
        bail!("listener port must be in range 1..=65535");
    }
    if listener.target_port == 0 {
        bail!("listener target port must be in range 1..=65535");
    }
    if listener.protocols.is_empty() {
        bail!("listener must select at least one protocol");
    }
    if !groups
        .iter()
        .any(|group| group.name == listener.target_group)
    {
        bail!("target group {} not found", listener.target_group);
    }
    for item in existing {
        if old_name.is_some_and(|old| item.name == old) {
            continue;
        }
        if item.name == listener.name
            || listener_resource_conflicts(
                cfg,
                &ListenerConfigResource::from(item),
                &ListenerConfigResource::from(listener),
            )?
        {
            bail!(
                "listener {} conflicts with existing listener {} on port {}",
                listener.name,
                item.name,
                listener.port
            );
        }
    }
    Ok(())
}

fn validate_consistent_hash_listener_capacity(
    cfg: &Config,
    listeners: &[Listener],
) -> anyhow::Result<()> {
    let mut file = cfg.file.clone();
    file.listeners = listeners.to_vec();
    file.validate_consistent_hash_listener_capacity(|_, listener| {
        let vip_count = crate::provider::native::effective_vip_ips(cfg, &listener.vip_ips)?.len();
        let protocol_count = listener
            .protocols
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len();
        Ok(vip_count * protocol_count)
    })
}

fn native_generated_listener_name(protocol: &str, port: u16) -> String {
    format!("{protocol}-{port}")
}

fn listener_resource_conflicts(
    cfg: &Config,
    existing: &ListenerConfigResource,
    want: &ListenerConfigResource,
) -> anyhow::Result<bool> {
    if existing.port != want.port {
        return Ok(false);
    }
    if !existing
        .protocols
        .iter()
        .any(|protocol| want.protocols.contains(protocol))
    {
        return Ok(false);
    }
    let existing_ips = effective_listener_ips(cfg, existing)?;
    let want_ips = effective_listener_ips(cfg, want)?;
    Ok(existing_ips.iter().any(|ip| want_ips.contains(ip)))
}

fn effective_listener_ips(
    cfg: &Config,
    resource: &ListenerConfigResource,
) -> anyhow::Result<HashSet<IpAddr>> {
    crate::provider::native::effective_vip_ips(cfg, &resource.vip_ips)
        .map(|ips| ips.into_iter().map(IpAddr::V4).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FileConfig};
    use std::path::PathBuf;

    fn test_cfg() -> Config {
        Config {
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
            file: FileConfig::default(),
        }
    }

    fn snapshot() -> crate::storage::proxy_config::ProxyConfig {
        crate::storage::proxy_config::ProxyConfig {
            listeners: vec![],
            target_groups: vec![crate::config::TargetGroup {
                name: "web".into(),
                ..Default::default()
            }],
        }
    }

    fn test_listener(port: u16) -> Listener {
        Listener {
            name: format!("tcp-{port}"),
            port,
            target_port: 18080,
            target_group: "web".into(),
            vip_ips: vec!["192.0.2.10".parse().unwrap()],
            ..Default::default()
        }
    }

    #[test]
    fn failed_update_keeps_old_listener_and_rejects_name_collisions() {
        let cfg = test_cfg();
        let mut state = snapshot();
        edit_snapshot(
            &cfg,
            &mut state,
            &test_listener(8080),
            &ListenerMutation::Create,
        )
        .unwrap();
        edit_snapshot(
            &cfg,
            &mut state,
            &test_listener(8081),
            &ListenerMutation::Create,
        )
        .unwrap();
        let before = serde_json::to_string(&state.listeners).unwrap();
        assert!(
            edit_snapshot(
                &cfg,
                &mut state,
                &test_listener(8081),
                &ListenerMutation::Update("tcp-8080")
            )
            .is_err()
        );
        let invalid = Listener {
            target_group: "missing".into(),
            ..test_listener(8082)
        };
        assert!(
            edit_snapshot(
                &cfg,
                &mut state,
                &invalid,
                &ListenerMutation::Update("tcp-8080")
            )
            .is_err()
        );
        assert_eq!(serde_json::to_string(&state.listeners).unwrap(), before);
    }

    #[test]
    fn updating_missing_listener_is_not_an_implicit_create() {
        let mut state = snapshot();
        let error = edit_snapshot(
            &test_cfg(),
            &mut state,
            &test_listener(8080),
            &ListenerMutation::Update("missing"),
        )
        .unwrap_err();
        assert_eq!(error.status, 404);
        assert!(state.listeners.is_empty());
    }

    #[test]
    fn empty_target_group_can_back_a_listener_before_backend_registration() {
        let mut cfg = test_cfg();
        cfg.file.node_role = crate::config::NodeRole::Gateway;
        cfg.file.target_groups.push(crate::config::TargetGroup {
            name: "pending".to_string(),
            ..crate::config::TargetGroup::default()
        });
        let listener = Listener {
            name: "tcp-8080".to_string(),
            port: 8080,
            target_port: 18080,
            target_group: "pending".to_string(),
            protocols: vec![Protocol::Tcp],
            ..Listener::default()
        };

        validate_listener_config(&cfg, &listener, None, &cfg.listeners, &cfg.target_groups)
            .expect("empty target groups must not block listener creation");
    }

    #[test]
    fn listener_import_upserts_existing_names() {
        let cfg = test_cfg();
        let mut state = snapshot();
        edit_snapshot(
            &cfg,
            &mut state,
            &test_listener(8080),
            &ListenerMutation::Create,
        )
        .unwrap();
        let mut imported = test_listener(8080);
        imported.target_port = 18081;
        let listeners = vec![imported.clone()];

        for listener in &listeners {
            let mutation = if state
                .listeners
                .iter()
                .any(|item| item.name == listener.name)
            {
                ListenerMutation::Update(listener.name.as_str())
            } else {
                ListenerMutation::Create
            };
            edit_snapshot(&cfg, &mut state, listener, &mutation).unwrap();
        }

        assert_eq!(state.listeners.len(), 1);
        assert_eq!(state.listeners[0].target_port, 18081);
    }

    #[test]
    fn consistent_hash_listener_create_rejects_bucket_capacity_overflow() {
        let mut cfg = test_cfg();
        cfg.file.network.gateway_ip = "192.0.2.1".parse().unwrap();
        let mut state = snapshot();
        let max = (edge_lb_common::NATIVE_CONSISTENT_HASH_BUCKET_MAP_CAPACITY
            / edge_lb_common::NATIVE_CONSISTENT_HASH_BUCKETS) as usize;

        for offset in 0..max {
            let mut listener = test_listener(10_000 + offset as u16);
            listener.vip_ips.clear();
            listener.select = LbSelect::ConsistentHash;
            edit_snapshot(&cfg, &mut state, &listener, &ListenerMutation::Create).unwrap();
        }

        let mut overflow = test_listener(10_000 + max as u16);
        overflow.vip_ips.clear();
        overflow.select = LbSelect::ConsistentHash;
        let error =
            edit_snapshot(&cfg, &mut state, &overflow, &ListenerMutation::Create).unwrap_err();

        assert_eq!(error.status, 400);
        assert!(
            error
                .message
                .contains("consistent_hash listener expansion uses")
        );
        assert_eq!(state.listeners.len(), max);
    }

    #[test]
    fn empty_external_ip_list_preserves_automatic_vip_expansion() {
        let resource = ListenerConfigResource {
            name: String::new(),
            vip_ips: Vec::new(),
            port: 8080,
            target_port: 18080,
            protocols: vec![Protocol::Tcp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let listener: Listener = resource.into();

        assert!(listener.vip_ips.is_empty());
        assert_eq!(listener.name, "tcp-8080");
    }

    #[test]
    fn listener_name_is_always_generated_from_protocol_and_port() {
        let resource = ListenerConfigResource {
            name: "stale-name".to_string(),
            vip_ips: vec!["192.168.0.12".parse().unwrap()],
            port: 8080,
            target_port: 18080,
            protocols: vec![Protocol::Tcp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let listener: Listener = resource.into();

        assert_eq!(listener.name, "tcp-8080");
    }

    #[test]
    fn auto_listener_name_is_preserved_for_generated_listeners() {
        let resource = ListenerConfigResource {
            name: "auto-stale-name".to_string(),
            vip_ips: vec!["192.168.0.12".parse().unwrap()],
            port: 8080,
            target_port: 18080,
            protocols: vec![Protocol::Tcp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let listener: Listener = resource.into();

        assert_eq!(listener.name, "auto-tcp-8080");
    }

    #[test]
    fn listener_protocols_are_normalized_and_deduplicated() {
        let resource = ListenerConfigResource {
            name: "stale-name".to_string(),
            vip_ips: vec!["192.168.0.12".parse().unwrap()],
            port: 8080,
            target_port: 18080,
            protocols: vec![Protocol::Udp, Protocol::Tcp, Protocol::Udp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let listener: Listener = resource.into();

        assert_eq!(listener.protocols, vec![Protocol::Udp, Protocol::Tcp]);
        assert_eq!(listener.name, "udp-tcp-8080");
    }

    #[test]
    fn combined_protocol_listener_keeps_one_generated_name() {
        let resource = ListenerConfigResource {
            name: "stale-name".to_string(),
            vip_ips: vec!["192.168.0.12".parse().unwrap()],
            port: 8080,
            target_port: 18080,
            protocols: vec![Protocol::Tcp, Protocol::Udp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let listener: Listener = resource.into();

        assert_eq!(listener.protocols, vec![Protocol::Tcp, Protocol::Udp]);
        assert_eq!(listener.name, "tcp-udp-8080");
    }

    #[test]
    fn listener_conflict_uses_socket_identity_not_name_only() {
        let cfg = test_cfg();
        let resource = |port: u16| ListenerConfigResource {
            name: "tcp-80".to_string(),
            vip_ips: vec!["192.168.0.12".parse().unwrap()],
            port,
            target_port: 8080,
            protocols: vec![Protocol::Tcp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let existing = resource(80);
        let same_name_other_port = resource(81);
        let same_socket_other_name = ListenerConfigResource {
            name: "old".to_string(),
            ..resource(80)
        };

        assert!(!listener_resource_conflicts(&cfg, &existing, &same_name_other_port).unwrap());
        assert!(listener_resource_conflicts(&cfg, &existing, &same_socket_other_name).unwrap());
    }

    #[test]
    fn listener_resource_round_trip_preserves_protocols_and_empty_vips() {
        let resource = ListenerConfigResource {
            name: "tcp-udp-443".to_string(),
            vip_ips: Vec::new(),
            port: 443,
            target_port: 8443,
            protocols: vec![Protocol::Tcp, Protocol::Udp],
            target_group: "tls-targets".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };

        let listener: Listener = resource.into();
        let restored = ListenerConfigResource::from(&listener);

        assert_eq!(restored.name, "tcp-udp-443");
        assert_eq!(restored.protocols, vec![Protocol::Tcp, Protocol::Udp]);
        assert!(restored.vip_ips.is_empty());
        assert_eq!(restored.target_port, 8443);
    }
}
