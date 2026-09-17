use serde::Deserialize;
use serde_json::json;

use crate::{
    api::response::Reply,
    automation::{
        filter,
        model::{AutomationConfig, AutomationExport, AutomationTemplate, AutomationTestResult},
        store, sync, validate,
    },
    config::{BackendNode, BackendTarget, Config, TargetGroup},
    events,
    provider::native,
};

use super::common::{paginate_json, require_gateway_role};
use anyhow::{Context, bail};

#[derive(Debug, Deserialize)]
struct ImportRequest {
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    mode: ImportMode,
    #[serde(flatten)]
    config: AutomationConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ImportMode {
    #[default]
    MergeSkip,
    MergeOverwrite,
    ReplaceAll,
}

pub(in crate::api) fn list(cfg: &Config, query: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    match store::load(cfg) {
        Ok(config) => {
            let items = config
                .templates
                .into_iter()
                .map(|template| serde_json::to_value(template).unwrap())
                .collect();
            Reply::json(200, paginate_json(items, query))
        }
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn create(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    let mut template: AutomationTemplate = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad automation template JSON: {e}")),
    };
    if let Err(e) = validate::normalize_template(&mut template) {
        return Reply::error(400, format!("{e:#}"));
    }
    let config = match store::load(cfg) {
        Ok(config) => config,
        Err(e) => return Reply::error(500, format!("{e:#}")),
    };
    if config
        .templates
        .iter()
        .any(|item| item.name == template.name)
    {
        return Reply::error(409, format!("automation template {} exists", template.name));
    }
    let (config, template) = store::upsert_template(config, None, template);
    save_config_reply(cfg, config, template)
}

pub(in crate::api) fn update(cfg: &Config, name: &str, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    let mut template: AutomationTemplate = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad automation template JSON: {e}")),
    };
    if let Err(e) = validate::normalize_template(&mut template) {
        return Reply::error(400, format!("{e:#}"));
    }
    let config = match store::load(cfg) {
        Ok(config) => config,
        Err(e) => return Reply::error(500, format!("{e:#}")),
    };
    if !config.templates.iter().any(|item| item.name == name) {
        return Reply::error(404, format!("automation template {name} not found"));
    }
    if template.name != name
        && config
            .templates
            .iter()
            .any(|item| item.name == template.name)
    {
        return Reply::error(409, format!("automation template {} exists", template.name));
    }
    let (config, template) = store::upsert_template(config, Some(name), template);
    save_config_reply(cfg, config, template)
}

pub(in crate::api) fn delete(cfg: &Config, name: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    let config = match store::load(cfg) {
        Ok(config) => config,
        Err(e) => return Reply::error(500, format!("{e:#}")),
    };
    let old = config
        .templates
        .iter()
        .find(|item| item.name == name)
        .cloned();
    let (config, changed) = store::delete_template(config, name);
    if !changed {
        return Reply::error(404, format!("automation template {name} not found"));
    }
    if let Some(old) = old.as_ref()
        && matches!(
            old.remove_policy,
            crate::automation::model::RemovePolicy::Prune
        )
    {
        let target_group = validate::generated_target_group_name(old);
        let reply = super::proxy_config::apply_authoritative(
            cfg,
            super::proxy_config::ProxyConfigOperation::TargetGroupDelete {
                name: target_group.clone(),
            },
        );
        if !(200..300).contains(&reply.status) && reply.status != 404 {
            return Reply::error(
                502,
                format!(
                    "generated target group cleanup failed with HTTP {}: {}",
                    reply.status,
                    String::from_utf8_lossy(&reply.body)
                ),
            );
        }
    }
    match sync::save_authoritative(cfg, &config) {
        Ok(sync) => Reply::json(
            200,
            json!({ "status": "deleted", "name": name, "sync": sync }),
        ),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn export(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    match store::load(cfg) {
        Ok(config) => Reply::json(
            200,
            serde_json::to_value(AutomationExport {
                version: 1,
                exported_at_unix: events::now_unix(),
                templates: config.templates,
            })
            .unwrap(),
        ),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn import(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    let request: ImportRequest = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad automation import JSON: {e}")),
    };
    let incoming = match validate::normalize_config(request.config) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("{e:#}")),
    };
    let current = match store::load(cfg) {
        Ok(config) => config,
        Err(e) => return Reply::error(500, format!("{e:#}")),
    };
    let (merged, report) = merge_import(current, incoming, request.mode);
    let merged = match validate::normalize_config(merged) {
        Ok(config) => config,
        Err(e) => return Reply::error(400, format!("{e:#}")),
    };
    if request.dry_run {
        return Reply::json(200, json!({ "dry_run": true, "report": report }));
    }
    match sync::save_authoritative(cfg, &merged) {
        Ok(sync) => {
            if sync.status == "saved"
                && let Err(e) = reconcile_templates(cfg, &merged)
            {
                return Reply::error(
                    502,
                    format!("automation templates imported but reconcile failed: {e:#}"),
                );
            }
            Reply::json(
                200,
                json!({ "status": "imported", "report": report, "sync": sync }),
            )
        }
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn test(cfg: &Config, name: &str, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    let template = if body.trim().is_empty() {
        match store::template(cfg, name) {
            Ok(Some(value)) => value,
            Ok(None) => return Reply::error(404, format!("automation template {name} not found")),
            Err(e) => return Reply::error(500, format!("{e:#}")),
        }
    } else {
        match serde_json::from_str::<AutomationTemplate>(body) {
            Ok(value) => value,
            Err(e) => return Reply::error(400, format!("bad automation template JSON: {e}")),
        }
    };
    match test_template(cfg, template) {
        Ok(result) => Reply::json(200, serde_json::to_value(result).unwrap()),
        Err(e) => Reply::error(400, format!("{e:#}")),
    }
}

pub(in crate::api) fn peer_replace_active(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    let config = match parse_config(body) {
        Ok(config) => config,
        Err(reply) => return reply,
    };
    match sync::save_from_peer_active(cfg, &config) {
        Ok(sync) => {
            if let Err(e) = reconcile_templates(cfg, &config) {
                return Reply::error(
                    502,
                    format!("automation templates saved but reconcile failed: {e:#}"),
                );
            }
            Reply::json(200, json!({ "status": "saved", "sync": sync }))
        }
        Err(e) => Reply::error(409, format!("{e:#}")),
    }
}

pub(in crate::api) fn peer_replace_replica(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    let config = match parse_config(body) {
        Ok(config) => config,
        Err(reply) => return reply,
    };
    match sync::save_from_peer_replica(cfg, &config) {
        Ok(sync) => Reply::json(200, json!({ "status": "saved", "sync": sync })),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(crate) fn reconcile_saved_templates(cfg: &Config) -> anyhow::Result<bool> {
    let config = store::load(cfg)?;
    reconcile_templates(cfg, &config)
}

fn save_config_reply(
    cfg: &Config,
    config: AutomationConfig,
    template: AutomationTemplate,
) -> Reply {
    let config = match validate::normalize_config(config) {
        Ok(config) => config,
        Err(e) => return Reply::error(400, format!("{e:#}")),
    };
    match sync::save_authoritative(cfg, &config) {
        Ok(sync) => {
            if sync.status == "saved"
                && let Err(e) = reconcile_templates(cfg, &config)
            {
                return Reply::error(
                    502,
                    format!("automation template saved but reconcile failed: {e:#}"),
                );
            }
            let mut value = serde_json::to_value(template).unwrap();
            if let serde_json::Value::Object(map) = &mut value {
                map.insert("sync".to_string(), serde_json::to_value(sync).unwrap());
            }
            Reply::json(200, value)
        }
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

fn parse_config(body: &str) -> Result<AutomationConfig, Reply> {
    let config: AutomationConfig = serde_json::from_str(body)
        .map_err(|e| Reply::error(400, format!("bad automation config JSON: {e}")))?;
    validate::normalize_config(config).map_err(|e| Reply::error(400, format!("{e:#}")))
}

fn test_template(
    cfg: &Config,
    mut template: AutomationTemplate,
) -> anyhow::Result<AutomationTestResult> {
    validate::normalize_template(&mut template)?;
    let nodes = automation_nodes(cfg);
    let matched = filter::matched_nodes(&template, &nodes);
    let mut planned = filter::plan_template(&template, &nodes);
    planned.targets = matched.clone();
    Ok(AutomationTestResult {
        template: template.name,
        planned: vec![planned],
        matched_nodes: matched,
        conflicts: Vec::new(),
        errors: Vec::new(),
    })
}

fn automation_nodes(cfg: &Config) -> Vec<crate::automation::model::MatchedNode> {
    let subscriptions =
        crate::control::active_backend_subscriptions_status().unwrap_or_else(|_| json!({}));
    let canonical_backends = cfg.backend_nodes_effective();
    crate::control::active_backend_nodes(cfg)
        .unwrap_or_else(|e| {
            tracing::warn!("[automation] active backend node lookup skipped: {e:#}");
            Vec::new()
        })
        .into_iter()
        .filter_map(|node| {
            let sub = subscription_for_backend(&subscriptions, &node);
            let name = canonical_backend_name(&canonical_backends, &node)
                .unwrap_or_else(|| node.name.clone());
            filter::matched_node_from_backend(
                name,
                node.public_ip,
                node.underlay_ip,
                sub.and_then(|s| s.get("public_ip_source"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                sub.and_then(|s| s.get("underlay_ip_source"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            )
        })
        .collect()
}

fn subscription_for_backend<'a>(
    subscriptions: &'a serde_json::Value,
    node: &BackendNode,
) -> Option<&'a serde_json::Value> {
    let subs = subscriptions.as_object()?;
    subs.get(&node.name).or_else(|| {
        let underlay = node.underlay_ip.to_string();
        subs.values().find(|sub| {
            sub.get("underlay_ip")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value == underlay)
        })
    })
}

fn canonical_backend_name(backends: &[BackendNode], node: &BackendNode) -> Option<String> {
    backends
        .iter()
        .find(|backend| backend.name == node.name)
        .or_else(|| {
            backends
                .iter()
                .find(|backend| backend.underlay_ip == node.underlay_ip)
        })
        .or_else(|| {
            (!node.public_ip.is_unspecified())
                .then(|| {
                    backends
                        .iter()
                        .find(|backend| backend.public_ip == node.public_ip)
                })
                .flatten()
        })
        .map(|backend| backend.name.clone())
}

fn reconcile_templates(cfg: &Config, config: &AutomationConfig) -> anyhow::Result<bool> {
    let current_groups = crate::provider::native::target_groups_native(cfg).unwrap_or_default();
    let mut applied = false;
    for template in config.templates.iter().filter(|template| template.enabled) {
        let group = planned_target_group(cfg, template)
            .with_context(|| format!("building target group payload for {}", template.name))?;
        if group.targets.is_empty() {
            tracing::info!(
                "[automation] template {} matched no backend nodes; keeping target group {}",
                template.name,
                group.name
            );
        }
        if current_groups.iter().any(|current| current == &group) {
            tracing::debug!(
                "[automation] generated target group {} already matches",
                group.name
            );
            continue;
        }
        let group_body = serde_json::to_string(&group).context("serializing target group")?;
        let group_reply = super::proxy_config::apply_authoritative(
            cfg,
            super::proxy_config::ProxyConfigOperation::TargetGroupCreate { body: group_body },
        );
        if !(200..300).contains(&group_reply.status) {
            bail!(
                "reconciling generated target group {} failed with HTTP {}: {}",
                group.name,
                group_reply.status,
                String::from_utf8_lossy(&group_reply.body)
            );
        }
        tracing::info!(
            "[automation] reconciled generated target group {}",
            group.name
        );
        applied = true;
    }
    Ok(applied)
}

fn planned_target_group(
    cfg: &Config,
    template: &AutomationTemplate,
) -> anyhow::Result<TargetGroup> {
    let nodes = automation_nodes(cfg);
    let existing = native::target_groups_native(cfg)?
        .into_iter()
        .find(|group| group.name == validate::generated_target_group_name(template));
    planned_target_group_for_nodes(template, &nodes, existing.as_ref())
}

fn planned_target_group_for_nodes(
    template: &AutomationTemplate,
    nodes: &[crate::automation::model::MatchedNode],
    existing: Option<&TargetGroup>,
) -> anyhow::Result<TargetGroup> {
    let targets = filter::matched_nodes(template, nodes);
    let probe_type = template
        .target_group
        .probe_type
        .as_deref()
        .filter(|value| !value.eq_ignore_ascii_case("none"))
        .map(str::to_ascii_lowercase);
    let probe_port = if matches!(probe_type.as_deref(), Some("ping")) {
        None
    } else {
        template.target_group.probe_port
    };
    let payload_probe = matches!(
        probe_type.as_deref(),
        Some("tcp" | "udp" | "http" | "https")
    );
    Ok(TargetGroup {
        name: validate::generated_target_group_name(template),
        monitor: template.target_group.monitor && probe_type.is_some(),
        probe_type: probe_type.clone(),
        probe_port,
        probe_req: payload_probe
            .then(|| template.target_group.probe_req.clone())
            .flatten(),
        probe_resp: payload_probe
            .then(|| template.target_group.probe_resp.clone())
            .flatten(),
        probe_skip_tls_verify: template.target_group.probe_skip_tls_verify
            && matches!(probe_type.as_deref(), Some("https")),
        period_secs: template.target_group.period_secs,
        retries: template.target_group.retries,
        targets: targets
            .into_iter()
            .map(|node| {
                let address = node.underlay_ip.parse()?;
                let old = existing.as_ref().and_then(|group| {
                    group
                        .targets
                        .iter()
                        .find(|target| target.address == address)
                });
                Ok::<BackendTarget, anyhow::Error>(BackendTarget {
                    backend: Some(node.name),
                    address,
                    weight: old.map(|target| target.weight).unwrap_or(1),
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn merge_import(
    current: AutomationConfig,
    incoming: AutomationConfig,
    mode: ImportMode,
) -> (AutomationConfig, serde_json::Value) {
    if matches!(mode, ImportMode::ReplaceAll) {
        let names = incoming
            .templates
            .iter()
            .map(|item| item.name.clone())
            .collect::<Vec<_>>();
        return (
            incoming,
            json!({ "created": names, "updated": [], "skipped": [] }),
        );
    }

    let mut merged = current;
    let mut created = Vec::new();
    let mut updated = Vec::new();
    let mut skipped = Vec::new();
    for template in incoming.templates {
        if let Some(existing) = merged
            .templates
            .iter_mut()
            .find(|item| item.name == template.name)
        {
            if matches!(mode, ImportMode::MergeOverwrite) {
                *existing = template.clone();
                updated.push(template.name);
            } else {
                skipped.push(template.name);
            }
        } else {
            created.push(template.name.clone());
            merged.templates.push(template);
        }
    }
    (
        merged,
        json!({ "created": created, "updated": updated, "skipped": skipped }),
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        automation::model::AutomationTemplate,
        config::{BackendNode, BackendTarget, TargetGroup},
    };

    #[test]
    fn empty_match_removes_offline_targets_but_keeps_the_group() {
        let mut template = AutomationTemplate::default();
        template.target_group.name = "service-targets".to_string();
        let current = TargetGroup {
            name: "service-targets".to_string(),
            targets: vec![BackendTarget {
                backend: None,
                address: "192.0.2.13".parse().unwrap(),
                weight: 2,
            }],
            ..TargetGroup::default()
        };
        let planned =
            super::planned_target_group_for_nodes(&template, &[], Some(&current)).unwrap();
        assert_eq!(planned.name, current.name);
        assert!(planned.targets.is_empty());
    }

    #[test]
    fn empty_match_creates_a_bindable_empty_group() {
        let mut template = AutomationTemplate::default();
        template.target_group.name = "new-targets".to_string();
        let planned = super::planned_target_group_for_nodes(&template, &[], None).unwrap();
        assert_eq!(planned.name, "new-targets");
        assert!(planned.targets.is_empty());
    }

    #[test]
    fn automation_backend_identity_uses_configured_backend_name() {
        let configured = vec![BackendNode {
            name: "192.168.0.13".to_string(),
            public_ip: "43.162.213.70".parse().unwrap(),
            underlay_ip: "192.168.0.13".parse().unwrap(),
            overlay_ip: "10.255.15.2/24".to_string(),
        }];
        let subscribed = BackendNode {
            name: "VM-0-13-ubuntu".to_string(),
            public_ip: "43.162.213.70".parse().unwrap(),
            underlay_ip: "192.168.0.13".parse().unwrap(),
            overlay_ip: "auto".to_string(),
        };

        assert_eq!(
            super::canonical_backend_name(&configured, &subscribed).as_deref(),
            Some("192.168.0.13")
        );
    }
}
