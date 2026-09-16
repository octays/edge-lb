//! Agent configuration, organized by role:
//!
//! ```toml
//! node_role = "gateway"            # gateway | backend
//! [discovery]                      # local IP/device discovery
//! [gateway.reconcile]              # gateway reconcile interval
//! [gateway.xds]                    # gateway control-plane listener
//! [gateway.network]                # overlay/VXLAN/DSCP source
//! [gateway.api]                    # gateway UI/API listener
//! [gateway.metrics]                # gateway-only Prometheus metrics listener
//! Runtime gateway/backend inventory is derived from local identity and xDS.
//! Listener and target-group proxy config is persisted by the native datapath.
//! [backend.xds]                    # backend control-plane subscription
//! [backend.return_path]            # backend nft/route settings
//! ```
//!
//! Resolution order: built-in defaults -> config file -> CLI overrides.
//! API/UI saves use [`FileConfig::render_user_toml`] so runtime inventory and
//! derived datapath projections are not written back to disk.

use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};

mod defaults;
mod model;
mod normalize;
mod overlay;
mod render;
mod return_contract;
mod validate;

#[allow(unused_imports)]
pub use model::{
    ActiveSource, ApiConfig, BackendConfig, BackendControlConfig, BackendNode,
    BackendReturnPathConfig, BackendTarget, BackendXdsConfig, ControlPlaneConfig, ControlPlaneMode,
    DeviceDiscoveryRuntime, EDGE_MARK_BASE, EDGE_TABLE_BASE, FileConfig, GatewayConfig,
    GatewayFlowPersistenceConfig, GatewayMetricsConfig, GatewayNode, GatewayReconcileConfig,
    GatewayReturnPath, GatewayXdsConfig, HaConfig, IpDiscoveryConfig, IpDiscoveryRuntime, LbMode,
    LbSelect, Listener, NetworkConfig, NodeRole, Protocol, RuntimeDiscovery, TargetGroup,
    gateway_slot, return_mark, return_table_id,
};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/edge-lb/config.toml";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/edge-lb";
pub const DEFAULT_LISTEN: &str = "127.0.0.1:18080";
pub const DEFAULT_GATEWAY_VXLAN_DEV: &str = "edge-hub";
pub const DEFAULT_BACKEND_VXLAN_DEV: &str = "edge-return";
pub const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/edge-lb";

impl FileConfig {
    /// Normalize role sections, defaults and runtime projections after
    /// deserialization or local discovery.
    pub fn normalize(&mut self) {
        self.normalize_config();
    }

    /// Load the config file if it exists; `None` when it is absent.
    pub fn load_file(path: &Path) -> Result<Option<Self>> {
        match fs::read_to_string(path) {
            Ok(text) => {
                let mut cfg: Self = toml::from_str(&text)
                    .with_context(|| format!("failed to parse {}", path.display()))?;
                cfg.normalize_config();
                Ok(Some(cfg))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow!("failed to read {}: {e}", path.display())),
        }
    }

    /// Validate invariants shared by every command.
    pub fn validate(&self) -> Result<()> {
        validate::validate(self)
    }

    pub(crate) fn validate_consistent_hash_listener_capacity(
        &self,
        listener_expansion_count: impl FnMut(&FileConfig, &Listener) -> Result<usize>,
    ) -> Result<()> {
        validate::validate_consistent_hash_listener_capacity(self, listener_expansion_count)
    }

    fn normalize_config(&mut self) {
        normalize::normalize_config(self);
    }

    pub fn resolve_backend_target_address(&self, target: &BackendTarget) -> IpAddr {
        // Service identity is independent of the VXLAN return-path address.
        if !target.address.is_unspecified() {
            return target.address;
        }
        let backends = self.backend_nodes_effective();
        target
            .backend
            .as_ref()
            .and_then(|name| {
                backends
                    .iter()
                    .find(|backend| &backend.name == name)
                    .map(|backend| backend.underlay_ip)
            })
            .unwrap_or(target.address)
    }

    pub fn resolve_backend_probe_address(&self, target: &BackendTarget) -> IpAddr {
        self.resolve_backend_target_address(target)
    }

    pub(crate) fn validate_backend_return_paths(&self) -> Result<()> {
        return_contract::validate(&self.backend_return_paths())
    }

    pub fn backend_return_paths(&self) -> Vec<GatewayReturnPath> {
        if !self.backend_return_paths.is_empty() {
            return dedup_gateway_return_paths(self.backend_return_paths.clone());
        }
        let backend_overlay_ip = self.local_backend().ok().map(|backend| backend.overlay_ip);
        let mut paths = Vec::new();
        for gateway in &self.gateway_nodes {
            let Ok(gateway_overlay_ip) = parse_overlay_host(&gateway.overlay_ip) else {
                continue;
            };
            let slot = gateway_slot(&self.gateway_nodes, gateway.underlay_ip);
            let dscp = self.network.dscp;
            paths.push(GatewayReturnPath {
                gateway: Some(gateway.name.clone()),
                gateway_underlay_ip: gateway.underlay_ip,
                gateway_overlay_ip,
                backend_overlay_ip: backend_overlay_ip.clone(),
                dscp,
                mark: return_mark(dscp, slot),
                route_table_id: return_table_id(dscp, slot),
            });
        }
        dedup_gateway_return_paths(paths)
    }

    /// Effective backend inventory from xDS or local single-node settings.
    pub fn backend_nodes_effective(&self) -> Vec<BackendNode> {
        if !self.backend_nodes.is_empty() {
            return self.backend_nodes.clone();
        }
        match (self.network.backend_public_ip, self.network.backend_ip) {
            (Some(public_ip), Some(underlay_ip)) => vec![BackendNode {
                name: self.node_name.clone(),
                public_ip,
                underlay_ip,
                overlay_ip: self.backend.overlay_ip.clone(),
            }],
            _ => Vec::new(),
        }
    }

    /// Backend matching this node name, or the first configured backend for
    /// single-backend installs.
    pub fn local_backend(&self) -> Result<BackendNode> {
        let backends = self.backend_nodes_effective();
        backends
            .iter()
            .find(|b| b.name == self.node_name)
            .or_else(|| backends.first())
            .cloned()
            .ok_or_else(|| anyhow!("no backend nodes configured"))
    }

    pub fn backend_by_underlay(&self, underlay: IpAddr) -> Option<BackendNode> {
        self.backend_nodes_effective()
            .into_iter()
            .find(|b| b.underlay_ip == underlay)
    }

    /// Resolve the gateway the return path should target right now.
    ///
    /// Resolve the active gateway from the SQLite HA runtime resource. The
    /// file-based active-gateway input is no longer used in production.
    pub fn active_gateway(&self) -> Result<GatewayNode> {
        let mut gateways = self.gateway_nodes.clone();
        if self.node_role == NodeRole::Gateway
            && let Ok(ha) = crate::runtime::ha::load_for_state_dir(&self.state_dir)
        {
            for peer in ha.peers {
                let Ok(underlay_ip) = peer.underlay_ip.parse() else {
                    continue;
                };
                if gateways
                    .iter()
                    .any(|gateway| gateway.name == peer.name || gateway.underlay_ip == underlay_ip)
                {
                    continue;
                }
                gateways.push(GatewayNode {
                    name: peer.name,
                    public_ip: peer
                        .public_ip
                        .as_deref()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(underlay_ip),
                    underlay_ip,
                    overlay_ip: peer
                        .overlay_ip
                        .unwrap_or_else(|| self.gateway.overlay_ip.clone()),
                });
            }
        }
        let pick = |key: &str| -> Option<GatewayNode> {
            gateways
                .iter()
                .find(|g| g.name == key || g.underlay_ip.to_string() == key)
                .cloned()
        };
        if matches!(self.ha.active_source, ActiveSource::Xds) {
            return gateways
                .iter()
                .find(|g| g.underlay_ip == self.network.gateway_ip)
                .or_else(|| gateways.first())
                .cloned()
                .ok_or_else(|| anyhow!("no gateway nodes configured"));
        }
        #[cfg(not(test))]
        let active_key = crate::storage::repository()?
            .get("ha_active_gateway", "current")?
            .map(|value| value.trim().to_string());
        #[cfg(test)]
        let active_key = fs::read_to_string(&self.ha.active_state_file)
            .ok()
            .map(|text| text.trim().to_string());
        if let Some(key) = active_key.as_deref().filter(|key| !key.is_empty()) {
            if let Some(gw) = pick(key) {
                return Ok(gw);
            }
            let fallback = gateways
                .iter()
                .find(|g| g.underlay_ip == self.network.gateway_ip)
                .or_else(|| gateways.first())
                .cloned();
            if let Some(gw) = fallback {
                tracing::warn!(
                    "SQLite active gateway references unknown gateway {:?}; using {}",
                    key,
                    gw.name
                );
                return Ok(gw);
            }
        }
        gateways
            .iter()
            .find(|g| g.underlay_ip == self.network.gateway_ip)
            .or_else(|| gateways.first())
            .cloned()
            .ok_or_else(|| anyhow!("no gateway nodes configured"))
    }

    /// Gateway matching the given name or underlay IP (failover target).
    pub fn gateway_by_key(&self, key: &str) -> Option<&GatewayNode> {
        self.gateway_nodes
            .iter()
            .find(|g| g.name == key || g.underlay_ip.to_string() == key)
    }

    /// Persist the active gateway selection in SQLite.
    #[track_caller]
    pub fn write_active_gateway(&self, key: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let caller = std::panic::Location::caller();
            tracing::info!(
                "[ha] writing active gateway selection key={} local_node={} caller={}:{}",
                key,
                self.node_name,
                caller.file(),
                caller.line()
            );
            crate::storage::repository()?.put(
                "ha_active_gateway",
                "current",
                crate::storage::next_revision(),
                format!("{key}\n"),
            )?;
            Ok(())
        }

        #[cfg(test)]
        {
            let path = &self.ha.active_state_file;
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir)
                    .with_context(|| format!("failed to create {}", dir.display()))?;
            }
            let tmp = path.with_extension("tmp");
            fs::write(&tmp, format!("{key}\n"))
                .with_context(|| format!("failed to write {}", tmp.display()))?;
            fs::rename(&tmp, path)
                .with_context(|| format!("failed to replace {}", path.display()))?;
            Ok(())
        }
    }

    pub fn active_gateway_revision(&self) -> Result<Option<i64>> {
        #[cfg(not(test))]
        {
            Ok(crate::storage::repository()?
                .get_document("ha_active_gateway", "current")?
                .map(|document| document.revision))
        }

        #[cfg(test)]
        {
            Ok(None)
        }
    }

    /// Persist to `path` via temp file + atomic rename.
    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        self.save_user_atomic(path)
    }

    /// Persist the user-facing TOML model. Runtime inventory and derived
    /// datapath projections are intentionally omitted.
    pub fn save_user_atomic(&self, path: &Path) -> Result<()> {
        self.save_text(path, self.render_user_toml())
    }

    /// Write `text` to `path` via temp file + atomic rename.
    pub fn save_text(&self, path: &Path, text: String) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, text).with_context(|| format!("failed to write {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("failed to replace {}", path.display()))?;
        Ok(())
    }

    /// Current user-facing TOML model used by API/UI saves.
    pub fn render_user_toml(&self) -> String {
        render::render_user_toml(self)
    }
}

fn dedup_gateway_return_paths(mut paths: Vec<GatewayReturnPath>) -> Vec<GatewayReturnPath> {
    paths.sort_by_key(|path| {
        (
            path.gateway_underlay_ip,
            path.gateway_overlay_ip,
            path.dscp,
            path.mark,
            path.route_table_id,
            path.gateway.clone().unwrap_or_default(),
        )
    });
    paths.dedup_by(|a, b| {
        a.gateway_underlay_ip == b.gateway_underlay_ip
            && a.gateway_overlay_ip == b.gateway_overlay_ip
            && a.dscp == b.dscp
            && a.mark == b.mark
            && a.route_table_id == b.route_table_id
    });
    paths
}

fn parse_overlay_host(value: &str) -> Result<IpAddr> {
    value
        .split('/')
        .next()
        .unwrap_or(value.trim())
        .parse()
        .with_context(|| format!("bad overlay_ip {value:?}"))
}

/// Effective configuration after layering CLI overrides on the file config.
#[derive(Debug, Clone)]
pub struct Config {
    pub file: FileConfig,
    /// Path the file was loaded from (or the default path).
    pub path: PathBuf,
}

impl Config {
    pub fn network(&self) -> &NetworkConfig {
        &self.file.network
    }

    pub fn backend_cfg(&self) -> &BackendConfig {
        &self.file.backend
    }

    pub fn gateway_cfg(&self) -> &GatewayConfig {
        &self.file.gateway
    }

    pub fn pin_dir(&self) -> PathBuf {
        PathBuf::from(DEFAULT_PIN_DIR)
    }

    /// Overlay gateway address without prefix (next-hop for backend routes).
    pub fn gateway_overlay_ip(&self) -> Result<IpAddr> {
        let gw = self.file.active_gateway()?;
        let ip = gw
            .overlay_ip
            .split('/')
            .next()
            .unwrap_or(gw.overlay_ip.trim());
        ip.parse()
            .with_context(|| format!("bad gateway overlay_ip {}", gw.overlay_ip))
    }
}

impl std::ops::Deref for Config {
    type Target = FileConfig;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xds_backend_bootstrap_allows_empty_proxy_config() {
        let mut file = FileConfig {
            node_role: NodeRole::Backend,
            ..FileConfig::default()
        };
        file.ha.active_source = ActiveSource::Xds;
        file.control_plane.enabled = true;
        file.control_plane.mode = ControlPlaneMode::Xds;
        file.control_plane.listen = "127.0.0.1:22222".to_string();
        file.network.underlay_dev = "eth0".to_string();
        file.normalize();

        file.validate().expect("xDS bootstrap config is valid");
    }

    #[test]
    fn native_datapath_accepts_default_dnat_listener() {
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            public_ip: "198.51.100.10".parse().unwrap(),
            underlay_ip: "192.0.2.10".parse().unwrap(),
            ..FileConfig::default()
        };
        file.network.underlay_dev = "eth0".to_string();
        file.network.gateway_ip = "192.0.2.10".parse().unwrap();
        file.network.gateway_public_ip = "198.51.100.10".parse().unwrap();
        file.network.backend_ip = Some("192.0.2.20".parse().unwrap());
        file.network.backend_public_ip = Some("198.51.100.20".parse().unwrap());
        file.backend_nodes.push(BackendNode {
            name: "backend-1".to_string(),
            public_ip: "198.51.100.20".parse().unwrap(),
            underlay_ip: "192.0.2.20".parse().unwrap(),
            overlay_ip: "10.255.255.2/24".to_string(),
        });
        file.target_groups.push(TargetGroup {
            name: "tcp-8080-targets".to_string(),
            targets: vec![BackendTarget {
                backend: Some("backend-1".to_string()),
                address: "192.0.2.20".parse().unwrap(),
                weight: 1,
            }],
            ..TargetGroup::default()
        });
        file.listeners.push(Listener {
            name: "tcp-8080".to_string(),
            port: 8080,
            target_port: 18080,
            target_group: "tcp-8080-targets".to_string(),
            protocols: vec![Protocol::Tcp],
            mode: LbMode::Default,
            ..Listener::default()
        });
        file.normalize();

        file.validate()
            .expect("native default DNAT listener should be valid");
    }

    #[test]
    fn native_backend_targets_preserve_service_addresses() {
        let mut file = FileConfig::default();
        file.backend_nodes.push(BackendNode {
            name: "backend-1".to_string(),
            public_ip: "198.51.100.20".parse().unwrap(),
            underlay_ip: "192.0.2.20".parse().unwrap(),
            overlay_ip: "10.255.255.2/24".to_string(),
        });
        let cfg = Config {
            file,
            path: DEFAULT_CONFIG_PATH.into(),
        };

        assert_eq!(
            cfg.resolve_backend_target_address(&BackendTarget {
                backend: Some("backend-1".to_string()),
                address: "192.0.2.20".parse().unwrap(),
                weight: 1,
            }),
            "192.0.2.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            cfg.resolve_backend_target_address(&BackendTarget {
                backend: None,
                address: "192.0.2.20".parse().unwrap(),
                weight: 1,
            }),
            "192.0.2.20".parse::<IpAddr>().unwrap()
        );
        for (backend, address, expected) in [
            (Some("backend-1"), "0.0.0.0", "192.0.2.20"),
            (Some("backend-1"), "192.0.2.99", "192.0.2.99"),
            (Some("backend-1"), "10.255.255.2", "10.255.255.2"),
            (None, "192.0.2.99", "192.0.2.99"),
            (Some("missing"), "0.0.0.0", "0.0.0.0"),
        ] {
            let target = BackendTarget {
                backend: backend.map(str::to_owned),
                address: address.parse().unwrap(),
                weight: 1,
            };
            let expected: IpAddr = expected.parse().unwrap();
            assert_eq!(cfg.resolve_backend_target_address(&target), expected);
            assert_eq!(cfg.resolve_backend_probe_address(&target), expected);
        }
    }

    #[test]
    fn backend_probe_address_uses_underlay_address() {
        let mut file = FileConfig::default();
        file.backend_nodes.push(BackendNode {
            name: "backend-1".to_string(),
            public_ip: "198.51.100.20".parse().unwrap(),
            underlay_ip: "192.0.2.20".parse().unwrap(),
            overlay_ip: "10.255.255.2/24".to_string(),
        });
        let cfg = Config {
            file,
            path: DEFAULT_CONFIG_PATH.into(),
        };

        assert_eq!(
            cfg.resolve_backend_probe_address(&BackendTarget {
                backend: Some("backend-1".to_string()),
                address: "192.0.2.20".parse().unwrap(),
                weight: 1,
            }),
            "192.0.2.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            cfg.resolve_backend_probe_address(&BackendTarget {
                backend: Some("backend-1".to_string()),
                address: "0.0.0.0".parse().unwrap(),
                weight: 1,
            }),
            "192.0.2.20".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn lb_select_uses_consistent_hash_wire_name() {
        assert_eq!(
            serde_json::from_str::<LbSelect>("\"consistent_hash\"").unwrap(),
            LbSelect::ConsistentHash
        );
        assert_eq!(
            serde_json::to_string(&LbSelect::ConsistentHash).unwrap(),
            "\"consistent_hash\""
        );
        assert!(serde_json::from_str::<LbSelect>("\"consistenthash\"").is_err());
    }

    #[test]
    fn vxlan_mtu_accepts_auto_string() {
        let mut file: FileConfig = toml::from_str(
            r#"
node_role = "gateway"

[gateway.network]
vxlan_mtu = "auto"
"#,
        )
        .expect("config parses");
        file.normalize();

        assert_eq!(file.network.vxlan_mtu, 0);
        assert!(file.network.vxlan_mtu_auto);
    }

    #[test]
    fn discovery_accepts_multiple_stun_servers() {
        let mut file: FileConfig = toml::from_str(
            r#"
node_role = "backend"

[discovery]
stun_servers = [" stun.example.test:3478 ", "stun.backup.test:3478"]
"#,
        )
        .expect("multiple STUN servers parse");
        file.normalize();
        assert_eq!(
            file.discovery.stun_servers,
            [
                "stun.example.test:3478".to_string(),
                "stun.backup.test:3478".to_string()
            ]
        );
        let rendered = file.render_user_toml();
        assert!(rendered.contains("stun_servers = ["));
        assert!(!rendered.contains("stun_server = "));
    }

    #[test]
    fn overlay_ips_are_assigned_from_overlay_cidr() {
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            node_name: "gateway-a".to_string(),
            network: NetworkConfig {
                overlay_cidr: "10.44.0.0/24".to_string(),
                underlay_dev: "eth0".to_string(),
                ..NetworkConfig::default()
            },
            gateway_nodes: vec![GatewayNode {
                name: "gateway-a".to_string(),
                public_ip: "203.0.113.10".parse().unwrap(),
                underlay_ip: "192.0.2.11".parse().unwrap(),
                overlay_ip: "auto".to_string(),
            }],
            backend_nodes: vec![
                BackendNode {
                    name: "backend-1".to_string(),
                    public_ip: "198.51.100.20".parse().unwrap(),
                    underlay_ip: "192.0.2.22".parse().unwrap(),
                    overlay_ip: "auto".to_string(),
                },
                BackendNode {
                    name: "backend-2".to_string(),
                    public_ip: "198.51.100.21".parse().unwrap(),
                    underlay_ip: "192.0.2.23".parse().unwrap(),
                    overlay_ip: "auto".to_string(),
                },
            ],
            ..FileConfig::default()
        };
        file.normalize();

        assert_eq!(file.gateway.overlay_ip, "10.44.0.1/24");
        assert_eq!(file.gateway_nodes[0].overlay_ip, "10.44.0.1/24");
        assert_eq!(file.backend_nodes[0].overlay_ip, "10.44.0.2/24");
        assert_eq!(file.backend_nodes[1].overlay_ip, "10.44.0.3/24");
        file.validate().expect("assigned overlay config is valid");
    }

    #[test]
    fn duplicate_backend_overlay_ips_are_reassigned() {
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            node_name: "gateway-a".to_string(),
            network: NetworkConfig {
                overlay_cidr: "10.44.0.0/24".to_string(),
                underlay_dev: "eth0".to_string(),
                ..NetworkConfig::default()
            },
            gateway_nodes: vec![GatewayNode {
                name: "gateway-a".to_string(),
                public_ip: "203.0.113.10".parse().unwrap(),
                underlay_ip: "192.0.2.11".parse().unwrap(),
                overlay_ip: "10.44.0.1/24".to_string(),
            }],
            backend_nodes: vec![
                BackendNode {
                    name: "backend-1".to_string(),
                    public_ip: "198.51.100.20".parse().unwrap(),
                    underlay_ip: "192.0.2.22".parse().unwrap(),
                    overlay_ip: "10.44.0.2/24".to_string(),
                },
                BackendNode {
                    name: "backend-2".to_string(),
                    public_ip: "198.51.100.21".parse().unwrap(),
                    underlay_ip: "192.0.2.23".parse().unwrap(),
                    overlay_ip: "10.44.0.2/24".to_string(),
                },
            ],
            ..FileConfig::default()
        };
        file.normalize();

        assert_eq!(file.backend_nodes[0].overlay_ip, "10.44.0.2/24");
        assert_eq!(file.backend_nodes[1].overlay_ip, "10.44.0.3/24");
        file.validate()
            .expect("deduplicated overlay config is valid");
    }

    #[test]
    fn user_toml_omits_proxy_config() {
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            node_name: "gateway-a".to_string(),
            target_groups: vec![TargetGroup {
                name: "api-targets".to_string(),
                monitor: true,
                probe_type: Some("http".to_string()),
                probe_port: Some(8080),
                probe_req: Some("/health".to_string()),
                probe_resp: None,
                probe_status: None,
                probe_skip_tls_verify: false,
                period_secs: Some(10),
                retries: Some(2),
                targets: vec![BackendTarget {
                    backend: Some("backend-1".to_string()),
                    address: "0.0.0.0".parse().unwrap(),
                    weight: 1,
                }],
            }],
            listeners: vec![Listener {
                name: "api".to_string(),
                port: 80,
                target_group: "api-targets".to_string(),
                protocols: vec![Protocol::Tcp],
                ..Listener::default()
            }],
            ..FileConfig::default()
        };
        file.normalize();

        let text = file.render_user_toml();
        assert!(text.contains("[gateway.reconcile]"));
        assert!(!text.contains("[gateway.active]"));
        assert!(!text.contains("[gateway.ha]"));
        assert!(!text.contains("[[target_groups]]"));
        assert!(!text.contains("[[listeners]]"));
        assert!(!text.contains("[[services]]"));
        assert!(!text.contains("[[gateway_nodes]]"));
        assert!(!text.contains("[[backend_nodes]]"));

        let mut parsed: FileConfig = toml::from_str(&text).expect("rendered TOML parses");
        parsed.normalize();
        assert!(parsed.listeners.is_empty());
        assert!(parsed.target_groups.is_empty());
    }

    #[test]
    fn user_toml_omits_derived_backend_return_identifiers() {
        let mut file = FileConfig {
            node_role: NodeRole::Backend,
            ..FileConfig::default()
        };
        file.normalize();

        let text = file.render_user_toml();
        assert!(text.contains("[backend.return_path]"));
        assert!(!text.contains("ct_mark"));
        assert!(!text.contains("fwmark"));
        assert!(!text.contains("route_table_id"));
        assert!(!text.contains("rule_priority"));
    }

    #[test]
    fn active_state_file_is_not_rendered_user_config() {
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            state_dir: PathBuf::from("/tmp/edge-lb-state"),
            ..FileConfig::default()
        };
        file.normalize();

        assert!(!file.render_user_toml().contains("active_state_file"));
        assert!(!file.render_user_toml().contains("active-gateway"));
    }

    #[test]
    fn xds_active_gateway_ignores_local_active_state_file() {
        let dir = std::env::temp_dir().join(format!(
            "edge-lb-xds-active-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let active_file = dir.join("active-gateway");
        fs::write(&active_file, "gateway-a\n").unwrap();
        let cfg = Config {
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
            file: FileConfig {
                ha: HaConfig {
                    active_source: ActiveSource::Xds,
                    active_state_file: active_file,
                    ..HaConfig::default()
                },
                network: NetworkConfig {
                    gateway_ip: "192.0.2.16".parse().unwrap(),
                    ..NetworkConfig::default()
                },
                gateway_nodes: vec![
                    GatewayNode {
                        name: "gateway-a".to_string(),
                        public_ip: "203.0.113.10".parse().unwrap(),
                        underlay_ip: "192.0.2.11".parse().unwrap(),
                        overlay_ip: "10.255.12.1/24".to_string(),
                    },
                    GatewayNode {
                        name: "gateway-b".to_string(),
                        public_ip: "203.0.113.11".parse().unwrap(),
                        underlay_ip: "192.0.2.16".parse().unwrap(),
                        overlay_ip: "10.255.16.1/24".to_string(),
                    },
                ],
                ..FileConfig::default()
            },
        };

        assert_eq!(cfg.active_gateway().unwrap().name, "gateway-b");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn backend_xds_gateways_populate_gateway_nodes() {
        let text = r#"
node_role = "backend"
public_ip = "auto"
underlay_ip = "auto"

[backend.xds]
gateways = ["192.168.0.12:22222", "192.168.0.16:22222"]
token = "secret"
reconnect_interval_secs = 5

[backend.return_path]
vxlan_dev = "edge-return"
"#;

        let mut parsed: FileConfig = toml::from_str(text).expect("backend xDS TOML parses");
        parsed.normalize();

        assert_eq!(parsed.gateway_nodes.len(), 2);
        assert_eq!(
            parsed.gateway_nodes[0].underlay_ip.to_string(),
            "192.168.0.12"
        );
        assert_eq!(
            parsed.gateway_nodes[1].underlay_ip.to_string(),
            "192.168.0.16"
        );
        assert_eq!(parsed.control_plane.gateway_port, Some(22222));
        assert!(parsed.render_user_toml().contains("gateways = ["));
    }

    #[test]
    fn backend_xds_accepts_backend_inventory_from_multiple_overlay_cidrs() {
        let file = FileConfig {
            node_role: NodeRole::Backend,
            node_name: "backend-a".to_string(),
            ha: HaConfig {
                active_source: ActiveSource::Xds,
                ..HaConfig::default()
            },
            control_plane: ControlPlaneConfig {
                enabled: true,
                mode: ControlPlaneMode::Xds,
                ..ControlPlaneConfig::default()
            },
            network: NetworkConfig {
                overlay_cidr: "10.255.12.0/24".to_string(),
                underlay_dev: "eth0".to_string(),
                vxlan_dev: "edge-return".to_string(),
                ..NetworkConfig::default()
            },
            gateway: GatewayConfig {
                overlay_ip: "10.255.12.1/24".to_string(),
                ..GatewayConfig::default()
            },
            backend_nodes: vec![
                BackendNode {
                    name: "backend-a".to_string(),
                    public_ip: "203.0.113.20".parse().unwrap(),
                    underlay_ip: "192.168.0.13".parse().unwrap(),
                    overlay_ip: "10.255.12.2/24".to_string(),
                },
                BackendNode {
                    name: "backend-b".to_string(),
                    public_ip: "203.0.113.21".parse().unwrap(),
                    underlay_ip: "192.168.0.14".parse().unwrap(),
                    overlay_ip: "10.255.16.2/24".to_string(),
                },
            ],
            ..FileConfig::default()
        };

        file.validate()
            .expect("xDS backend inventory may include peer gateway overlay CIDRs");

        let static_file = FileConfig {
            ha: HaConfig::default(),
            control_plane: ControlPlaneConfig::default(),
            ..file
        };
        assert!(
            static_file.validate().is_err(),
            "static backend config still requires backend overlays in local CIDR"
        );
    }

    #[test]
    fn backend_xds_rejects_more_than_two_gateways() {
        let text = r#"
node_role = "backend"
public_ip = "auto"
underlay_ip = "auto"

[backend.xds]
gateways = ["192.168.0.12:22222", "192.168.0.16:22222", "192.168.0.17:22222"]
token = "secret-token-value"
reconnect_interval_secs = 5

[backend.return_path]
vxlan_dev = "edge-return"
"#;

        let mut parsed: FileConfig = toml::from_str(text).expect("backend xDS TOML parses");
        parsed.normalize();
        let err = parsed
            .validate()
            .expect_err("more than two gateways must fail validation");
        assert!(
            err.to_string().contains("supports at most 2 entries"),
            "{err:#}"
        );
    }

    #[test]
    fn backend_return_paths_follow_gateway_inventory() {
        let file = FileConfig {
            gateway_nodes: vec![
                GatewayNode {
                    name: "gateway-a".to_string(),
                    public_ip: "203.0.113.10".parse().unwrap(),
                    underlay_ip: "192.0.2.10".parse().unwrap(),
                    overlay_ip: "10.44.0.1/24".to_string(),
                },
                GatewayNode {
                    name: "gateway-b".to_string(),
                    public_ip: "203.0.113.11".parse().unwrap(),
                    underlay_ip: "192.0.2.11".parse().unwrap(),
                    overlay_ip: "10.45.0.1/24".to_string(),
                },
            ],
            ..FileConfig::default()
        };
        let cfg = Config {
            file,
            path: "/tmp/edge-lb-test.toml".into(),
        };

        let paths = cfg.backend_return_paths();

        assert_eq!(paths.len(), 2);
        assert_eq!(
            paths[0].gateway_underlay_ip,
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            paths[0].gateway_overlay_ip,
            "10.44.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(paths[0].mark, return_mark(46, 0));
        assert_eq!(paths[0].route_table_id, return_table_id(46, 0));
        assert_eq!(
            paths[1].gateway_underlay_ip,
            "192.0.2.11".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            paths[1].gateway_overlay_ip,
            "10.45.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(paths[1].mark, return_mark(46, 1));
        assert_eq!(paths[1].route_table_id, return_table_id(46, 1));
    }
}
