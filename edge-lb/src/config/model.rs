use std::{fmt, net::IpAddr, path::PathBuf};

use edge_lb_common::{
    NATIVE_SELECT_CONSISTENT_HASH, NATIVE_SELECT_HASH, NATIVE_SELECT_LC, NATIVE_SELECT_PERSIST,
    NATIVE_SELECT_PRIORITY, NATIVE_SELECT_RR,
};
use serde::{Deserialize, Serialize};

use super::defaults::{
    default_auto_ip, default_backend_overlay, default_backend_weight, default_gateway_ip,
    default_gateway_overlay, default_gateway_public_ip, default_node_name, deserialize_ip_auto,
    deserialize_option_ip_auto, deserialize_u32_auto, serialize_ip_auto, serialize_option_ip_auto,
    serialize_u32_auto,
};
use super::{DEFAULT_LISTEN, DEFAULT_STATE_DIR};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Backend,
    Gateway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LbSelect {
    #[default]
    Rr,
    Hash,
    #[serde(rename = "consistent_hash")]
    ConsistentHash,
    Priority,
    Persist,
    Lc,
}

impl LbSelect {
    pub fn code(self) -> u32 {
        match self {
            Self::Rr => NATIVE_SELECT_RR,
            Self::Hash => NATIVE_SELECT_HASH,
            Self::ConsistentHash => NATIVE_SELECT_CONSISTENT_HASH,
            Self::Priority => NATIVE_SELECT_PRIORITY,
            Self::Persist => NATIVE_SELECT_PERSIST,
            Self::Lc => NATIVE_SELECT_LC,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LbMode {
    #[default]
    Default,
}

impl LbMode {
    pub fn code(self) -> u32 {
        match self {
            Self::Default => 0,
        }
    }
}

/// Local active-gateway source selector. Runtime HA state is stored in SQLite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActiveSource {
    File,
    Manual,
    Xds,
    Http,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlPlaneMode {
    #[default]
    File,
    Xds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayNode {
    pub name: String,
    #[serde(
        default = "default_auto_ip",
        deserialize_with = "deserialize_ip_auto",
        serialize_with = "serialize_ip_auto"
    )]
    pub public_ip: IpAddr,
    #[serde(
        default = "default_auto_ip",
        deserialize_with = "deserialize_ip_auto",
        serialize_with = "serialize_ip_auto"
    )]
    pub underlay_ip: IpAddr,
    /// Overlay address (with prefix) of this gateway. Defaults to the first
    /// usable address from network.overlay_cidr.
    #[serde(default = "default_gateway_overlay")]
    pub overlay_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendNode {
    pub name: String,
    #[serde(
        default = "default_auto_ip",
        deserialize_with = "deserialize_ip_auto",
        serialize_with = "serialize_ip_auto"
    )]
    pub public_ip: IpAddr,
    #[serde(
        default = "default_auto_ip",
        deserialize_with = "deserialize_ip_auto",
        serialize_with = "serialize_ip_auto"
    )]
    pub underlay_ip: IpAddr,
    /// Overlay address (with prefix) of this backend. Defaults to sequential
    /// addresses from network.overlay_cidr after the gateway address.
    #[serde(default = "default_backend_overlay")]
    pub overlay_ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayReturnPath {
    pub gateway: Option<String>,
    pub gateway_underlay_ip: IpAddr,
    pub gateway_overlay_ip: IpAddr,
    pub backend_overlay_ip: Option<String>,
    pub dscp: u32,
    pub mark: u32,
    pub route_table_id: u32,
}

/// Marks and route-table ids for the return path are derived per
/// (gateway, dscp). Slots keep each gateway's space disjoint.
pub const EDGE_MARK_BASE: u32 = 0x1000;
/// Inclusive lower bound of marks emitted by the current slotted derivation.
#[cfg(test)]
pub const EDGE_CURRENT_MARK_BASE: u32 = 0x1040;
/// Exclusive upper bound of every mark edge-lb derives.
#[cfg(test)]
pub const EDGE_MARK_LIMIT: u32 = 0x1400;
pub const EDGE_TABLE_BASE: u32 = 1000;
/// Inclusive lower bound of route tables emitted by the current slotted
/// derivation.
#[cfg(test)]
pub const EDGE_CURRENT_TABLE_BASE: u32 = 1064;
/// Exclusive upper bound of every table id edge-lb derives.
#[cfg(test)]
pub const EDGE_TABLE_LIMIT: u32 = 1000 + 7 * 64;
/// Maximum supported simultaneous gateways in the return-path slot space.
pub const EDGE_MAX_GATEWAY_SLOTS: u32 = 6;

const EDGE_DSCP_MASK: u32 = 0x3f;
const EDGE_SLOT_STRIDE: u32 = 64;

/// Return-path fwmark for one (gateway slot, dscp). Slot 0 occupies
/// 0x1040..=0x107f.
pub fn return_mark(dscp: u32, gateway_slot: u32) -> u32 {
    let slot = gateway_slot.min(EDGE_MAX_GATEWAY_SLOTS - 1);
    EDGE_MARK_BASE | ((slot + 1) << 6) | (dscp & EDGE_DSCP_MASK)
}

/// Return-path routing table id for one (gateway slot, dscp). Slot 0
/// occupies 1064..=1127.
pub fn return_table_id(dscp: u32, gateway_slot: u32) -> u32 {
    let slot = gateway_slot.min(EDGE_MAX_GATEWAY_SLOTS - 1);
    EDGE_TABLE_BASE + (slot + 1) * EDGE_SLOT_STRIDE + (dscp & EDGE_DSCP_MASK)
}

/// Stable slot of a gateway: its index in the underlay-sorted gateway list.
/// Every gateway computes the same sorted list (self + HA peers), so slots
/// are unique without extra coordination.
pub fn gateway_slot(gateways: &[GatewayNode], gateway_underlay: IpAddr) -> u32 {
    let mut underlays: Vec<IpAddr> = gateways.iter().map(|gw| gw.underlay_ip).collect();
    underlays.sort_by_key(|ip| match ip {
        IpAddr::V4(v4) => (4u8, u32::from(*v4) as u128),
        IpAddr::V6(v6) => (6u8, u128::from(*v6)),
    });
    underlays.dedup();
    underlays
        .iter()
        .position(|ip| *ip == gateway_underlay)
        .unwrap_or(0) as u32
}

#[cfg(test)]
mod return_id_tests {
    use super::*;

    fn node(underlay: &str) -> GatewayNode {
        GatewayNode {
            name: underlay.to_string(),
            public_ip: "203.0.113.10".parse().unwrap(),
            underlay_ip: underlay.parse().unwrap(),
            overlay_ip: "10.255.255.1/24".to_string(),
        }
    }

    #[test]
    fn marks_and_tables_are_unique_per_gateway() {
        let gateways = [node("192.168.0.16"), node("192.168.0.12")];
        let a = gateway_slot(&gateways, "192.168.0.12".parse().unwrap());
        let b = gateway_slot(&gateways, "192.168.0.16".parse().unwrap());
        assert_ne!(a, b);
        for dscp in 0..64u32 {
            assert_ne!(return_mark(dscp, a), return_mark(dscp, b));
            assert_ne!(return_table_id(dscp, a), return_table_id(dscp, b));
        }
    }

    #[test]
    fn derived_ids_stay_in_current_managed_ranges() {
        for slot in 0..EDGE_MAX_GATEWAY_SLOTS {
            for dscp in 0..64u32 {
                let mark = return_mark(dscp, slot);
                assert!((EDGE_CURRENT_MARK_BASE..EDGE_MARK_LIMIT).contains(&mark));
                let table = return_table_id(dscp, slot);
                assert!((EDGE_CURRENT_TABLE_BASE..EDGE_TABLE_LIMIT).contains(&table));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(
        default = "default_auto_ip",
        deserialize_with = "deserialize_ip_auto",
        serialize_with = "serialize_ip_auto"
    )]
    pub address: IpAddr,
    #[serde(default = "default_backend_weight", alias = "backend_weight")]
    pub weight: u32,
}

impl Default for BackendTarget {
    fn default() -> Self {
        Self {
            backend: None,
            address: default_auto_ip(),
            weight: 1,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TargetGroup {
    pub name: String,
    pub monitor: bool,
    pub probe_type: Option<String>,
    pub probe_port: Option<u16>,
    pub probe_req: Option<String>,
    pub probe_resp: Option<String>,
    pub probe_skip_tls_verify: bool,
    pub period_secs: Option<u32>,
    pub retries: Option<u32>,
    pub targets: Vec<BackendTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Listener {
    pub name: String,
    pub port: u16,
    /// Backend forwarding port. Endpoint health probe ports belong to the target group.
    #[serde(default)]
    pub target_port: u16,
    pub target_group: String,
    /// Explicit VIP addresses. Empty uses the effective local gateway/VIP set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vip_ips: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<Protocol>,
    pub select: LbSelect,
    pub mode: LbMode,
    pub inactive_timeout: Option<u32>,
}

impl Default for Listener {
    fn default() -> Self {
        Self {
            name: String::new(),
            port: 0,
            target_port: 0,
            target_group: String::new(),
            vip_ips: Vec::new(),
            protocols: vec![Protocol::Tcp],
            select: LbSelect::Rr,
            mode: LbMode::Default,
            inactive_timeout: None,
        }
    }
}

/// xDS-like gRPC control plane. Gateway nodes serve snapshots; backend nodes
/// subscribe and reconcile from the last good snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlPlaneConfig {
    pub enabled: bool,
    pub mode: ControlPlaneMode,
    /// Gateway-side listen address.
    pub listen: String,
    /// Backend-side connect port. Defaults to the port parsed from `listen`.
    pub gateway_port: Option<u16>,
    pub token: Option<String>,
    pub trusted_source_cidrs: Vec<String>,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: ControlPlaneMode::File,
            listen: "127.0.0.1:22222".to_string(),
            gateway_port: None,
            token: None,
            trusted_source_cidrs: Vec::new(),
        }
    }
}

/// Active gateway selection settings. The selected gateway itself is stored in
/// the SQLite `ha_active_gateway/current` resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HaConfig {
    pub active_source: ActiveSource,
    /// Test-only active selection substitute. Production active state lives in
    /// SQLite `ha_active_gateway/current`.
    #[cfg(test)]
    pub active_state_file: PathBuf,
    /// Daemon watch interval in seconds.
    pub watch_interval_secs: u64,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            active_source: ActiveSource::File,
            #[cfg(test)]
            active_state_file: PathBuf::from("/var/lib/edge-lb/active-gateway"),
            watch_interval_secs: 3,
        }
    }
}

/// Shared network topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Public IP of the active gateway (verification target).
    #[serde(
        deserialize_with = "deserialize_ip_auto",
        serialize_with = "serialize_ip_auto"
    )]
    pub gateway_public_ip: IpAddr,
    /// Gateway underlay IP. On a gateway node this is the local underlay
    /// address; on a backend node it is the fallback return-path target.
    #[serde(
        deserialize_with = "deserialize_ip_auto",
        serialize_with = "serialize_ip_auto"
    )]
    pub gateway_ip: IpAddr,
    /// Underlay IP of the standby gateway, if configured.
    #[serde(
        default,
        deserialize_with = "deserialize_option_ip_auto",
        serialize_with = "serialize_option_ip_auto",
        skip_serializing_if = "Option::is_none"
    )]
    pub standby_gateway_ip: Option<IpAddr>,
    /// Optional single-backend bootstrap fields for minimal local configs.
    #[serde(
        default,
        deserialize_with = "deserialize_option_ip_auto",
        serialize_with = "serialize_option_ip_auto",
        skip_serializing_if = "Option::is_none"
    )]
    pub backend_public_ip: Option<IpAddr>,
    #[serde(
        default,
        deserialize_with = "deserialize_option_ip_auto",
        serialize_with = "serialize_option_ip_auto",
        skip_serializing_if = "Option::is_none"
    )]
    pub backend_ip: Option<IpAddr>,
    /// Overlay CIDR used for the VXLAN return network. Node overlay addresses
    /// are assigned from this CIDR unless explicitly overridden.
    pub overlay_cidr: String,
    /// Underlay device carrying VXLAN outer packets.
    pub underlay_dev: String,
    /// Name of the VXLAN device managed by this agent.
    pub vxlan_dev: String,
    pub vni: u32,
    pub vxlan_port: u16,
    #[serde(
        deserialize_with = "deserialize_u32_auto",
        serialize_with = "serialize_u32_auto"
    )]
    pub vxlan_mtu: u32,
    #[serde(default, skip)]
    pub vxlan_mtu_auto: bool,
    /// DSCP marking value. Gateways set it and backends match it.
    pub dscp: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            gateway_public_ip: default_gateway_public_ip(),
            gateway_ip: default_gateway_ip(),
            standby_gateway_ip: None,
            backend_public_ip: None,
            backend_ip: None,
            overlay_cidr: "10.255.255.0/24".to_string(),
            underlay_dev: "auto".to_string(),
            vxlan_dev: "auto".to_string(),
            vni: 100,
            vxlan_port: 4789,
            vxlan_mtu: 1450,
            vxlan_mtu_auto: false,
            dscp: 46,
        }
    }
}

/// IP discovery settings used only when a public/underlay field is `auto`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IpDiscoveryConfig {
    /// Optional high-priority env var for the local node public IP.
    pub public_ip_env: Option<String>,
    /// Optional high-priority env var for the local node underlay IP.
    pub underlay_ip_env: Option<String>,
    /// Optional high-priority env var for the local underlay device.
    pub underlay_dev_env: Option<String>,
    /// STUN servers for public IP discovery, tried in order.
    #[serde(default)]
    pub stun_servers: Vec<String>,
    /// UDP target used to discover the local source address.
    pub udp_probe_addr: String,
}

impl Default for IpDiscoveryConfig {
    fn default() -> Self {
        Self {
            public_ip_env: Some("EDGE_LB_PUBLIC_IP".to_string()),
            underlay_ip_env: Some("EDGE_LB_UNDERLAY_IP".to_string()),
            underlay_dev_env: Some("EDGE_LB_UNDERLAY_DEV".to_string()),
            stun_servers: vec!["stun.l.google.com:19302".to_string()],
            udp_probe_addr: "8.8.8.8:53".to_string(),
        }
    }
}

/// Runtime result of resolving one auto/static IP field.
#[derive(Debug, Clone, Default, Serialize)]
pub struct IpDiscoveryRuntime {
    pub value: Option<IpAddr>,
    pub mode: String,
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DeviceDiscoveryRuntime {
    pub value: Option<String>,
    pub mode: String,
    pub source: String,
}

/// Runtime discovery report. This is intentionally not persisted to TOML.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RuntimeDiscovery {
    pub public_ip: IpDiscoveryRuntime,
    pub underlay_ip: IpDiscoveryRuntime,
    pub underlay_dev: DeviceDiscoveryRuntime,
}

/// Gateway-only settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xds: Option<GatewayXdsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconcile: Option<GatewayReconcileConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane: Option<ControlPlaneConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<GatewayMetricsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_persistence: Option<GatewayFlowPersistenceConfig>,
    /// Gateway overlay address derived from network.overlay_cidr.
    pub overlay_ip: String,
    /// TC priority of the gateway DSCP marker filter.
    pub dscp_pref: u16,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            xds: None,
            reconcile: None,
            control_plane: None,
            network: None,
            api: None,
            metrics: None,
            flow_persistence: None,
            overlay_ip: default_gateway_overlay(),
            dscp_pref: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayReconcileConfig {
    pub interval_secs: u64,
}

impl Default for GatewayReconcileConfig {
    fn default() -> Self {
        Self {
            interval_secs: HaConfig::default().watch_interval_secs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayXdsConfig {
    pub listen: String,
    pub token: Option<String>,
    pub trusted_source_cidrs: Vec<String>,
}

impl Default for GatewayXdsConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:22222".to_string(),
            token: None,
            trusted_source_cidrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayMetricsConfig {
    pub enabled: bool,
    pub listen: String,
    /// CIDRs allowed to scrape /metrics. Empty means derive the local underlay subnet.
    pub trusted_source_cidrs: Vec<String>,
}

impl Default for GatewayMetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:19090".to_string(),
            trusted_source_cidrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayFlowPersistenceConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub min_remaining_ttl_secs: u64,
    /// Maximum canonical bidirectional flow pairs retained in one snapshot.
    pub max_records: usize,
    pub restore_on_start: bool,
    pub flush_on_shutdown: bool,
}

impl Default for GatewayFlowPersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 30,
            min_remaining_ttl_secs: 5,
            max_records: 524_288,
            restore_on_start: true,
            flush_on_shutdown: true,
        }
    }
}

/// Backend-only settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xds: Option<BackendXdsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_path: Option<BackendReturnPathConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<BackendControlConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane: Option<ControlPlaneConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiConfig>,
    /// Runtime overlay IP assigned from the overlay CIDR and effective backend
    /// inventory.
    #[serde(skip_serializing)]
    pub overlay_ip: String,
    /// conntrack/mark value used to steer replies into the VXLAN.
    pub ct_mark: u32,
    /// fwmark selector, `value/mask` notation for `ip rule`.
    pub fwmark: String,
    /// Routing table name registered in /etc/iproute2/rt_tables.
    pub route_table: String,
    pub route_table_id: u32,
    pub rule_priority: u32,
    /// nft table owned by this agent on the backend.
    pub nft_table: String,
    /// TCP MSS clamp applied to container replies leaving via the VXLAN.
    pub mss: u32,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            xds: None,
            return_path: None,
            control: None,
            control_plane: None,
            network: None,
            api: None,
            overlay_ip: default_backend_overlay(),
            ct_mark: 1,
            fwmark: "0x1/0xff".to_string(),
            route_table: "edge-return".to_string(),
            route_table_id: 100,
            rule_priority: 100,
            nft_table: "edge_lb_return".to_string(),
            mss: 1410,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendXdsConfig {
    pub gateway: String,
    pub gateways: Vec<String>,
    pub token: Option<String>,
    pub reconnect_interval_secs: u64,
}

impl Default for BackendXdsConfig {
    fn default() -> Self {
        Self {
            gateway: String::new(),
            gateways: Vec::new(),
            token: None,
            reconnect_interval_secs: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendReturnPathConfig {
    pub vxlan_dev: String,
    pub ct_mark: u32,
    pub fwmark: String,
    pub route_table: String,
    pub route_table_id: u32,
    pub rule_priority: u32,
    pub nft_table: String,
    pub mss: u32,
}

impl Default for BackendReturnPathConfig {
    fn default() -> Self {
        Self {
            vxlan_dev: "auto".to_string(),
            ct_mark: 1,
            fwmark: "0x1/0xff".to_string(),
            route_table: "edge-return".to_string(),
            route_table_id: 100,
            rule_priority: 100,
            nft_table: "edge_lb_return".to_string(),
            mss: 1410,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendControlConfig {
    pub source: ActiveSource,
    pub reconnect_interval_secs: u64,
}

impl Default for BackendControlConfig {
    fn default() -> Self {
        Self {
            source: ActiveSource::Xds,
            reconnect_interval_secs: 3,
        }
    }
}

/// Management API/UI settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    /// HTTP listen address. Non-loopback listeners require auth_token.
    pub listen: String,
    pub auth_token: Option<String>,
    /// CIDRs allowed to call /api routes. Empty means derive the local underlay subnet.
    pub trusted_source_cidrs: Vec<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.to_string(),
            auth_token: None,
            trusted_source_cidrs: Vec::new(),
        }
    }
}

/// Full on-disk configuration model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FileConfig {
    /// Local node role.
    pub node_role: NodeRole,
    pub node_name: String,
    #[serde(
        default = "default_auto_ip",
        deserialize_with = "deserialize_ip_auto",
        serialize_with = "serialize_ip_auto"
    )]
    pub public_ip: IpAddr,
    #[serde(
        default = "default_auto_ip",
        deserialize_with = "deserialize_ip_auto",
        serialize_with = "serialize_ip_auto"
    )]
    pub underlay_ip: IpAddr,
    /// Default log filter used when EDGE_LB_LOG/RUST_LOG is not set.
    pub log_level: String,
    pub state_dir: PathBuf,
    pub ha: HaConfig,
    pub network: NetworkConfig,
    pub discovery: IpDiscoveryConfig,
    pub gateway_nodes: Vec<GatewayNode>,
    pub backend_nodes: Vec<BackendNode>,
    pub target_groups: Vec<TargetGroup>,
    pub listeners: Vec<Listener>,
    #[serde(skip)]
    pub backend_return_paths: Vec<GatewayReturnPath>,
    #[serde(skip)]
    pub runtime_discovery: RuntimeDiscovery,
    pub gateway: GatewayConfig,
    pub backend: BackendConfig,
    pub api: ApiConfig,
    pub control_plane: ControlPlaneConfig,
}

impl Default for FileConfig {
    fn default() -> Self {
        let node_name = default_node_name();
        Self {
            node_role: NodeRole::Backend,
            node_name: node_name.clone(),
            public_ip: default_auto_ip(),
            underlay_ip: default_auto_ip(),
            log_level: "info".to_string(),
            state_dir: DEFAULT_STATE_DIR.into(),
            ha: HaConfig::default(),
            network: NetworkConfig::default(),
            discovery: IpDiscoveryConfig::default(),
            gateway_nodes: Vec::new(),
            backend_nodes: Vec::new(),
            target_groups: Vec::new(),
            listeners: Vec::new(),
            backend_return_paths: Vec::new(),
            runtime_discovery: RuntimeDiscovery::default(),
            gateway: GatewayConfig::default(),
            backend: BackendConfig::default(),
            api: ApiConfig::default(),
            control_plane: ControlPlaneConfig::default(),
        }
    }
}
