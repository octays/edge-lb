use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeListenerStateList {
    pub listeners: Vec<NativeListenerStateEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeListenerStateEntry {
    #[serde(default)]
    pub target_group: String,
    pub spec: NativeListenerSpec,
    #[serde(default)]
    pub targets: Vec<NativeListenerTarget>,
    /// Logical listener protocols. The datapath expands this into one
    /// protocol-specific lookup key per selected transport protocol.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeListenerSpec {
    pub vip_ips: Vec<String>,
    pub port: u16,
    pub protocol: String,
    #[serde(default)]
    pub sel: u32,
    #[serde(default)]
    pub mode: u32,
    #[serde(default)]
    pub monitor: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probetype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probeport: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probereq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proberesp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_timeout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_retries: Option<u32>,
    #[serde(default)]
    pub inactive_timeout: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeListenerTarget {
    /// Backend target address.
    pub address: String,
    /// Forwarding port owned by the listener configuration.
    pub target_port: u16,
    #[serde(default)]
    pub weight: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetHealthList {
    pub entries: Vec<TargetHealthEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetHealthEntry {
    #[serde(default)]
    pub target_group: String,
    pub host_name: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub inactive_retries: Option<u32>,
    #[serde(default)]
    pub probe_type: Option<String>,
    #[serde(default)]
    pub probe_req: Option<String>,
    #[serde(default)]
    pub probe_resp: Option<String>,
    #[serde(default)]
    pub probe_duration: Option<u32>,
    #[serde(default)]
    pub probe_port: Option<u16>,
    #[serde(default)]
    pub min_delay: Option<String>,
    #[serde(default)]
    pub avg_delay: Option<String>,
    #[serde(default)]
    pub max_delay: Option<String>,
    #[serde(default)]
    pub current_state: Option<String>,
    #[serde(default)]
    pub sync: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthProbeConfig {
    #[serde(default)]
    pub probe_type: Option<String>,
    #[serde(default)]
    pub probe_port: Option<u16>,
    #[serde(default)]
    pub probe_req: Option<String>,
    #[serde(default)]
    pub probe_resp: Option<String>,
    #[serde(default)]
    pub skip_tls_verify: bool,
    #[serde(default)]
    pub probe_duration: Option<u32>,
    #[serde(default)]
    pub inactive_retries: Option<u32>,
}

impl HealthProbeConfig {
    pub fn enabled(&self) -> bool {
        self.probe_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some_and(|value| !value.eq_ignore_ascii_case("none"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_listener_state_uses_native_resource_field_names() {
        let value = NativeListenerStateList {
            listeners: vec![NativeListenerStateEntry {
                target_group: "web".to_string(),
                spec: NativeListenerSpec {
                    vip_ips: vec!["192.0.2.10".to_string()],
                    port: 8080,
                    protocol: "tcp".to_string(),
                    ..NativeListenerSpec::default()
                },
                targets: vec![NativeListenerTarget {
                    address: "192.0.2.20".to_string(),
                    target_port: 10080,
                    weight: 1,
                    ..NativeListenerTarget::default()
                }],
                protocols: vec!["tcp".to_string()],
            }],
        };

        let json = serde_json::to_value(value).unwrap();
        assert!(json.get("listeners").is_some());
        assert!(json["listeners"][0].get("spec").is_some());
        assert!(json["listeners"][0].get("targets").is_some());
        assert!(json.get("services").is_none());
        assert!(json["listeners"][0].get("service_arguments").is_none());
        assert!(json["listeners"][0].get("endpoints").is_none());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteTargetHealthResult {
    Deleted,
    NotFound,
    Referenced { listener: String },
}
