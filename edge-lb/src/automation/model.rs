use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AutomationConfig {
    pub templates: Vec<AutomationTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AutomationTemplate {
    pub name: String,
    pub enabled: bool,
    pub triggers: AutomationTriggers,
    pub node_scope: NodeScope,
    pub node_filter: Option<NodeFilter>,
    pub target_group: TargetGroupTemplate,
    pub conflict_policy: ConflictPolicy,
    pub remove_policy: RemovePolicy,
}

impl Default for AutomationTemplate {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            triggers: AutomationTriggers::default(),
            node_scope: NodeScope::All,
            node_filter: Some(NodeFilter::default()),
            target_group: TargetGroupTemplate::default(),
            conflict_policy: ConflictPolicy::Skip,
            remove_policy: RemovePolicy::Prune,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TargetGroupTemplate {
    pub name: String,
    pub monitor: bool,
    pub probe_type: Option<String>,
    pub probe_port: Option<u16>,
    pub probe_req: Option<String>,
    pub probe_resp: Option<String>,
    pub probe_skip_tls_verify: bool,
    pub period_secs: Option<u32>,
    pub retries: Option<u32>,
}

impl Default for TargetGroupTemplate {
    fn default() -> Self {
        Self {
            name: String::new(),
            monitor: false,
            probe_type: Some("none".to_string()),
            probe_port: None,
            probe_req: None,
            probe_resp: None,
            probe_skip_tls_verify: false,
            period_secs: Some(15),
            retries: Some(3),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AutomationTriggers {
    pub on_create: bool,
    pub on_node_change: bool,
}

impl Default for AutomationTriggers {
    fn default() -> Self {
        Self {
            on_create: true,
            on_node_change: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeScope {
    #[default]
    All,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeFilter {
    pub r#match: FilterMatch,
    pub conditions: Vec<FilterCondition>,
}

impl Default for NodeFilter {
    fn default() -> Self {
        Self {
            r#match: FilterMatch::All,
            conditions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterMatch {
    #[default]
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterCondition {
    pub field: FilterField,
    pub op: FilterOp,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterField {
    Name,
    UnderlayIp,
    PublicIp,
    UnderlayIpSource,
    PublicIpSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Equals,
    NotEquals,
    Prefix,
    NotPrefix,
    Contains,
    NotContains,
    Regex,
    InCidr,
    NotInCidr,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    #[default]
    Skip,
    Overwrite,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovePolicy {
    #[default]
    Prune,
    Keep,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutomationExport {
    pub version: u32,
    pub exported_at_unix: u64,
    pub templates: Vec<AutomationTemplate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutomationTestResult {
    pub template: String,
    pub planned: Vec<PlannedTargetGroup>,
    pub matched_nodes: Vec<MatchedNode>,
    pub conflicts: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannedTargetGroup {
    pub template: String,
    pub name: String,
    pub monitor: bool,
    pub probe_type: String,
    pub targets: Vec<MatchedNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchedNode {
    pub name: String,
    pub underlay_ip: String,
    pub public_ip: String,
    pub underlay_ip_source: Option<String>,
    pub public_ip_source: Option<String>,
}
