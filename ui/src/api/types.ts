// Edge LB management API data types. Wire fields stay explicit so the UI does
// not invent a second representation of the control-plane model.

export type NodeRole = 'backend' | 'gateway'
export type Protocol = 'tcp' | 'udp'
export type LbSelect = 'rr' | 'hash' | 'consistent_hash' | 'priority' | 'persist' | 'lc'

export interface PageQuery {
  page?: number
  per_page?: number
  q?: string
}

export interface PageResult<T> {
  items: T[]
  total: number
  page: number
  per_page: number
}

export interface BackendTarget {
  backend?: string | null
  address: string
  weight: number
  health?: string | null
}

export interface TargetGroup {
  name: string
  health?: 'ok' | 'nok' | 'unassociated' | null
  monitor?: boolean
  probe_type?: string | null
  probe_port?: number | null
  probe_req?: string | null
  probe_resp?: string | null
  probe_status?: number | null
  probe_skip_tls_verify?: boolean
  period_secs?: number | null
  retries?: number | null
  targets: BackendTarget[]
}

export interface TargetGroupExport {
  version: number
  targetGroups: TargetGroup[]
}

/** Control-plane listener resource. It only binds a VIP/protocol to a target group. */
export interface ListenerConfig {
  name: string
  vip_ips: string[]
  port: number
  target_port: number
  protocols: Protocol[]
  target_group: string
  select?: LbSelect
  inactive_timeout?: number | null
}

export interface GatewayNode {
  name: string
  public_ip: string
  underlay_ip: string
  overlay_ip: string
}

export interface BackendNode {
  name: string
  public_ip: string
  underlay_ip: string
  overlay_ip: string
  public_ip_mode?: string
  public_ip_source?: string
  underlay_ip_mode?: string
  underlay_ip_source?: string
  conflicts?: NodeConflict[]
}

export interface BackendSubscription {
  public_ip: string
  public_ip_mode?: string
  public_ip_source?: string
  underlay_ip: string
  underlay_ip_mode?: string
  underlay_ip_source?: string
  peer?: string | null
  stream_id: string
  connected_at: number
  last_seen: number
  last_version: string
  conflicts?: NodeConflict[]
}

export interface PublicIpDiscovery {
  value?: string | null
  mode: string
  source: string
}

export interface NodeConflict {
  severity: string
  kind: string
  subject: string
  detail: string
}

export interface Status {
  node_role: NodeRole
  node_name: string
  public_ip: string
  underlay_ip: string
  overlay_ip: string
  active_gateway: string | null
  listen: string
  discovery?: {
    public_ip?: { value?: string | null; mode?: string; source?: string }
    underlay_ip?: { value?: string | null; mode?: string; source?: string }
    underlay_dev?: { value?: string | null; mode?: string; source?: string }
  }
  vxlan?: {
    dev: string
    underlay_dev: string
    vni: number
    vxlan_port: number
    mtu: number
    dscp: number
    present: boolean
    up: boolean
    remote: string | null
  }
  nft_table_present?: boolean
  policy_rule_present?: boolean
  dscp_attached?: boolean
  native_datapath_attached?: boolean
  underlay_xdp_attachment?: string | null
  dscp_stats?: { matched: number; changed: number }
}

export type NotificationKind =
  | 'webhook'
  | 'dingtalk'
  | 'feishu'
  | 'wecom'
  | 'telegram'
  | 'slack'
  | 'pushplus'
  | 'lanxin'

export interface NotificationChannel {
  id: string
  name: string
  kind: NotificationKind
  enabled: boolean
  events: string[]
  lang: string
  config: Record<string, unknown>
  created_at_unix: number
  updated_at_unix: number
}

export type NotificationChannelSummary = Omit<NotificationChannel, 'config'>

export interface NotificationList {
  channels: NotificationChannelSummary[]
  events: string[]
}

export interface NotificationDelivery {
  ok: boolean
  status_code?: number | null
  response: string
}

export type AutomationNodeScope = 'all' | 'filtered'
export type AutomationFilterMatch = 'all'
export type AutomationFilterField =
  | 'name'
  | 'underlay_ip'
  | 'public_ip'
  | 'public_ip_source'
  | 'underlay_ip_source'
export type AutomationFilterOp =
  | 'equals'
  | 'not_equals'
  | 'prefix'
  | 'not_prefix'
  | 'contains'
  | 'not_contains'
  | 'regex'
  | 'in_cidr'
  | 'not_in_cidr'
export type AutomationConflictPolicy = 'skip' | 'overwrite'
export type AutomationRemovePolicy = 'prune' | 'keep'

export interface AutomationFilterCondition {
  field: AutomationFilterField
  op: AutomationFilterOp
  value: string
}

export interface AutomationNodeFilter {
  match: AutomationFilterMatch
  conditions: AutomationFilterCondition[]
}

export interface AutomationTargetGroupTemplate {
  name: string
  monitor?: boolean
  probe_type?: string | null
  probe_port?: number | null
  probe_req?: string | null
  probe_resp?: string | null
  probe_status?: number | null
  probe_skip_tls_verify?: boolean
  period_secs?: number | null
  retries?: number | null
}

export interface AutomationTemplate {
  name: string
  enabled: boolean
  triggers: {
    on_create: boolean
    on_node_change: boolean
  }
  node_scope: AutomationNodeScope
  node_filter?: AutomationNodeFilter | null
  target_group: AutomationTargetGroupTemplate
  conflict_policy: AutomationConflictPolicy
  remove_policy: AutomationRemovePolicy
}

export interface AutomationTemplateExport {
  version: number
  exported_at_unix?: number
  exported_at?: string
  templates: AutomationTemplate[]
}

export type AutomationImportMode = 'merge_skip' | 'merge_overwrite' | 'replace_all'

export interface AutomationImportRequest extends AutomationTemplateExport {
  dry_run?: boolean
  mode?: AutomationImportMode
}

export interface AutomationImportResult {
  status?: string
  dry_run?: boolean
  report: unknown
  sync?: unknown
}

export interface AutomationTemplateStatus {
  last_run_unix?: number | null
  generated_count?: number | null
  degraded?: boolean
  errors?: string[]
}

export interface AutomationTemplateTestResult {
  template: string
  planned?: unknown[]
  matched_nodes?: unknown[]
  conflicts?: unknown[]
  errors?: string[]
}

export type GatewayHaMode = 'active_backup'
export type GatewayHaFailoverMode = 'manual' | 'bfd_auto'
export type GatewayHaVipProvider = 'l2' | 'hook'
export type GatewayHaVipBindDevice = 'underlay' | 'loopback'
export type GatewayHaVipOwner = 'edge_lb'
export type GatewayHaXsyncRpc = 'grpc'

export interface GatewayHaPeer {
  name: string
  underlay_ip: string
  public_ip?: string | null
  api_addr?: string | null
  xds_addr?: string | null
  overlay_cidr?: string | null
  overlay_ip?: string | null
  dscp?: number | null
  vni?: number | null
  vxlan_port?: number | null
  mtu?: number | null
  version?: string | null
  capabilities?: string[]
}

export interface GatewayHaVipConfig {
  provider: GatewayHaVipProvider
  owner: GatewayHaVipOwner
  bind_device: GatewayHaVipBindDevice
  garp_device?: string | null
  private_vip?: string | null
  bind_timeout_secs: number
  verify_timeout_secs: number
  garp: GatewayHaGarpConfig
  promote_hook?: string | null
  demote_hook?: string | null
  verify_hook?: string | null
}

export interface GatewayHaBgpConfig {
  local_as?: number | null
  router_id: string
  peers: string[]
  hold_time_secs: number
  keepalive_secs: number
}

export interface GatewayHaGarpConfig {
  count: number
  interval_ms: number
  repeat_after_ms: number
  repeat_count: number
}

export interface GatewayHaConfig {
  enabled: boolean
  mode: GatewayHaMode
  self_index: number
  preferred_active?: string | null
  connection_sync: boolean
  xsync_rpc: GatewayHaXsyncRpc
  failover: GatewayHaFailoverMode
  peers: GatewayHaPeer[]
  vip: GatewayHaVipConfig
  bgp: GatewayHaBgpConfig
}

export interface GatewayHaStatus {
  config: GatewayHaConfig | { error: string }
  session_token?: GatewayHaPeerTokenStatus
  native: {
    node: string
    active_gateway?: string | null
    state: string
    enabled: boolean
    peer_count: number
  }
  bfd?: {
    peer_ip?: string | null
    source_ip?: string | null
    state: string
    last_rx_ms?: number | null
    last_error?: string | null
  }
  xsync?: {
    state: string
    peer?: string | null
    last_error?: string | null
    last_ack_applied: number
  }
}

export interface GatewayHaPeerTokenStatus {
  present: boolean
  peer_name?: string
  peer_underlay_ip?: string
  session_token_id?: string
  updated_at_unix?: number
  error?: string
}

export interface GatewayHaSaveResult {
  status: string
  path: string
  datapath_refresh_required: boolean
}

export interface GatewayHaPairRequest {
  endpoint: string
  bootstrap_token: string
  config?: GatewayHaConfig
}

export interface GatewayHaPairResult {
  status: string
  local: GatewayHaPairedNode
  peer: GatewayHaPairedNode
  ha_config_storage: string
  session_token_storage: string
  datapath_refresh_required: boolean
  warnings: string[]
}

export interface GatewayHaUnpairResult {
  status: string
  path: string
  secret_deleted: boolean
  datapath_refresh_required: boolean
}

export interface GatewayHaPairedNode {
  name: string
  underlay_ip: string
  public_ip: string
  api_addr: string
  xds_addr: string
  overlay_cidr: string
  overlay_ip: string
  dscp: number
  vni: number
  vxlan_port: number
  mtu: number
  version: string
  capabilities: string[]
}

export interface GatewayHaFailoverResult {
  status: string
  gateway: string
  local_state: string
  peer_state?: string | null
  vip: string
}
