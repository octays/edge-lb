# edge-lb Metrics 指标说明

edge-lb 在 gateway 角色下可通过独立 HTTP 端口暴露 Prometheus text format 指标。backend 不提供 metrics HTTP 端口。

## 启用方式

```toml
[gateway.metrics]
enabled = true
listen = "0.0.0.0:19090"
trusted_source_cidrs = ["192.168.0.0/24"]
```

访问路径：

```text
GET /metrics
```

metrics 不属于 `/api/v1`，不使用 Bearer token，只使用 CIDR 白名单。

`trusted_source_cidrs = []` 时，只允许本机 `underlay_dev` 所在接口网段访问；不会隐式允许 `127.0.0.1`。如果 Prometheus 在本机通过 loopback 抓取，需要显式加入：

```toml
trusted_source_cidrs = ["192.168.0.0/24", "127.0.0.1/32"]
```

## 通用信息指标

| 指标 | 类型 | 说明 |
| --- | --- | --- |
| `edge_lb_node_info{role,node}` | gauge | 节点身份信息，当前 metrics 只在 gateway 暴露，值固定为 `1`。 |
| `edge_lb_build_info{version}` | gauge | edge-lb 构建版本，值固定为 `1`。 |
| `edge_lb_underlay_info{dev,underlay}` | gauge | gateway underlay 设备和 underlay IP，值固定为 `1`。 |

## 进程资源指标

| 指标 | 类型 | 说明 |
| --- | --- | --- |
| `edge_lb_process_cpu_seconds_total` | counter | edge-lb 进程累计 CPU 时间，单位秒。 |
| `edge_lb_process_start_time_seconds` | gauge | edge-lb 进程启动时间，Unix timestamp 秒。 |
| `edge_lb_process_memory_rss_bytes` | gauge | edge-lb 进程 RSS 常驻内存，单位 bytes。 |
| `edge_lb_process_memory_virtual_bytes` | gauge | edge-lb 进程虚拟内存，单位 bytes。 |
| `edge_lb_process_threads` | gauge | edge-lb 进程线程数。 |

常用 PromQL：

```promql
rate(edge_lb_process_cpu_seconds_total[1m])
edge_lb_process_memory_rss_bytes
time() - edge_lb_process_start_time_seconds
```

## 主机资源指标

| 指标 | 类型 | 说明 |
| --- | --- | --- |
| `edge_lb_host_cpu_cores` | gauge | gateway 主机 CPU core 数。 |
| `edge_lb_host_memory_total_bytes` | gauge | gateway 主机总内存，单位 bytes。 |
| `edge_lb_host_memory_available_bytes` | gauge | gateway 主机可用内存，单位 bytes。 |
| `edge_lb_host_memory_used_bytes` | gauge | `total - available`，单位 bytes。 |
| `edge_lb_host_load1` | gauge | 1 分钟 load average。 |
| `edge_lb_host_load5` | gauge | 5 分钟 load average。 |
| `edge_lb_host_load15` | gauge | 15 分钟 load average。 |

常用 PromQL：

```promql
edge_lb_host_memory_used_bytes / edge_lb_host_memory_total_bytes
edge_lb_host_load1 / edge_lb_host_cpu_cores
rate(edge_lb_process_cpu_seconds_total[1m]) / edge_lb_host_cpu_cores
```

## Gateway datapath 指标

| 指标 | 类型 | 说明 |
| --- | --- | --- |
| `edge_lb_gateway_dscp_attached` | gauge | DSCP TC 程序是否已挂载，`1` 表示已挂载。 |
| `edge_lb_gateway_native_datapath_attached` | gauge | native DNAT datapath 是否已挂载，`1` 表示已挂载。 |
| `edge_lb_gateway_dscp_packets_matched_total` | counter | DSCP marker 匹配到的包总数。 |
| `edge_lb_gateway_dscp_packets_changed_total` | counter | DSCP marker 实际改写 DSCP 的包总数。 |
| `edge_lb_gateway_native_listener_hit_total` | counter | native DNAT 命中 listener 的包总数。 |
| `edge_lb_gateway_native_listener_miss_total` | counter | native DNAT 未命中 listener 的包总数。 |
| `edge_lb_gateway_native_target_miss_total` | counter | listener 命中但未找到可用 target 的次数。 |
| `edge_lb_gateway_native_return_miss_total` | counter | reverse NAT 未找到 flow 的次数。 |
| `edge_lb_gateway_native_rewritten_total` | counter | native datapath 完成改写的包总数。 |
| `edge_lb_gateway_native_checksum_error_total` | counter | native NAT 地址/端口 store、checksum 更新或 UDP zero-checksum 恢复失败的包数；`patch` 中这些改写失败统一丢弃，每包计一次。 |
| `edge_lb_gateway_native_flow_map_capacity` | gauge | `NATIVE_FLOWS` eBPF LRU map 的 entry 容量。每条连接通常占用正向和反向两条 entry。 |
| `edge_lb_gateway_native_flow_pair_capacity` | gauge | 按双向 entry 估算的最大 flow pair 容量；当前 `1048576 / 2 = 524288`。 |
| `edge_lb_gateway_native_flow_event_lost_total` | counter | native flow 新建/删除事件写入 ringbuf 失败次数；该指标增长表示 xSync 可能需要依赖低频差量补偿。 |
| `edge_lb_gateway_native_consistent_hash_bucket_hit_total` | counter | `consistent_hash` 新流命中 bucket table 的次数。 |
| `edge_lb_gateway_native_consistent_hash_bucket_miss_total` | counter | `consistent_hash` 新流未找到 bucket 的次数，通常表示 bucket 表未写入或不完整。 |
| `edge_lb_gateway_native_consistent_hash_bucket_unusable_total` | counter | bucket 指向的 target 当前不可用或越界的次数。 |
| `edge_lb_gateway_native_consistent_hash_fallback_total` | counter | `consistent_hash` 因 bucket miss/unusable 回退到首个可用 target 的次数。 |
| `edge_lb_gateway_native_consistent_hash_bucket_table_info{listener,listener_id,vip,port,protocol,bucket_count,digest}` | gauge | 实际 pinned bucket table 的摘要信息，值固定为 `1`，用于比对双 gateway 是否生成同一张表。 |
| `edge_lb_gateway_native_flow_persistence_enabled` | gauge | native flow map 本地快照是否开启，`1` 表示开启。 |
| `edge_lb_gateway_native_flow_snapshot_records` | gauge | 最近一次成功写入的 canonical flow pair 数。 |
| `edge_lb_gateway_native_flow_snapshot_bytes` | gauge | 最近一次成功写入的 snapshot 文件大小。 |
| `edge_lb_gateway_native_flow_snapshot_duration_seconds` | gauge | 最近一次 snapshot 的 dump、编码和落盘耗时。 |
| `edge_lb_gateway_native_flow_snapshot_errors_total` | counter | snapshot 写入失败次数。 |
| `edge_lb_gateway_native_flow_restore_records_total` | counter | 启动恢复成功写回的 canonical flow pair 数。 |
| `edge_lb_gateway_native_flow_restore_skipped_total{reason}` | counter | 启动恢复跳过的 flow pair 数，reason 包括 `expired`、`config`、`incomplete`。 |
| `edge_lb_gateway_native_flow_restore_duration_seconds` | gauge | 最近一次启动恢复耗时。 |
| `edge_lb_gateway_native_flow_restore_errors_total` | counter | 启动恢复失败次数。 |

常用 PromQL：

```promql
rate(edge_lb_gateway_native_listener_hit_total[1m])
rate(edge_lb_gateway_native_rewritten_total[1m])
rate(edge_lb_gateway_native_target_miss_total[1m])
rate(edge_lb_gateway_native_checksum_error_total[1m])
rate(edge_lb_gateway_native_consistent_hash_fallback_total[1m])
edge_lb_gateway_native_consistent_hash_bucket_table_info
edge_lb_gateway_native_flow_snapshot_records
rate(edge_lb_gateway_native_flow_snapshot_errors_total[5m])
```

## 回程 Redirect 指标（patch 开发中）

gateway-only，从独立 `NATIVE_RETURN_STATS` per-CPU map 读取，不扫描 flow、租约或客户端列表。
不改变原 NAT/正向 redirect 统计 ABI，沿用原 metrics 端口和白名单。

| 指标 | 类型 | 含义 |
|---|---|---|
| `edge_lb_gateway_native_return_redirect_stats_available` | gauge | map 可读为 1，否则为 0 且不输出以下计数 |
| `edge_lb_gateway_native_return_redirect_submitted_total` | counter | 已提交 redirect，不等于设备发出或客户端成功接收 |
| `edge_lb_gateway_native_return_redirect_fallback_total{reason}` | counter | 固定原因：policy、expired、route、neighbor、ttl、mtu、unsupported |
| `edge_lb_gateway_native_return_redirect_mutation_error_total` | counter | TTL/L2 改写或提交失败并丢弃的包数 |

`policy` 表示 FIB 出口/source/入口对应的租约不存在；`expired` 为租约过期；`route` 包含
非转发、本地交付、不可达、forwarding 禁用及 helper 错误；`neighbor` 为 FIB 缺邻居。
`unsupported` 包含 options、GSO、mark、非 host/VLAN、长度/checksum 不支持等情况。
NAT 本身的改写失败仍计入 `edge_lb_gateway_native_checksum_error_total`。

```promql
rate(edge_lb_gateway_native_return_redirect_submitted_total[1m])
sum by (reason) (rate(edge_lb_gateway_native_return_redirect_fallback_total[1m]))
rate(edge_lb_gateway_native_return_redirect_mutation_error_total[1m])
```

## 正向 Redirect 指标（patch 开发中）

指标来自独立的 `NATIVE_REDIRECT_STATS` per-CPU map，不改变现有 NAT stats ABI。
当前已接通数据面核心、保守准入、短租约自动收敛与失效机制；不能把指标可抓取视为
准入通过或端到端加速成功。存在 nft/legacy/XFRM 策略、不支持的主机/TC 条件或读取失败时
不会发布 route。具体边界见 [正向方案](tc-direct-redirect-fast-path-plan.md)。backend 不新增指标端口。

| 指标 | 类型 | 说明 |
| --- | --- | --- |
| `edge_lb_gateway_native_redirect_stats_available` | gauge | 本次成功读取 map 为 1，否则为 0；不表示准入或发送成功。 |
| `edge_lb_gateway_native_redirect_admission_status{state,reason}` | gauge | 最近一次自动准入/发布状态，固定输出一条值为 1 的样本；不是每包命中率。 |
| `edge_lb_gateway_native_redirect_admission_updated_seconds` | gauge | 最近一次自动准入/发布状态更新的 Unix 秒。 |
| `edge_lb_gateway_native_redirect_map_digest` | gauge | 最近一次成功发布的正向 route、回程 lease 与本机地址集合摘要；不包含短租约过期时间，值为 0 表示尚无成功发布。 |
| `edge_lb_gateway_native_redirect_submitted_total` | counter | helper 返回 redirect 动作的次数，不等于设备发送成功或端到端成功。 |
| `edge_lb_gateway_native_redirect_fallback_total{reason}` | counter | 未修改 TTL/L2 前回退的次数，原因见下表。 |
| `edge_lb_gateway_native_redirect_mutation_error_total` | counter | 开始修改 TTL/L2 后的 helper 错误，此时丢弃而非回退，避免半修改报文进入协议栈。 |

`admission_status` 的 `state` 当前为 `unknown`、`published` 或 `blocked`。`reason` 使用固定低基数集合，
例如 `none`、`startup`、`rp_filter`、`forwarding`、`routing_policy`、`kernel_policy`、
`tc`、`lease`、`neighbor`、`route`、`cache`、`other`。它帮助区分 `route_miss` 是尚未收敛、
准入被策略拒绝还是缓存被撤销；不能用它替代 redirect submitted/fallback 的 per-packet 统计。

`fallback_total{reason}` 的 `reason` 也使用固定低基数集合，不以 IP、MAC、target 或 listener 作为标签：

| reason | 含义 |
| --- | --- |
| `route_miss` | 缺少缓存条目，可能尚未准入/收敛或已失效，不单指邻居缺失。 |
| `route_invalid` | ifindex、MTU、MAC 或 ABI 字段无效。 |
| `expired` | 缓存有效期已到。 |
| `target_changed` | 目标 slot 对应的实际地址/端口与已有 flow 不符。 |
| `ttl` | TTL <= 1，交给内核处理。 |
| `mtu` | IP 报文超过缓存的有效 L3 MTU。 |
| `unsupported` | 入口/DSCP 不匹配，或报文/offload/checksum 等条件不满足。 |

map 不可读时只输出 `stats_available=0`，不伪造零 counter。
map 重新加载会重置计数，使用 `rate()` / `increase()` 处理重置。
采集只读取一个 per-CPU 元素，复杂度随可能的 CPU 数量增长，不扫描 flow 或 route 缓存，
不做路由查询、不触发业务收敛。

## 通用采集开销

metrics scrape 不进入 eBPF 转发 fast path，不触发 datapath reconcile。每次 scrape 会读取少量 eBPF stats map 和 `/proc` 虚拟文件：

- `/proc/self/stat`
- `/proc/self/status`
- `/proc/stat`
- `/proc/meminfo`
- `/proc/loadavg`

这些读取通常是轻量操作。建议 Prometheus scrape interval 使用 `15s` 或 `30s`；不建议多客户端高频并发抓取。
