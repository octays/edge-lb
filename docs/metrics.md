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
| `edge_lb_gateway_native_checksum_error_total` | counter | checksum 更新失败次数。 |
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

## 采集开销

metrics scrape 不进入 eBPF 转发 fast path，不触发 datapath reconcile。每次 scrape 会读取少量 eBPF stats map 和 `/proc` 虚拟文件：

- `/proc/self/stat`
- `/proc/self/status`
- `/proc/stat`
- `/proc/meminfo`
- `/proc/loadavg`

这些读取通常是轻量操作。建议 Prometheus scrape interval 使用 `15s` 或 `30s`；不建议多客户端高频并发抓取。
