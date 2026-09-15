# native flow map 持久化调研

本文记录 `NATIVE_FLOWS` 持久化的可行性、边界和首版实现路径。目标是让 gateway
进程重启、eBPF 程序重挂或主机短暂维护后，已有长生命周期会话尽量回到原 backend，
同时不增加 TC eBPF 热路径开销。

## 结论

可以做，且首版已经按 gateway-only 的后台运行态能力实现；不能在 datapath 每包路径里做
任何磁盘、SQLite 或同步 RPC 操作这个约束保持不变。

推荐方案是：后台周期性从 pinned `NATIVE_FLOWS` 生成本地二进制快照；启动时在 native
datapath 挂载并完成 listener/target reconcile 后，从快照恢复仍未过期、仍匹配当前配置的
flow pair。快照保存 `last_seen_age_ns` 或剩余 TTL，不保存本机 monotonic
`last_seen_ns` 绝对值。

该能力默认关闭，需要通过 `[gateway.flow_persistence]` 显式开启。开启后也要限制频率、批量、恢复数量和指标观测，
避免 1M flow map 下用户态全量扫描成为新的 CPU/IO 压力源。

## 当前基础

- `NATIVE_FLOWS` 是 pinned eBPF LRU map，当前容量为 `1048576` entry。
- 每条逻辑连接通常写正向和反向两条 entry，理想容量约 `524288` 对双向连接。
- 用户态已有 `dump_flows`、`upsert_flows` 和 `delete_flows`，可以读取和写回 pinned map。
- `sweep_flows_and_refresh_loads` 已能清理过期 flow，并从 flow map 重算 `lc` active flow。
- xSync wire 层已经使用 `last_seen_age_ns`，接收端按本机 monotonic clock 还原
  `last_seen_ns`。这个语义可以复用于本地持久化。
- 首版本地持久化使用 `state_dir/native-flows.snapshot` 二进制文件，支持 checksum、
  ABI/version 校验、启动恢复、关闭前 best-effort flush 和 Prometheus 指标。
- 现有 xSync 每 2 秒做一次全量 `dump_flows` 补偿。1M map 下，这条全量扫描路径本身也
  需要压测和指标观测。

## 需要解决的问题

### 单机重启

如果只是 `edge-lb` 进程重启，且 pinned map 和 TC attachment 没被销毁，flow map 原本
可能仍在内核里，不需要从磁盘恢复。持久化主要覆盖以下场景：

- eBPF 程序或 map 被重建；
- 主机重启；
- 包升级过程中 datapath 被重新加载；
- 进程退出后 pinned map 被清理；
- HA 节点长时间不可达，xSync 无法覆盖本机重启窗口。

### 时间语义

`NativeFlowValue.last_seen_ns` 是本机 monotonic clock，不能跨重启直接保存和恢复。
快照应保存：

- `saved_at_unix_ns`：快照写入 wall clock 时间；
- `last_seen_age_ns`：写快照时 `now_monotonic - last_seen_ns`；
- `timeout_secs`：flow 创建时复制的 listener idle timeout。

恢复时计算：

```text
restored_age_ns = last_seen_age_ns + max(0, now_unix_ns - saved_at_unix_ns)
```

若 `restored_age_ns >= timeout_secs`，该 flow 跳过；否则用当前 monotonic clock 生成新的
`last_seen_ns`。

wall clock 回拨时只能按 `elapsed=0` 处理，避免因为时钟回拨把已保存 flow 变得“更年轻”。
wall clock 大幅跳前时会更保守地丢弃 flow。

### target 身份

持久化不能盲目恢复旧 `target_id`。`target_id` 是 listener 内的运行态 slot，目标组重排、
删除或导入后可能变化。

当前实现的恢复顺序是：

1. 优先按 listener socket、协议、VIP、target 地址和端口精确匹配当前 endpoint，并重映射
   当前 `listener_id` / `target_id`。
2. 如果精确匹配失败，但 snapshot 来自 HA peer 的 xSync 复制，旧 target 地址可能是对端
   gateway 的 overlay 地址；此时仅在旧 `target_id` 仍落在当前 listener target 范围内，
   且 target port 一致时，才按 `target_id` 做受限 fallback。
3. fallback 恢复时必须把 `NativeFlowValue.target` 改写成本 gateway 当前 overlay target，
   反向 flow key 也基于改写后的 target 生成。

这个 fallback 依赖同一 target group 在 paired gateway 上保持相同目标顺序；如果目标组发生
删除、重排或端口变化，不匹配的 flow 会被计入 `skipped{reason="config"}`，不会写入 eBPF。

恢复时应使用目标端点身份重映射：

- 通过 `value.target` 和 `value.target_port` 找到当前 listener 目标组中的 endpoint；
- 找不到则跳过；
- 找到后使用当前 slot 写入新的 `target_id`；
- listener 必须仍然存在，且 VIP、协议、监听端口与 flow key/value 一致。

健康状态建议不作为默认恢复门槛。原因是当前内存态语义已经允许已有 flow 在 target
健康抖动时继续命中 `NATIVE_FLOWS`，直到 idle timeout 或显式删除。恢复只要求 endpoint
仍属于当前配置；如果 endpoint 已被删除或 listener 已变更，则不恢复。

## 存储形态

不建议把每条 flow 作为 SQLite row 写入现有 `resource_documents`：

- 1M entry 会产生大量行级写入和索引维护；
- 与业务配置 revision 语义混杂；
- SQLite 文件膨胀和 vacuum 会影响运维；
- 恢复路径需要大量随机读。

首版使用 state dir 下的单个二进制 snapshot 文件：

```text
/var/lib/edge-lb/native-flows.snapshot
/var/lib/edge-lb/native-flows.snapshot.tmp
```

写入流程：

1. dump 当前 flow map。
2. 过滤过期 entry，并按正反向 pair 去重。
3. 将 canonical flow pair 编码为定长二进制记录。
4. 写入 `.tmp`。
5. `fsync` 文件。
6. 原子 rename 到正式文件。
7. 尽量 `fsync` 父目录。

快照 header 至少包含：

| 字段 | 说明 |
| --- | --- |
| magic/version | 文件格式版本 |
| map_abi_version | `NativeFlowKey/NativeFlowValue` ABI 版本 |
| node_name | 写入节点名 |
| saved_at_unix_ns | 快照 wall clock 时间 |
| flow_capacity | 写快照时 map 容量 |
| record_count | canonical flow pair 数 |
| config_digest | listener/target 配置摘要 |
| checksum | 文件完整性校验 |

## 快照策略

默认建议：

| 参数 | 建议值 | 说明 |
| --- | --- | --- |
| enabled | false | 首版显式开启，避免默认引入扫描和 IO |
| interval_secs | 30 | SIP 长会话场景足够，低于 5 秒意义不大 |
| min_remaining_ttl_secs | 5 | 太接近过期的 flow 不写入 |
| max_records | 524288 | 与 1048576 entry 的双向容量匹配 |
| restore_on_start | true | 只在 native datapath attach/reconcile 后执行 |
| flush_on_shutdown | best-effort | SIGTERM 时尽力写一次，不能依赖它保证完整 |

写快照应由单独后台 worker 执行，不能阻塞 API、探测、xDS 或 HA 状态机。若当前 xSync
已经在同一周期执行全量 dump，后续实现应考虑共享扫描结果，避免 xSync reconcile 和
持久化 worker 在大 map 下重复扫表。

## 恢复策略

启动恢复顺序：

1. 初始化 SQLite 和本地配置。
2. 挂载 native datapath，创建 pinned maps。
3. reconcile listener、target、consistent hash bucket 和 DSCP map。
4. 读取 flow snapshot。
5. 过滤过期、ABI 不匹配、checksum 失败、配置不匹配的记录。
6. 按当前 target endpoint 重映射 `target_id`。
7. 生成正向和反向 entry，批量 `upsert_flows`。
8. 执行一次 `sweep_flows_and_refresh_loads`，刷新 `lc` active flow。
9. 暴露恢复结果 metrics 和日志。

恢复不能替代 xSync。HA 场景下，磁盘快照只负责本机重启窗口；跨 gateway 接管仍以 xSync
为准。如果 BACKUP 启动时本地 snapshot 较旧，而 xSync 随后收到 MASTER 更新，应以 xSync
较新的 `last_seen_ns` 覆盖本地旧值。

active gateway 归属变化会标记 native proxy state dirty，由 gateway 主循环执行完整
datapath reconcile 后再尝试恢复 flow。这样 peer activate、BFD promotion 和 ka-hook
promotion 不依赖“VIP 地址是否刚刚绑定”这个副作用来触发 listener map 重建。

## 一致性与失败处理

- 快照文件损坏：跳过并记录错误，不阻塞 gateway 启动。
- ABI/version 不匹配：跳过，避免旧结构写入新 map。
- 配置摘要不匹配：不应整体跳过，可以逐条按 listener/endpoint 校验恢复；摘要只作为
  诊断和快速判断依据。
- target 已删除：跳过该 flow。
- listener 已删除或协议/端口不匹配：跳过该 flow。
- 正反向 pair 不完整：跳过该 pair，不能恢复半条 NAT 状态。
- map 写满：停止恢复或按剩余 TTL/最近活跃排序截断，并计数。
- 启动后健康探测尚未完成：不把健康 unknown 作为恢复失败；只要求 endpoint 仍在配置中。

## 性能风险

持久化不会增加 eBPF 每包路径开销，但用户态全量扫描和写盘仍有成本：

- 1M entry map 使用 `iter()` 逐项读取可能产生明显 syscall 和 CPU 开销；
- 周期性写 100MB 级别快照会带来 IO 峰值；
- 与 xSync 2 秒全量 reconcile 叠加时，可能放大用户态 CPU；
- restore 大批量写 map 会拉长启动时间；
- LRU map 可能在恢复期间继续被新流写入，导致部分恢复 entry 被挤出。

首版已经补充 metrics：

| 指标 | 含义 |
| --- | --- |
| `edge_lb_gateway_native_flow_snapshot_records` | 最近一次写入的 canonical flow pair 数 |
| `edge_lb_gateway_native_flow_snapshot_duration_seconds` | dump、编码、fsync 总耗时 |
| `edge_lb_gateway_native_flow_snapshot_bytes` | 快照文件大小 |
| `edge_lb_gateway_native_flow_snapshot_errors_total` | 快照失败次数 |
| `edge_lb_gateway_native_flow_restore_records_total` | 启动恢复成功的 flow pair 数 |
| `edge_lb_gateway_native_flow_restore_skipped_total{reason=...}` | 过期、配置不匹配、pair 不完整等跳过原因 |
| `edge_lb_gateway_native_flow_restore_duration_seconds` | 恢复耗时 |

## 推荐落地步骤

1. [已实现] 增加 gateway 配置块 `gateway.flow_persistence`，默认关闭。
2. [已实现] 抽象 snapshot entry，使用 endpoint 身份而不是旧 `target_id` 作为恢复依据。
3. [已实现] 实现 snapshot 文件编码、checksum、原子写入和读取。
4. [已实现] 增加启动 restore hook，放在 native datapath reconcile 之后。
5. [已实现] 增加后台 snapshot worker，首版使用 30 秒 interval。
6. [已实现] 补充 metrics 和日志。
7. [部分实现] 单元测试已覆盖时间恢复、过期跳过、pair 不完整跳过和编码 round-trip；
   target 重排 remap、配置删除跳过需要继续补充。
8. [待验证] 在测试环境做回归：SIP/UDP 长会话、进程重启、eBPF 重挂、主机重启、HA 切换后再重启。

## 当前不建议做的事

- 不把 flow 持久化写入 datapath 热路径。
- 不保存或恢复 monotonic `last_seen_ns` 绝对值。
- 不把 flow 快照作为业务配置 revision。
- 不用旧 `target_id` 直接恢复。
- 不默认开启。
- 不承诺主机长时间停机后还能恢复会话。
- 不通过持久化修复 reverse key 冲突、两项非原子写入或 LRU 单项淘汰问题；这些仍属于
  flow map 正确性模型本身的问题。
