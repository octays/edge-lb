# edge-lb 全项目正确性与性能优化评估

评估日期：2026-09-09。基线：HEAD 676eed9，加评估时工作区已有的未提交修改；不是已发布版本或线上部署状态。本文重新核对当前实现，替代原文“基线问题 + 末尾补丁记录”混排的写法。

范围：edge-lb、edge-lb-common、edge-lb-ebpf、ui、tools/ha-bench、tools/backend-server，以及构建、部署、测试入口。重点追踪报文、配置写入、HA、后台任务的调用链，不声称逐行穷尽所有缺陷。首次评估仅更新本文；后续按用户授权实施的内容和验证结果记录在第 18 节，未部署、不调整项目版本。

## 1. 结论与评估方法

**先处理连接状态、配置事务和主备切换的正确性，再压测优化。** 当前值得投入的工作不限于 eBPF：业务写入并发丢更新、HA 同步相互等待、旧订阅清理、UI 错误处理也会影响可用性。没有同版本 CPU profile、PPS/CPS、活跃流量级和队列延迟基线，不能断言某一模块是主要瓶颈，或承诺 HashMap 能提升某个百分比。

证据标记：

- **[源码]**：当前代码可以直接确认的行为。
- **[推导]**：由代码构造的失败场景，尚未通过本轮真实网络/并发实验复现。
- **[待测]**：可行候选，是否值得实施取决于测量。
- **[已改]**：工作区已经包含实现；不代表发布或网络验收通过。

优先级不是工作量：P0 是转发错误、丢配置、HA 一致性风险；P1 是功能完整性、可用性和明确重复开销；P2 是需要 profile 支持的性能改造。每一项修复须补充测试和执行记录，不将“测试通过”写成“所有场景已验证”。

### 1.1 必须保持的约束

1. 管理模型只有监听配置、目标组和自动目标组模板；不恢复独立 endpoint API、外部 LB provider 或容器依赖。
2. 默认数据面是仅 DNAT、保留客户端真实 IP、backend 按 DSCP 经 VXLAN 回程、gateway 反向 NAT。任何改变源端口、分片处理、回程模式的方案必须单独说明语义。
3. HA 切换不得清空/重建 listener、target、DSCP 或 flow maps。切换只做接管动作与 active 状态同步；正常报文续期、探测健康更新和 xSync 副本维护继续运行。
4. backend 不依赖 MASTER/BACKUP，只接收配置回程所需的各 gateway 参数。节点离线不能靠持久缓存伪装在线。
5. 业务配置由 MASTER 权威写入并复制；本机接口、underlay 和绑定设备是本机配置。业务复制不能用对端的 underlay IP 覆盖本端。
6. 保留 L2、hook 接管能力；BGP 接管不在当前配置面暴露。“配置能保存”不等于“运行时已执行”，能力状态必须诚实。
7. 不以性能为理由扩大路由、nft、TC 或 pin 的删除范围；不降低 SQLite 持久性承诺，不默认削弱认证。

### 1.2 优先级总表

| ID | 级别 | 当前结论 | 主要入口 | 代价/风险 |
| --- | --- | --- | --- | --- |
| D1 | P0，部分已修 | 已有 flow 优先于 listener map；分片不建 flow；双向 flow 非事务、GC 与续期竞态仍在 | eBPF/main.rs、linux/native_dnat.rs | §32；仍需 map 世代与报文级测试 |
| D2 | P0，部分已修 | listener_id 稳定派生；配置变化优先刷新 pinned maps，设备/ABI 变化才重挂；无损发布仍需实机验证 | linux/native_dnat.rs | §32 |
| H1 | P0，部分已修 | xSync 跨机时间域和同批 delete/upsert 顺序已修；重连基线、世代和 ACK 语义仍不完整 | provider/native/xsync.rs | 中高，需协议与实机测试 |
| S1 | P0 | 本地业务快照/CAS/整批事务与持久化待复制游标已落地（§20、§22） | handlers/listeners.rs、storage/proxy_config.rs、storage/repository.rs | 非集群事务；数据面通知仍有崩溃边界 |
| H2 | P0 | 已实现快照序号、配对/角色 CAS、重放拒绝与后台重试；仲裁任期、晋升追平、客户端 op_id 和 UI 待做（§22） | storage/proxy_replication.rs、runtime/proxy_replication.rs | 后端核心已实施，尚不满足部署验收 |
| H3 | P0，部分已修 | 手动/peer 切换已改为本机接管动作成功后才提交 active 状态；peer handoff 失败会回滚本机角色；本机 takeover 失败会通知 peer 恢复原 active；远端确认丢失、双机 fencing 与实机切换仍待验证 | native/ha.rs、handlers/ha.rs | 中高，需双机故障注入 |
| D3 | P1；分片业务发布前阻断 | 报文解析缺少明确分片/ICMP 差错契约 | eBPF/main.rs | 中高，不能静默误解析 |
| C1 | P1，核心已修 | 订阅/overlay 原子更新、完整 ACK 清空及同版本 ACK 观测缓存已完成 | control/registry.rs、backend.rs | 第 18 节；线上重连验收待做 |
| U1 | P1，部分已修 | 目标组保存失败不再关闭弹窗；请求响应乱序仍待处理 | useNodeData.ts、TargetGroupsPage.vue | 第 18 节 |
| H4 | P1 | BFD 排队/失效恢复、GARP 执行与 hook 接管恢复 | runtime/bfd.rs、native/ha.rs | 中 |
| P1 | P1 | 探测已有独立到期时间，但仍串行且整批延迟发布 | native/probe.rs | 中，有界并发而非无限 spawn |
| R1 | P0 | 已落地本机 SQLite 所有权记录、外来冲突拒绝；崩溃窗口/特权并发边界见 §19 | linux/route.rs | 核心保护已修复，仍有部署前置条件 |
| R2 | P1，安全取值已修 | 已移除 send 即成功的伪探测，改为设备/已知路由 MTU 保守取值（§26）；主动反馈探测待做 | runtime/discovery.rs | 中，仍需真实跨低 MTU 链路验收 |
| O1 | P1 | 重复全表扫描、连接不复用、通知队头阻塞和无界历史 | native_dnat.rs、ha_write.rs、notify、storage | 低到中，分别实施 |
| T1 | P1 | 测试入口、生产 SQLite 路径和 HA 故障覆盖不足 | Makefile、workflow、runtime/state.rs | 中，优先构建可靠门禁 |
| O2 | P2 | 流续期节流、批量 map syscall、预编译调度表、UI 分包 | 各模块 | 先测再决定，不一揽子重写 |

## 2. 已有实现与应撤销的旧建议

| 项目 | 当前源码结论 | 本轮处理 |
| --- | --- | --- |
| TARGET_PORTS | [已改] HashMap<u32,u32> 单次查找；业务最多 16 个唯一端口，物理容量 32 容纳新旧集合 | 保留；不是“待改 Array 扫描” |
| DSCP_CFG | Array<u32> 只有一个元素，固定访问索引 0；用户态同值不写 | 保留 Array，不换 HashMap/PerCPU |
| DSCP stats | PerCpuArray，seen 已删除；只统计 matched/changed | 不重复开发，不删除故障计数 |
| DSCP 更新 | 端口先增加后删除、无变化跳过；ABI 检查包含新 map 类型 | 多个 insert 不是一次内核 batch，也不是整集合原子切换 |
| AgentState::save | gateway heal 没有 save；生产 save 写 SQLite，tmp+rename 仅 cfg(test) | 撤销“每 3s 写盘、每天省 28800 次 tmp+rename”的断言 |
| flow key 修复 | [已改] 建流、正向续期、回程共享 reverse_for/forward_for | 仅解决 key 一致性；未解决 D1 的并发/半对问题 |
| 探测修复 | [已改] HTTP body 匹配、TCP 分次读取、UDP 配置匹配时超时失败、独立到期时间 | 不再描述成旧代码；仍需解决串行调度和发布竞态 |
| 自动目标组 | [已改] 无节点可形成空组；gateway 启动有 3s 防抖，不再无限保留旧 targets | 继续验证真实离线、重连抖动和生成组的写入原子性 |
| xDS | [已改] 按实际下发快照编码算版本，backend apply 串行锁内重新合并；重操作移入 spawn_blocking | 继续查订阅和 overlay 生命周期，不重新增加 HA 主备字段 |
| 路由/nft | 已有 dump 后差量路由收敛；nft 删除/新建在同一 nfnetlink batch | 不误报为“尚无差量/必有删建空窗” |
| BFD | 已用 wren-bfd；收包线程与容量 8 的选举队列分离 | 不再建议第一次拆线程，检查执行和重试边界 |
| SQLite 日志 | 两处连接创建使用 sqlx_logging(false) | 已关闭 SQLx 查询日志，不是仍需降 debug |
| UI 数据加载 | 已按页面选择资源，不是启动加载所有列表 | 优化请求去重、取消和数据版本 |
| 依赖版本 | Cargo.lock：Aya 0.14.0、SeaORM 1.1.20、sqlx-sqlite 0.8.6、wren-bfd 0.3.1 | 删除旧文 Aya 0.13.1 的版本假设 |

Array 的单元素固定查找与端口集合查找不是同一问题。Array 元素预分配，PerCPU 为各 CPU 提供独立值，不适合仅因“读很多”就替换一个共享只读配置。[Linux Array map 文档](https://docs.kernel.org/bpf/map_array.html)

源码：[DSCP](../edge-lb/src/linux/dscp.rs)、[eBPF](../edge-lb-ebpf/src/main.rs)、[AgentState](../edge-lb/src/runtime/state.rs)、[gateway heal](../edge-lb/src/role/gateway.rs)。

## 3. DNAT/SNAT 与连接生命周期

源码：[eBPF/main.rs](../edge-lb-ebpf/src/main.rs) 的 try_native_dnat_ingress、try_native_dnat_return、adjust_active_flows；[native_dnat.rs](../edge-lb/src/linux/native_dnat.rs) 的 sweep_flows_and_refresh_loads、upsert_flows；[共享 key](../edge-lb-common/src/lib.rs)。

### 3.1 D1：不是补一次 lookup 就能解决的正确性问题

- [源码] NATIVE_FLOWS 为 1048576 项共享 LRU，每条逻辑连接通常占正反两项；理想容量约 524288 对，不是 1048576 条完整连接。insert/remove/output 多处忽略返回值，没有建流提交状态。
- [推导] 同一首包并发处理可分别选择后端；两项写入非原子，LRU 可单项淘汰，留下不完整或相互不匹配的映射。共享 map 的单项替换原子不等于跨项事务。[Linux Hash/LRU map 文档](https://docs.kernel.org/bpf/map_hash.html)
- [推导] 同一个客户端 IP/源端口访问两个 VIP 或监听端口，若映射到同一 backend IP/端口，反向五元组完全相同。reverse key 不携带原 VIP，BPF_ANY 会覆盖其归属，回包可能被改成另一监听的源地址。UDP 固定源端口可以构造此场景；单纯扩大 key、加入回包中不存在的字段不能解决识别问题。
- [源码] GC 先收集过期 key 再删除，报文可在中间续期；LC 全量重算会覆盖同时发生的增量。再次读取只缩小竞争窗口，不是 CAS。
- [源码] 回程 miss/过期走 PIPE；NAT helper 失败也会沿错误分支放行。[推导] 原始后端源地址或部分改写的包可能继续进入协议栈，不能把所有错误都当“非本程序流量”。

方案：先定义反向 tuple 的唯一性/冲突策略、单一建流所有者、完整流提交和删除世代，再选择具体 map 结构。冲突可先拒绝并计数；改选 backend 也不保证总能避开。引入源端口转换必须另行评审客户端语义，不能悄悄破坏仅 DNAT 的承诺。保留非本工具流量放行，对已确认归本工具且无法完成 NAT 的流量定义明确错误处理。

验收：同五元组多核并发、两 VIP 共享 backend tuple、正反向单向活跃、满 map、单项淘汰、插入失败、GC 与续期交错、rewrite 中途失败。必须有特权 eBPF/map 测试和真实报文，helper 单测不能替代。

### 3.2 D2：配置更新与稳定身份

[源码] native_dnat::apply 用展开后的 listeners Debug 字符串比较签名；不变时复用，否则先 drop 旧 attachment，再 attach_owned。attach_owned 重新建立 maps，并按展开数组顺序分配 listener_id、target_id。

[推导] 普通监听/目标组改动也可丢失其他监听的连接；新程序加载失败没有完整旧实例可继续服务。两端本地 IP 展开和目标顺序不同，会让相同数字 ID 指向不同逻辑资源。xSync 复制这些 ID，却没有配置 generation 校验。

建议：稳定的逻辑 listener/target ID 与本机 VIP lookup 分开；先校验并构造候选配置，再发布；配置增量不销毁 flow map。target 下线和删除分别定义既有连接的保留/终止策略。需要双缓冲时仅用于配置发布，不先搭一个泛化多版本框架。HA 切换无 map 重建测试和普通配置更新保流测试必须分开。

### 3.3 D3：解析与协议支持边界

[源码] 当前主要解析 Ethernet + IPv4 + TCP/UDP；可读 skb 长度不等于 IPv4 total_len、fragment offset、TCP/UDP 最小报文长度有效。未见完整的分片关联和 ICMP quoted tuple NAT 路径。

[推导] 非首片不能直接将 IP 负载当传输层头；首片被 NAT 后其他分片还要保持一致。ICMP 差错/PMTU 路径不完整可能影响较大 UDP/SIP 或跨 MTU 通信。VLAN/offload 场景也须明确支持范围。

先增加合法性检查和不支持场景的显式处理，再决定支持分片还是限制业务范围。验收含 IPv4 options、截断报文、首片/后续片、乱序分片、UDP 零校验和、GRO/GSO、ICMP 差错和不同 MTU；不能只跑小包 echo。

### 3.4 可测性能方向

1. 修复 D1 后合并维护周期的过期清理、负载统计和同步补偿视图，避免多次全扫。
2. 续期节流可能减少 flow-hit 的两次 insert，但需按最小 idle timeout 定义误差；同步副本必须按相同语义续期。不能直接硬编码 1 秒。
3. 原位原子更新时间戳、batch lookup/update 是候选，需验证内核、Aya、verifier、部分成功和 LRU 行为。不要把共享 flow map 改成 PerCPU map。
4. 同一路径两次 native_bump 可合并一次 stats lookup，属于低风险微优化，收益仍要 profile；保留 return_miss、insert/output failure 等诊断能力。
5. map 容量先做预算与饱和测试再参数化；运行期扩容通常涉及对象替换，不可承诺无损。

转发路径候选方案单独记录在 [forwarding-performance-options.md](forwarding-performance-options.md)，包括 veth、TC redirect、XDP 和 AF_XDP 的收益边界与验证顺序。此处不将任何 fast path 方案列为默认改造，仍要求先用 profile 和报文级压测证明瓶颈位置。

## 4. 调度算法与 DSCP

源码：[调度及 marker](../edge-lb-ebpf/src/main.rs)、[调度 helper/test](../edge-lb-common/src/lib.rs)、[用户态权重](../edge-lb/src/linux/native_dnat.rs)。

| 算法 | 当前语义 | 风险/优化 |
| --- | --- | --- |
| rr | 游标按全部槽位递增，再扫描可用槽位 | [推导] 槽位为健康/不健康/健康时，一轮选 0、2、2，健康目标并非等额 |
| hash | skb hash 对槽位数取模；不可用时取首个健康槽 | 故障槽集中到首个健康目标；不是最少连接，也不是一致性 hash |
| consistent_hash | 使用项目内稳定 flow hash 选择 1024 个预计算一致性桶；桶表由用户态基于健康目标和 64-bit HRW/Rendezvous 分数生成，流身份为客户端 IP、客户端源端口、监听端口和协议，不包含 VIP | 面向 SIP；保留现有 `hash` 不变；忽略权重，`weight=0` 仍视为不可选；eBPF 新流路径为常量查桶；metrics 暴露 bucket table digest 与 bucket hit/miss/unusable/fallback 计数；单测覆盖分布和目标增删迁移比例 |
| priority | 游标在健康权重总和内选择区间 | 实际是加权轮询；测试权重更新与健康变化的发布一致性 |
| persist | 客户端 IPv4 字节异或得到槽位和 fallback | 客户端粘性，不提供实时负载均衡；加载时强制使用默认 3h timeout，需与监听 idle timeout 文案统一 |
| lc | 新流遍历目标、读活动 flow 数，游标打破平局 | 计的是 flow 生命周期，不是真实 ESTABLISHED；并发读改写和 GC 重算有竞争 |

修正确性时不要未经评审更改所有算法语义。现有 `hash` 是兼容性语义，必须继续使用 skb hash 取模；一致性选择只能通过新增 `consistent_hash` 实现。先测不健康槽分布、并发 RR/LC、权重零/边界、目标增删；hash/persist 的稳定性包含数组排序和 hash 输入，不能假设不同主机的 skb hash 一定相同。已建流靠 flow 复用而非每包重新调度。

2026-09-15 的 `consistent_hash` 高并发回归见 [high-concurrency-test-report-2026-09-11.md](high-concurrency-test-report-2026-09-11.md)：最终部署后 `concurrency=64`、`timeout=5000ms` 下 TCP 成功 CPS `8934.3`、默认 UDP socket 复用吞吐 `30959.5 req/s`，TCP 0 失败，UDP 54 次 timeout。active gateway 未记录 target miss、return miss、checksum error、bucket miss、unusable bucket 或 consistent-hash fallback。默认 UDP 分布偏斜主要来自 `ha-bench` 复用 worker UDP socket，源端口样本有限；使用 `--udp-new-socket-per-request` 后去重源端口样本提升到 `55536`，UDP 吞吐 `63951.5 req/s`，0 失败，分布约 `51.0% / 49.0%`，可用于判断真实多客户端源端口分布。

健康目标索引、累积权重表可以在配置变化时构建，降低新建流扫描；只在目标数和 CPS 显示收益时实施。LC 的扫描成本只在新流发生，不能用它解释全部长连接 PPS。n2/n3 不纳入本轮。

DSCP 端口 HashMap 已落地，接下来测 1/8/16 个端口、命中/不命中、仅 DSCP marker 与完整 DNAT 两种路径。单端口时旧 Array 可能也只查一次；“每包省 15 次”仅是旧实现特定扫描位置的上界，不是普遍收益。

端口集合与 DSCP_CFG 独立更新不是整体原子切换；正常小范围更新可接受短暂旧/新并集，但修改 DSCP 会影响 backend 回程，必须定义配置协同窗口。TC attachment 检查仍有文本匹配，适合改用已有结构化 netlink 信息，精确匹配设备、方向、priority 和程序身份，不额外依赖系统命令。

## 5. H1：xSync 连接同步

源码：[xsync.rs](../edge-lb/src/provider/native/xsync.rs) 的 sync_session_grpc、apply_proto_request、entry_to_proto/from_proto；[flow apply](../edge-lb/src/linux/native_dnat.rs)。

### 正确性

- [已改] wire 层传输 `last_seen_age_ns`，接收端按本机 CLOCK_MONOTONIC 还原
  `last_seen_ns`。map 内部仍只保存本机 monotonic 时间，跨机不得直接比较绝对
  `last_seen_ns`。重传会按当前 age 重新映射，不能持续延寿。
- [已改] 发送前按 key 折叠一批 flow 事件：delete 后 upsert 保留最终 upsert，
  多个 upsert 保留最新 `last_seen_ns`，被 upsert 覆盖的 delete 不发送。
- [推导] 事件级顺序仍没有 epoch/sequence。跨批删除后重建、慢 ACK 与重连全量基线之间仍可能需要更明确的 generation/ACK 语义。
- [源码] replica 索引跨重连保留，事件 reader 在 session 建立时打开；没有接收 map generation 握手。[推导] 对端重建 map 后旧索引仍认为已复制，reader 也可能还在旧 map 上。
- [已改] ACK 只有在已挂载 native flow map 接受本批全部操作时才推进发送端
  replica 索引；幂等 upsert/delete no-op 计为已接受，map 不存在返回 0 并保留
  backlog。ACK 仍不是配置 generation 或切主任期证明。
- [源码] sender/receiver 校验角色，但没有绑定完整配置世代与操作顺序；仅拥有 token 不等于状态就可应用。

### 性能与执行顺序

当前为 25ms 轮询、2s 补偿；补偿 sweep 后再 dump，gateway heal 还会 sweep。活跃时间戳不断变，补偿不是仅发送丢失的新连接。drain 到空没有消费时间/数量上限；gRPC 队列限制消息数，不限制单条 entries 大小；异步接收任务内仍同步做存储和 map 操作。

先落地顺序折叠、世代/ACK、重连全量基线、单批条数/字节上限和有限消费预算，再合并遍历。RingBuf 可用 poll/epoll 等待，但不能取消补偿扫描：事件丢失、LRU 淘汰和活跃续期仍需兜底。[Linux ring buffer 文档](https://docs.kernel.org/bpf/ringbuf.html)

验收：不同 uptime、同 key 删除重建、对端重启、ring 满、慢 ACK、分批中途断线、map 重建、角色互换、无 HA 的独立 GC。记录 ACK 延迟、落后序号、事件丢失、补偿耗时和有效 flow 对数，不能只比较两端 map 项数。

## 6. S1：SQLite、配置模型与事务

源码：[repository.rs](../edge-lb/src/storage/repository.rs)、[storage 初始化](../edge-lb/src/storage/mod.rs)、[listeners.rs](../edge-lb/src/api/handlers/listeners.rs)、[native/store.rs](../edge-lb/src/provider/native/store.rs)。

### 6.1 统一 SQLite 不等于统一事务

[初始发现，第三批已修复本地路径] Repository 单个 Put 会在事务中写 revision 与 resource document，但原 listener create 先修改 native state，再独立读改写 listeners/config；update 先删旧 native listener、再建新、再写 canonical 列表；删除和导入也跨多个操作。

[推导] 4 个 API worker 可同时读同一旧列表，随后各自覆盖整列表，丢掉另一请求的修改。任一步失败还可能出现“API 报失败，但部分状态已经生效”。native::with_state_lock 不覆盖外层列表读改写，也不是跨资源事务。

建议最小实现是一个业务 mutation 入口：事务内读取/校验预期版本、引用约束、写 listener/target-group 与 revision/待复制记录；事务后调度派生数据面，不在 DB 事务内等待网络或 netlink。SQLite desired config 为唯一权威，health、运行时 map 状态与复制状态分开。不要再给每个入口增加一套 cache/锁/JSON 包装。

导入先明确“整体事务”或“逐条结果”契约；不能处理一半失败后仅返回一个通用错误而不报告已提交项。

第三批已实现监听与目标组共用事务快照读取与 CAS mutation，引用校验在版本冲突后重跑；两个资源及版本记录一次提交，导入整批提交。native 投影只在提交后派生，不再成为 GET 回填或配置恢复来源。第五批将持久化待复制游标加入同一事务，并添加 HA 角色/配对的只读 CAS 条件；复制任期与仲裁边界见 §22。

### 6.2 已存在的重复模型

初始实现的 ListenerConfigResource、Listener、NativeListenerStateEntry 和展开的 NativeListener 同时存在。eBPF scalar key 属于合理编译产物，但由缺字段推断 target group、GET 时回填 listeners/config 增加双重真相。第三批已移除反向恢复和 GET 回填；API DTO 与内部编译投影仍各有边界，不把保留投影等同于保留第二份业务权威。

建议保留明确的 API DTO/业务模型/数据面布局边界，而不是机械合成一个结构体；删掉中间可写真相和隐式读时迁移。VIP 在本机解析，UI 显示实际有效 IP，不能靠列表聚合掩盖错误存储。

### 6.3 SQLite 性能与可维护性

- [源码] repository 用容量 128 的同步队列和单线程 worker；send/recv 无应用级超时，串行执行；调用方的“get 再 put”不是队列中的原子命令。
- [源码，§30/§31 已部分处理] Delete 仍记录 revision；通知投递记录已经限制为最近 512 条。通知配置和自动化模板保存已跳过内容不变写入，业务配置 revision 历史仍按后续批次处理。
- [源码] initialize_async 建连接设置 PRAGMA 后关闭，Repository 再建连接。foreign_keys、busy_timeout 是连接级设置，不能依赖前一连接继承；应检查真实 worker 连接并显式配置。SQLx 默认值可能已满足部分要求，本轮不宣称外键当前必然关闭。[SQLite PRAGMA 文档](https://www.sqlite.org/pragma.html)
- next_revision 是进程内原子值结合 wall clock，不是集群任期。第五批在 Repository 启动读取数据库最大 revision 作为下限，防止重启时 wall clock 落后导致重复；副本使用另一个持久化 sequence 排序，不用本地 revision 承担分布式 fencing。
- 首先记录队列等待、SQL 执行、序列化、事务耗时、WAL 大小；再决定读缓存/连接复用方式，不直接增加 rusqlite 双栈或把 SQLite synchronous 改成 NORMAL。
- SQLite 存 token/通知凭据时应验证 DB、WAL、目录及备份权限，并检查 API 导出脱敏。鉴权成功不代表所有字段都适合返回。

验收：并发创建两个不同监听都保留；目标组删除与监听创建竞争；每阶段注入写失败；重复导入与相同内容零变更；重启读取、旧版本 CAS 拒绝、实际 SQLite 连接参数检查。

## 7. H2：HA 业务配置权威写入

源码：[proxy_config.rs](../edge-lb/src/api/handlers/proxy_config.rs)、[ha_write.rs](../edge-lb/src/runtime/ha_write.rs)、[API server](../edge-lb/src/api/server.rs)。

### 7.1 同步转发形成的相互等待

[初始源码，第四批已修复等待环] BACKUP worker 同步等待 MASTER；MASTER 本机提交后同步回写 BACKUP 的 replica API。原先两个端点都由同一组 4 个 blocking HTTP worker 服务。

[推导] 对 BACKUP 发起 4 个并发写请求，可占满 4 个 worker 等待 MASTER；MASTER 的回写需要 BACKUP 空闲 worker，因此形成等待环，直到 HTTP 超时才可能释放。不能把它写成无限死锁，也不能靠“线程从 4 改到 16”根治。

建议配置提交与副本回写脱离请求线程循环等待。可用事务 outbox + 独立复制消费者，并明确 local_committed/replica_applied 和失败状态；若要求双端落盘后才成功，等待机制也不能占住对端处理复制所需的执行资源。异步 HTTP/gRPC 是手段，不是事务与排序的替代。

第四批先落地可独立验证的接收侧隔离：三个终结型副本接口有独立 worker，普通 4 worker 不变；两类队列各 32，非阻塞分发、满载 503。不是把所有请求线程数调大，且不能让会再次访问对端的 `/active` 占用保留 worker。实际 loopback HTTP 等待环与队列满载测试通过，证据和剩余边界见 §21。

### 7.2 缺少版本化、幂等和角色屏障

- [初始源码，第五批更换副本协议] ProxyConfigOperation 现在只负责客户端/BACKUP 向 MASTER 的操作转发，仍无客户端 operation_id。副本端不再重放操作，改为接收 sequence/source/pairing_id/hash 与完整业务快照，并在提交时校验角色和配对版本。
- [当前边界] 同配对旧版本、同版本不同内容和升主后的副本写会拒绝；HA 本机业务提交返回 202，由后台重试，不再因副本失败将已提交写入报成 502。但 BACKUP 向 MASTER 转发超时仍可能不知道是否已提交，且缺少 quorum/任期/晋升追平，不能宣称解决分区后的配置丢失。
- [初始源码，第三批本地重放已修] create_or_replace_config_local 原先使用创建冲突校验，已有同名监听重放可能被自己挡住；现已在同一业务快照内替换，仍无集群 op_id/顺序保障。
- [初始源码，第四批已修] peer 请求原先每次重建 blocking reqwest Client；现读写共享池、逐请求 token、User-Agent 使用编译版本，响应体读取失败明确返回错误。

应在 S1 的事务基础上加操作 ID、权威任期/版本、幂等应用、旧副本拒绝、可重试回写与重新入群基线。共享业务配置复制不携带本机 VIP 展开结果。通知、自动目标组模板复用这一模型，但不在没有必要时强行把所有控制协议合成一个超大消息。

验收：对 BACKUP 并发 4/8 写入、返回前断网、同操作重放、反序到达、写入同时切主、对端 SQLite 清空后重同步。两端内容 hash/版本以及 API 成功语义必须一致。

## 8. H3/H4：BFD、接管与故障恢复

源码：[bfd.rs](../edge-lb/src/runtime/bfd.rs)、[native/ha.rs](../edge-lb/src/provider/native/ha.rs)、[peer_activate](../edge-lb/src/api/handlers/ha.rs)、[GARP helper](../edge-lb/src/runtime/ka_hook.rs)。

### 8.1 切换状态机

[源码] patch 分支的切换提交顺序已经收紧：切到对端时先在本机执行 BACKUP 角色、解绑 VIP，再通知对端升主；若对端激活失败，本机会尝试恢复本机 MASTER 角色。切到本机时先要求对端降级，对端 `peer_activate` 先执行本机角色变更，再提交 active 状态；若本机升主失败，会通知对端恢复原 active。[推导] 这消除了“角色动作失败但 active 已经提交”的本地时序问题，但仍没有形成完整的跨节点事务。

计划：切换操作 ID/任期、准备与完成状态、超时查询确认、幂等续做；已提交 active、实际绑定/宣告和回滚结果分别可观测。不得声称两个节点仅靠 BFD 就能在完全网络分区时同时保证“始终唯一主”和“始终自动可用”；严格唯一主需要租约/仲裁/外部 fencing 之类的独立证明，若不引入则必须明确故障边界。

手动切换和 BFD 接管要走同一受保护执行入口，避免两个地方各自写 active 和操作 VIP。保持切换不重建业务 maps 的现有保护。

### 8.2 BFD 队列与 GARP

- [源码] 收包已经独立；选举队列满时丢请求并告警，工作项携带旧 cfg/ha_cfg；只有状态迁移等时机入队，执行失败没有通用的最终状态重试保证。
- [推导] 上一轮慢 peer HTTP/GARP 阻塞执行队列时，过时配置任务可能晚到，最后一次迁移也可能丢失。建议保存最新期望状态/世代并合并任务，执行前重新核对；失败有界重试，不让旧任务覆盖新状态。
- 接收循环的 timeout 按本机 interval × multiplier 计算；使用 wren-bfd Session 不等于完整遵守其全部协商/计时语义。补两端不同 interval、刚启动对端不可达、鉴权成功但 FSM 不接受的包等测试，不先重写 BFD 库。
- GARP burst 当前同步执行；绑定成功但 announce 失败后，reconcile_vip 看到已经 bound 不会自动再次宣告。分开记录“地址已绑”和“宣告待完成”，带角色世代调度重复 GARP，降主立即取消旧任务。
- 对 GARP count/总耗时设置合理边界，不能让一次配置把切换执行线程占用很久。

### 8.3 Hook 接管执行器

[源码] BGP 接管模式已经从 UI/capability 移除，历史或外部输入的 `bgp` provider
归一化为 `hook`，避免“配置可保存但无执行器”。hook 模式固定使用
`/usr/local/bin/edge-lb-promote`、`/usr/local/bin/edge-lb-demote` 和
`/usr/local/bin/edge-lb-verify-vip`；路径不允许通过 UI/API 修改。

切换执行顺序为 MASTER 执行 promote 后 verify，BACKUP 执行 demote 后 verify。
脚本返回非 0 时切换失败。当前执行器按本进程内最后状态去重，避免周期性
`reconcile_vip` 重复执行 hook；跨进程重启后会按当前状态重新执行一次，用于恢复
外部 VIP 状态。

## 9. xDS、节点注册与 overlay

源码：[registry.rs](../edge-lb/src/control/registry.rs)、[gateway.rs](../edge-lb/src/control/gateway.rs)、[backend.rs](../edge-lb/src/control/backend.rs)、[snapshot.rs](../edge-lb/src/control/snapshot.rs)。

C1 的两个明确问题：

以下是修复前的复现场景；第 18 节已实施注册表与 ACK 修复，不再列为当前仍存在的同一缺陷。

1. remove(node_name, stream_id) 对 ACTIVE_BACKEND_SUBSCRIPTIONS 检查 stream_id，但随后无条件移除 KNOWN_BACKEND_NODES 的同名项。[推导] 旧流退出可清掉新连接的 overlay 分配缓存，后续 active_backend_nodes 得到 auto 并重新分配。TTL 清理与重新注册也要用同一世代边界。
2. touch 仅在 req.conflicts 非空时更新 conflicts。[推导] 已恢复节点发送 conflicts=[]，旧冲突仍可留在 UI，造成“已修但一直报警”。心跳与完整 ACK 应区分，完整状态要允许显式清空。

建议把订阅状态与对应 overlay 分配放在可原子更新的节点记录里，不恢复磁盘在线列表。回归：旧流晚退出、新流已注册、TTL 清理交错、名称相同地址变化、零冲突 ACK、两 gateway 独立订阅和分配稳定性。

性能：快照版本与实际下发字段一致已改；同版本 ACK 不应触发配置应用。测每 backend 快照构造耗时、序列化字节和应用次数，再考虑按“配置版本 + 订阅版本 + backend 身份”缓存不可变快照。不要为了共享缓存把不需要的 HA/业务字段重新发给 backend。

registry JSON 序列化、全量 clone 和 TTL 扫描应缩短持锁时间；减少锁前先测，不能用不一致的两个快照替换原本正确的原子操作。在线 TTL 的时钟也应避免 wall-clock 调整导致误过期。

## 10. Backend 路由、nft 和 Linux 调用

源码：[route.rs](../edge-lb/src/linux/route.rs)、[return_path.rs](../edge-lb/src/linux/return_path.rs)、[nftables.rs](../edge-lb/src/linux/nftables.rs)、[net.rs](../edge-lb/src/linux/net.rs)。

已完成：路由同轮复用 socket、dump 后差量收敛；nft 规则在单个 batch 更新；backend 回程使用 gateway 维度与 DSCP；netlink 调用不依赖宿主机 ip/nft/bpftool 命令。

R1 初始发现：reconcile_table_on_socket 将派生区间内不符合 expected 的条目视为可删；rule_is_ours_family 只要 mark 或 table 在区间内就认为是本工具规则。**数值区间不是独占所有权证明。** 第二批已删除该判断和字符串 ownership 推断，落地本机 SQLite 创建记录、精确匹配、冲突拒绝以及共享 preflight 校验，验证见 §19。不能将其等同于内核/SQLite 跨系统事务，或对其他特权写入者的绝对隔离。

return_path::heal 仅以 nft 表存在判定内容有效；表还在而 chain/rule 被删不会自愈。将轻量 liveness 与低频内容审计分开，用期望指纹与实际规则检查，不能为了降开销取消恢复能力。

net::run_netlink 每次构建 runtime，已经处理嵌套 runtime 情况；有 runtime 时转到 scoped thread 再 join，避免 panic，但仍阻塞调用者。优先复用一轮 netlink 工作上下文，把阻塞边界放在整个 apply 外层；不再给每一个小 helper 搭线程池。

同配置避免 nft 重建，保留原子 batch；端口/规则足够多时再评估 nft set/map。nft、route、FDB 是不同子系统，跨它们的操作没有整体原子性，需要失败续做。

### 10.1 自动发现与 PMTU

源码：[discovery.rs](../edge-lb/src/runtime/discovery.rs)。STUN 已使用 stunclient，不需要重新实现协议。但 local_public_ip 按服务器列表同步尝试，每个客户端设 3s timeout；API load_config 会走自动发现，没有统一的运行时结果缓存。建议启动/网络变化时刷新并保留来源、时间和错误状态，API 读取已发布快照，避免每次请求受外部 STUN/DNS 延迟影响。

R2：[初始源码，§26 已删除] 名为 ping_ipv4_no_fragment 的函数实际创建 UDP socket 发往端口 33434，启用 IP_PMTUDISC_DO 后仅检查 send 成功，未等待响应/错误队列；二分搜索据此记 best。send 成功仅说明本地发送路径接受，不证明远端收到；中途链路 MTU 更小或 ICMP 被屏蔽时不能标记“PMTU 实测成功”。当前仅使用设备及内核已知路由 MTU，按普通 1500 外层预算封顶，标记 path_verified=false；主动反馈探测仍待实现。UDP 异步错误与 PMTU 行为见 [Linux UDP 手册](https://man7.org/linux/man-pages/man7/udp.7.html)。

### 10.2 主机调优边界

源码：[sysctl.rs](../edge-lb/src/linux/sysctl.rs)。当前不仅开启必要的 ip_forward，还硬编码提升 somaxconn/backlog/socket buffer/conntrack 上限，并降低 tcp_fin_timeout；没有在此入口看到逐项 opt-in。floor 只保证不降低更大的容量值，不代表没有主机级副作用。

建议将必需的转发能力与可选容量调优分开：后者显式授权、报告旧值/目标值、按内存和实际瓶颈判断。socket buffer max 是允许上限，不是立即为所有 socket 分配 128MiB；conntrack 上限也不是立即占用固定内存。tcp_fin_timeout 不是 TIME_WAIT 清理开关，不应拿它解决所有短连接开销。[Linux IP sysctl 文档](https://docs.kernel.org/networking/ip-sysctl.html)

## 11. 健康探测

源码：[probe.rs](../edge-lb/src/provider/native/probe.rs)、[target_groups handler](../edge-lb/src/api/handlers/target_groups.rs)、[目标组模型](../edge-lb/src/provider/native/api_model.rs)。

已经具备：仅绑定监听的组被探测；HTTP/HTTPS 共用长期 Client 并区分证书策略；HTTP 状态码/body 匹配；TCP 请求与分段响应匹配；UDP 配置匹配时超时失败；结果写回前核对探测定义。

P1 剩余问题：

- probe_round 顺序执行所有到期目标，执行完一批才 apply_results；一个坏目标会拖延其他目标结果发布。N 个不可达目标的轮次耗时随 N 增长，独立 due time 不等于独立执行。
- 周期当前从完成时刻起算，再加 worker 1s tick；它是 fixed-delay，不是严格 fixed-rate。先定义允许的探测抖动，不要把 retries × period 当作准确摘除上界。
- 无 probe_port 时取第一个引用监听的 target_port，然后把结果写给该组所有 listener identities。[推导] 一个组被不同目标端口引用时，顺序决定健康语义。按目标组最小单位的约束，应要求明确探测端口，或制定唯一、可验证的缺省规则，不能暗中取第一个。
- 调度 key 包含 listener identities。仅增加引用监听也可能重置同一组的失败次数/计划；建议按 group + target + probe config generation 管理探测，监听绑定只决定启停。
- 发布前再次检查配置仍不是带 generation 的原子提交；并发配置变化窗口还存在。
- UDP 未配置匹配时，timeout 被判可达而非“应用已回应”。必须在协议说明和 UI 表达此差异；reqwest 复用只适用于 HTTP/HTTPS，不能声称 raw TCP/UDP 也通过它复用连接。

实施：有界并发调度、每目标绝对 deadline、按时完成即可提交、generation 拒绝旧结果；相同 probe 配置不重建 Client。重构后以 1/16/64 个目标混合快成功/慢超时，测试调度抖动、失败阈值、配置中途删除、TLS 切换、HTTP 大 body、TCP 分片、UDP 错误/超时，保持现有语义合同。

## 12. 自动目标组、通知、API 与日志

### 12.1 自动目标组

源码：[filter.rs](../edge-lb/src/automation/filter.rs)、[validate.rs](../edge-lb/src/automation/validate.rs)、[sync.rs](../edge-lb/src/automation/sync.rs)、[gateway reconcile](../edge-lb/src/role/gateway.rs)。

[源码] Regex::new 在每个 node/condition 匹配时执行，CIDR 也重复解析，字段取值会 clone 字符串。建议模板校验时编译匹配器，按模板版本复用；不引入通用脚本引擎。非法规则在保存时拒绝，运行时不应只 unwrap_or(false) 静默变成“无节点”。

3s trailing debounce 对持续抖动可能一直推迟生成；先测再决定增加最大等待时间。无匹配仍保持空目标组，组名归属/同名模板冲突要显式校验。模板保存、生成组更新和 HA 回写需要复用 S1/H2，不各自写一套事务。

### 12.2 通知

源码：[notify/mod.rs](../edge-lb/src/notify/mod.rs)、[store.rs](../edge-lb/src/notify/store.rs)、[events.rs](../edge-lb/src/events.rs)。

[源码，第 29 节已修响应读取边界] 已复用 dispatcher HTTP Client，有容量 1024 的队列，但所有事件/渠道串行；最多 5 次尝试，每次 HTTP timeout 8s，加退避。一个失败 webhook 可长时间阻塞其他关键事件；队满 try_send 丢弃并告警。响应读取已限制为 2048 字符诊断文本，实际读取最多 `limit + 1` 字节后截断。投递记录仍持续追加。

建议有界渠道并发和独立重试调度，关键事件延迟/丢失计数；是否需要 durable outbox 按通知交付承诺决定，不先承诺 exactly-once。按失败类别重试并处理 Retry-After，给历史设保留上限。避免将带 token 的 URL 或响应秘密原样写日志。

### 12.3 API 资源保护与状态查询

[源码，第 28 节已修 body 读取边界] API 每请求先 load_config/自动发现/HA 合并，再鉴权；body 已限制为 1 MiB，声明超限或实际读取超限返回 413，读取错误和非法 UTF-8 返回 400。4 个同步 worker 仍承担状态、写入、运维和 HA 请求，静态资源复制 bytes 到 Vec，没有 ETag 等缓存响应模型。

优先：缓存最小鉴权配置并先认证，限制读取时间/并发重操作，peer Client 复用，阻塞任务隔离。状态读取复用最近观测及 freshness，不因刷新页面执行全量 apply；不把缓存过期状态伪装“健康”。

静态缓存、预压缩资源、分页放在容量证据之后；不为了小规模管理 UI 加完整缓存平台。公开 API 只接受当前 /api/v1 资源面：监听配置、目标组、自动目标组、通知、节点、HA、apply/cleanup。整体配置替换、metrics、HTTP verify、legacy operations/failover 已从公开入口移除，避免 UI/API 接入重新绕回旧模型。

### 12.4 日志与生命周期

状态迁移用 info，周期性成功/无变化用 debug；重复失败去重或限频，但保留首次错误与恢复记录，不能把所有异常降到 debug。BFD/复制/探测使用有界标签，不把完整五元组作为高基数指标标签。

API worker 和通知 worker 的阻塞 recv 缺少一致的 shutdown/drain/join 契约。明确停机先停止接收新操作、完成或取消有限在途任务、完成 HA 交接、清理本工具对象；禁止通过更激进清理降低“停机耗时”却影响其他程序。

## 13. UI 正确性、契约与加载

源码：[useNodeData.ts](../ui/src/composables/useNodeData.ts)、[client.ts](../ui/src/api/client.ts)、[TargetGroupsPage.vue](../ui/src/components/target-groups/TargetGroupsPage.vue)、[App.vue](../ui/src/App.vue)。

U1：[已修，第 18 节] 原实现 run 捕获错误后不返回失败状态，目标组保存用 !busy 关闭弹窗，失败也会关闭。现已让 run 返回 boolean，并只在写入成功时关闭；移除保存路径的额外一次 refreshTargetGroupData，统一由 run 刷新。refreshAll 的读取错误保留显示，不改变已提交写入的成功结果。

请求级问题：无 AbortSignal/timeout/同资源去重或世代判断；快速切页、保存后刷新与旧请求并发时，较早响应可能覆盖新状态。busy 是单个字符串，多操作相互清空；注销仅清少量字段，页面级共享 refs 仍保留旧列表。增加按资源的请求生命周期、latest-wins 和完整 logout reset；不要求先换状态管理框架。

类型检查通过不等于 JSON 契约正确。表单、导入、API、HA payload 应对名称、tcp+udp 集合、端口、probe 字段使用同一规则并有契约测试；JS 与 Rust 正则支持范围不完全相同，前端校验只做提前反馈，后端仍权威。

UI 已按页加载数据，但页面模块仍在 App 静态 import；是否动态分包取决于实际 bundle 和首屏时间。继续使用 shadcn-vue，不手写替代控件。新增 Playwright 覆盖失败不关弹窗、重复提交、切页乱序、健康字段切换、导入错误、HA 状态刷新与移动端布局。

## 14. 测试、构建与压测工具

源码：[Makefile](../Makefile)、[build.yml](../.github/workflows/build.yml)、[ha-bench](../tools/ha-bench/src/main.rs)、[backend-server](../tools/backend-server/src/server.rs)。

### 14.1 测试门禁

- make test 只执行 cargo test -p edge-lb，不包含 common/tools；不能把它称为全 workspace 测试。
- 当前 workflow 构建 UI/eBPF/二进制与包，但未见 fmt、typecheck、Rust 单测作为发布前门禁。make ui 只 build，不能替代 vue-tsc。
- AgentState 的 cfg(test) 使用 JSON 文件，生产使用 SQLite；部分测试没有覆盖真实持久化路径。测试应使用隔离 SQLite repo/依赖注入，而不是重新引入生产 JSON 兼容。
- 普通单测不能证明 TC verifier、多核 map、netlink 所有权、双机 HTTP worker 竞争和真实 HA 中断窗口。
- 构建容器 Rust 基础镜像使用浮动 tag；固定可追溯工具链、依赖锁、eBPF object/二进制 ABI 和发布 manifest。UPX 只影响制品大小/启动解压与运行内存特征，不能当作 PPS 优化；压缩与未压缩产物分别 smoke test。

建议拆“快速合同单测”和“Linux 特权/双节点网络测试”，最终 tag 发布复用已验证产物；不让只有 helper 测试通过的镜像被标成 HA 无损验收完成。

### 14.2 压测工具本身的偏差

[源码] ha-bench 每次延迟存为 u128 到 Vec，汇总 clone 后排序；--out 下每请求抢共享输出锁。请求完成数用配置 duration 做除数，尾部完成时间/启动开销未单列；TCP reuse 在部分失败后自动重连重试。

建议每 worker 直方图/有界采样、可选原始明细和批量异步输出，记录实际开始/停止/排空时间。分别输出首次尝试失败、重试次数、重连次数和最终成功，HA 测试不能让自动重连把“连接断了”统计成“连接保持”。同时报告尝试 RPS 与成功 RPS。

backend-server 的 TCP 每连接线程、串行 UDP 接收可能先达到瓶颈；新建连接模式测 CPS，复用模式测应用请求吞吐，既不是直接 PPS 也不是压测机无限容量。达到上限前同时采集 client/gateway/backend CPU、线程、socket 错误、softirq 和网卡丢包。

### 14.3 CLI、安装与配置输出

源码：[cli.rs](../edge-lb/src/cli.rs)、[install.rs](../edge-lb/src/install.rs)、[config/render.rs](../edge-lb/src/config/render.rs)。默认按 node_role 启动已经存在；install 使用位置角色参数，不再增加等价的 --role/--node-role 别名。隐藏 gateway/backend 子命令和内部 helper 是否仍有必要，需按实际调用者清理，不能只隐藏帮助后认定旧入口已删除。

[源码] install_binary 先 fs::copy 到正式路径，随后才校验/写配置和 unit；write_unit 直接写正式文件。[推导] 运行中覆盖二进制可能失败，配置校验失败也可能留下部分安装结果。建议先验证全部参数，写临时制品并检查，再原子替换；安装失败应报告哪些步骤已完成，不把卸载变成无差别清状态。

已有 config.toml 且未 --force 时 write_config 保留原文件，却返回请求角色供成功提示使用。[推导] 指定新角色但保留旧配置时，提示角色和下次实际启动角色可能不同；应拒绝冲突或明确报告实际角色。角色模板、TOML render/load 需 round-trip 测试，确保端口、认证、网络和可选字段不静默丢失。

## 15. 分阶段执行与验收计划

所有以下未勾选项都是计划，不表示本轮已实现。

| 阶段 | 执行项 | 完成标准 |
| --- | --- | --- |
| A：固定合同与复现 | [x] R1 外来路由/规则保护（§19 边界）；[x] C1 旧流退出/空 ACK；[x] U1 保存失败；[x] S1 并发写/回滚；[ ] H2 双机重放和 4 worker 场景 | 明确复现与回归证据，不把纯单测当真实网络验收 |
| B：业务权威 | [x] 单一 SQLite mutation、跨资源事务、CAS、最新快照待发送槽、复制序号/错误状态；[ ] 客户端 op_id、仲裁任期、晋升追平、UI accepted 状态 | 见 §22；双机真实鉴权/故障测试与部署门槛未完成 |
| C：数据面基础 | [x] D1/D2 第一阶段：已有 flow 优先、分片拒绝、稳定 listener_id、pinned map 刷新；[ ] 双向 flow 事务/GC、完整无损发布、D3 报文边界、R2 有反馈 PMTU | 特权 map/报文测试通过，配置变化不破坏无关流 |
| D：HA 完整性 | [ ] H1 时间域/顺序/基线；[x] H3 本机 hook/VIP 成功后提交 active 状态；[x] H3 peer handoff 失败后回滚本机角色；[x] H3 本机 takeover 失败后通知 peer 回滚；[ ] H3 双机 fencing 边界；H4 执行重试与接管能力 | 不同 uptime、故障注入、旧操作晚到、map 世代切换通过 |
| E：有界后台任务 | [ ] 探测并发、单轮维护视图、通知重试队列、HTTP 复用、无变化零写入 | 有明确资源上限，无队头长期阻塞，语义不变 |
| F：测后调优 | [ ] flow 续期节流/batch、调度预计算、nft set、UI 缓存/分包 | 同版本对照，给出真实收益与回归成本 |
| G：发布 | [ ] 验证 CI 门禁、制品 ABI、角色安装、停止/重启、文档合同 | 可复现报告、版本与实际二进制一致 |

依赖：H1 的 ID/generation 对齐依赖 D2；H2 的可靠复制依赖 S1；高 PPS 结果必须在 D1/D3 行为明确后才有意义。A 可以分小补丁先修，不必等全部大项完成。每个补丁更新本文执行记录及 implementation-contracts，禁止只把 TODO 勾掉而不记录证据。

## 16. 测量方法与测试命令

本轮没有登录测试服务器，没有新 PPS/HA 中断实测，以下为后续验收模板。使用实验地址 192.0.2.10 代表 VIP，192.0.2.20 代表 backend；执行时替换，不在报告提交真实公网地址或 token。

~~~sh
# 小包功能检查，不用于吞吐结论
printf 'discover\n' | nc -N -w 2 192.0.2.10 8080
printf 'discover\n' | nc -u -w 2 192.0.2.10 8080

# 新建 TCP + 默认每 worker 复用 UDP socket
ha-bench --target 192.0.2.10 --port 8080 --protocol both \
  --duration 60 --concurrency 8 --payload discover --timeout-ms 1000

# 长连接请求，必须另报自动重连与首次尝试失败
ha-bench --target 192.0.2.10 --port 8080 --protocol both \
  --duration 60 --concurrency 64 --payload discover --timeout-ms 1000 --tcp-reuse-conn

# UDP 新流压力
ha-bench --target 192.0.2.10 --port 8080 --protocol udp \
  --duration 60 --concurrency 64 --payload discover --timeout-ms 1000 --udp-new-socket-per-request

# 网络与回程证据；诊断工具只在测试机使用，不新增 daemon 命令依赖
ip -details rule show
ip route show table all
nft -a list ruleset
tc -s filter show dev eth0 ingress
tcpdump -ni eth0 'tcp port 8080 or udp port 8080 or udp port 4789'
tcpdump -ni edge-hub 'tcp port 8080 or udp port 8080'
~~~

测试矩阵：目标 1/2/16/64，端口 1/8/16，并发逐级增加；全健康/部分故障/目标变化；空流表/稳定活跃/容量压力；单机/HA 空闲/HA 高频建流/切换。HA 至少区分进程停机、主机故障、控制通道断开、响应丢失和网络分区，不能只按 UI 按钮。

指标：首次尝试成功率、最终成功率、p50/p95/p99、最长连续失败窗口、旧 TCP 连接保留、TCP CPS、应用 RPS、网卡 PPS/丢包、各 CPU softirq、flow 完整对数与 miss/insert failure、xSync 延迟/丢事件、探测排队/超期、API 队列等待、SQLite 读写与 WAL、常驻内存。记录内核、NIC/offload、CPU、工具版本、map 容量和采样开销。

建立基线前不承诺“2c4GB 一定几十万 PPS”“改 HashMap 固定省多少 CPU”“BFD 检测时间就是业务恢复时间”。

## 17. 本轮核验记录

本轮仅更新本文；前述 [已改] 均来自评估开始前工作区，不冒充本轮实施结果。

| 命令/检查 | 结果与边界 |
| --- | --- |
| cargo fmt --all --check | 通过 |
| make check | Linux 容器 cargo check --workspace --exclude edge-lb-ebpf 通过 |
| cd ui && bun run typecheck | 通过；未运行浏览器交互回归 |
| cargo test -p edge-lb-common -p ha-bench -p backend-server --offline | 39 个测试通过：common 10、ha-bench 7、backend-server 22 |
| make test | Linux 特权容器中 155 个 daemon 测试通过；含现有 DSCP map/native ingress 加载测试，不等于完整数据面/HA 验收 |
| 源码核对 | 覆盖上述模块及 dirty worktree；待测情形明确标记为推导/计划 |
| 未执行 | 线上变更、双机并发/故障注入、真实 HA 转发、PPS profile、发布构建和部署 |

后续执行记录格式：日期、条目 ID、修改范围、测试命令、实际结果、剩余边界。优先解决 P0 和可快速复现的 C1/U1；不要将本评估直接当作全量重构授权。

## 18. 第一批实施记录：2026-09-09

用户授权开始优化后，本批聚焦 C1 与 U1 的可独立验证部分，不混入 flow/HA 协议/路由所有权改造。

- [x] C1：subscriptions 与 nodes 合并到 BackendRegistry 单锁边界。注册、断线、TTL 到期和 overlay 分配发布原子更新；旧 stream_id 不能删除或修改新连接状态。相同配置快照也会发布已分配 overlay，防止缓存仍为 auto。
- [x] C1：完整 ACK 的空冲突列表替换旧告警；心跳、旧流 ACK、空冲突 NACK 不清除旧观测。
- [x] C1 关联修复：backend 不再只缓存 last_applied_version，而是缓存 AppliedSnapshot（版本与冲突观测）。同版本 ACK 重发最近观测，不重新 apply，也不误发空列表清掉真实告警。
- [x] U1：run 返回明确写入成功结果；目标组保存失败保留弹窗，成功才关闭，刷新失败仍显示读取错误；去掉保存时重复的页面数据刷新。
- [x] 增加 ui 的 bun test 入口，不新增测试框架依赖。3 个操作测试覆盖写失败、写成功和成功后刷新失败；未进行真实浏览器点击回归。

复现证据：修复前 late_disconnect_preserves_reconnected_overlay 测试实际返回 auto 而非已分配地址；full_ack_clears_conflicts_but_heartbeat_does_not 在清空断言处失败；前端 run 成功/失败结果测试收到 undefined。修复后均通过。

验证：Linux 特权容器 cargo test -p edge-lb 通过 162 项（本批新增 7 项），包含 TTL 边界、并发注册/清理、重复快照分配发布及重复 ACK 观测缓存；ui bun run test 通过 3 项，bun run typecheck、bun run build、cargo fmt --all --check、git diff --check 通过。Linux make check、make clippy（-D warnings）均通过。

第一批结束时剩余：R1 路由所有权（现已推进至 §19）、S1/H2 事务与复制、D1/D2/H1/H3 数据面及 HA 正确性；U1 请求取消/响应乱序/注销清理仍待做。注册表继续使用原 TTL/时钟语义，未宣称已解决 wall-clock 跳变。没有提交、打 tag 或部署。

## 33. 第十六批执行记录：xSync monotonic 时间重基准

- [x] H1 正确性：`NativeFlowValue.last_seen_ns` 保持为本机 monotonic clock，仅在本机 eBPF/native map 中使用。
- [x] xSync wire 语义改为 `last_seen_age_ns`：MASTER 发送前按本机 `now - last_seen` 计算年龄，BACKUP 接收后按本机 `now - age` 还原，避免两台机器 monotonic 起点不同导致 flow 新旧比较和 idle timeout 判断错误。
- [x] proto 字段名同步改为 `last_seen_age_ns`，不继续保留跨机器绝对 `last_seen_ns` 的误导语义。
- [x] xSync 发送前按 flow key 折叠 batch：同一批 delete 后 upsert 只发送最终 upsert；多个 upsert 只保留最新 `last_seen_ns`；被 upsert 覆盖的 delete 不再发送，避免接收端“先写入再删除”误删刚重建的 flow。
- [x] 新 gRPC session 完成握手后清空发送端 replica 索引，强制下一轮按当前 flow map 发送基线。接收端 ACK 按“已被已挂载 datapath 接受的操作数”计数，幂等 no-op 也算已接受；发送端只有确认数等于本批操作数时才推进 replica 索引，避免 BACKUP datapath 未挂载时 ACK 0 后 MASTER 误以为已同步。
- [x] xSync 单条 gRPC 消息增加 4096 个 flow 操作上限，优先发送 upsert，delete 延后到后续补偿轮次，避免重连基线或事件积压时形成超大消息。
- [x] 增加单元测试覆盖发送端 age 编码、接收端本机时间重基准、0 age 处理、delete/upsert 同批折叠、最新 upsert 保留、ACK 完整性判断和批次上限。

剩余边界：xSync 仍是 MASTER -> BACKUP 的异步 flow state 复制，不能替代业务配置同步屏障；切主期间的长连接保持还需要真实双 gateway + VIP 故障注入压测验证。

## 19. 第二批实施记录：2026-09-09

范围：R1，限制在 backend 策略路由创建、清理、诊断与必要的 SQLite 初始化，不修改 listener/target/flow map、BFD 或 HA 写入协议。

- [x] 删除按 mark/table 区间认领和整表删除；新增本机 SQLite `route_ownership/local`（boot ID、netns、规则与路由标识），只记录创建 ACK 成功的对象。
- [x] main 的 backend run/apply/show/cleanup 初始化本机 SQLite；不导入 gateway HA 业务配置，不再让单测初始化掩盖生产 backend 未初始化的问题。
- [x] apply/cleanup 由 state_dir 文件锁串行；preflight 与 apply 共用结构化所有权校验。表中存在未记录对象或规则 mask 重叠时拒绝，检查失败不继续路由修改。
- [x] dump-driven 差量收敛保留；规则先检查完整 mark/mask/table，按实际已占用 priority 顺延。新增路由 CREATE|EXCL，禁止覆盖随后出现的外来对象。已移除网关的旧表也按记录收敛，不依赖新快照中的旧地址/ifindex。
- [x] 删除前重新检查部分键歧义；未知选择条件、额外路由属性、被截断或中断的 dump 都拒绝。内核返回的 suppress=-1 是不生效的默认属性，可规范化识别；实际 suppress 条件不能忽略。
- [x] 重复轮次不写 SQLite。所有权记录的 namespace/boot 不匹配时不认领，JSON 损坏必须报错；这里的 JSON 是 SQLite 字段内容，不生成 JSON 文件。

真实 Linux 验证：Rust 测试新建 CLONE_NEWNET，通过 `ip link add test-underlay type dummy`、`ip link add test-return type dummy` 建隔离拓扑；地址使用 192.0.2.10/24、10.44.0.2/24、10.45.0.2/24。调用生产 netlink 收敛与实际 SQLite repository，验证外来 pref=100 保留、edge-lb 顺延至 101、三次重收敛 revision 不变、网关改址时旧默认路由消失、切换到另一表仍清理旧表、cleanup 保留同表外来 host route。另添加 `ip rule add pref 200 from 198.51.100.0/24 fwmark 0x106e table 1110 protocol static`，验证含额外 selector 的同键规则不会被部分键删除。

运行命令：`cargo fmt --all --check`、`make check`、`make test`、`make clippy`。定向执行：`docker run --rm --privileged -v "$PWD:/src" -v edge-lb-cargo:/usr/local/cargo/registry -w /src edge-lb-build:bookworm cargo test -p edge-lb linux::route::tests -- --nocapture`。最终完整测试 **163 passed**，包含隔离网络命名空间 + 真实 SQLite 测试；fmt、make check、Clippy 与 diff whitespace 检查通过。删除了基于旧字符串/区间认领假设的测试，用结构化身份、掩码冲突、真实 netlink 测试替换；数量不是简单累加。

部署前置条件与未覆盖边界：

- 没有自动认领旧规则，也没有更新测试服务器。旧部署若无所有权记录，需要维护窗口核实处理；仅覆盖二进制会安全拒绝原来的无记录路由。
- SQLite 与内核创建不是同一事务；ACK 后保存前故障可能留下未认领对象，下轮拒绝接管。未实现意图日志/崩溃自动恢复，也未做磁盘写失败注入。
- 拓扑改变时仍有已记录旧路由的删建窗口；未宣称无损路由更新。其他特权进程完全同标识重建对象、检查与删除间的并发操作无法绝对识别；仍需单一本机资源管理者。
- 网络命名空间测试证明规则/路由保护与幂等性，不代表公网转发性能或真实 HA 切换压测。S1/H2、D1/D2/H1/H3、探测并发及其他性能项仍待实施。

## 20. 第三批实施记录：2026-09-09

范围：S1 本地监听/目标组业务事务及其派生边界；H2 只修复本地副本创建、改名重放和整批导入入口，不改 BFD、flow-sync 或 HA 切换数据面约束。

- [x] 新增 `storage/proxy_config.rs`：同一事务读取监听和目标组，校验后使用两份文档的预期 revision 做 CAS，一次提交两份文档和版本记录。版本变化重新执行校验，最多 16 次；无内容变化不写入。
- [x] 监听/目标组 CRUD、导入和自动化生成目标组经过统一 mutation；修改不存在的监听返回 404，重名/端口冲突或目标组被引用返回错误且不修改旧配置。导入整体成功或整体回滚。
- [x] GET/导出不写回、不从运行态反推配置；读取失败不再伪装成功空列表。显式存储的空列表优先于进程旧配置，损坏文档报错。
- [x] 数据库提交成功且有变化后才设置 dirty。gateway 从 canonical 配置重建 native 投影，保持有效健康观测、移除失效记录；投影重建不反复触发 dirty，也不把本机展开的 VIP 同步给对端。
- [x] 副本监听创建、改名重放保留单一对象和列表顺序；批量导入走单次 HA 操作，并在接收端再次去除本机 VIP 字段。

测试证据：

- 8 个线程在首次读取后用 barrier 同时开始修改，CAS 重试后保留全部 8 个目标组，监听/目标组文档 revision 一致。
- 实际 SQLite trigger 在写第二份文档时注入错误，验证两份文档和版本记录全部回滚；旧 read-set 提交不覆盖其他写入。
- 删除目标组期间插入引用它的监听，重试后再次检查引用并拒绝删除；失败批次和同内容更新保持原版本。
- 验证空 canonical 配置不复活旧对象、损坏文档返回错误、监听改名重放不重复、native 投影保留健康并清理删除项。本机 underlay 会自动补入有效 VIP，测试按该合同校验。

验证：`make test` 在 Linux 特权容器中 **172 passed, 0 failed**；`make check`、`make clippy`（workspace，排除 eBPF crate，`-D warnings`）、`cargo fmt --all --check` 和 `git diff --check` 通过。测试包含真实 SQLite 并发/失败注入以及已有隔离 netns/eBPF 加载用例，不等于真实 HTTP 多 worker 或双机 HA 验收。

剩余边界与下一批：

- H2 仍通过请求内同步回写；本机已提交但对端失败时 API 仍可能返回失败。没有持久化 outbox、op_id、权威任期、乱序拒绝和断线重试，不能把本地 CAS 当作集群一致性。
- revision 仍使用现有进程时间序号，不是分布式版本协议；时钟回退后重启、多个独立 repository 的 SQLite BUSY、连接级 PRAGMA 校验仍需处理。
- dirty 不是持久化任务队列。提交后、通知前故障由启动时重新读取配置收敛；当前没有数据库与 eBPF 的跨系统事务，也没有解决 D2 map 世代发布问题。
- 业务文档仍以整列表序列化；本批优先正确性，未声称减少固定比例 CPU、WAL 或提高 PPS。通知和自动化模板自身的复制事务未随之迁移。
- 没有登录服务器、部署、提交或打 tag。下一批优先 H2 的复制队列、版本/顺序和失败状态，按双机故障场景补测试。

## 21. 第四批实施记录：2026-09-09

范围：H2 的 HTTP 等待环与 O1 中 HA HTTP 连接复用。未修改 SQLite 写事务、BFD、VIP 接管、业务 map 或复制消息模型。

- [x] `api/server.rs` 将普通请求与终结型副本写分开调度。普通 worker 仍为 4，副本 worker 为 1，只接收 proxy-config/notifications/automation-templates 的指定方法与 `/replica` 路径；两类队列各 32，满载立即返回 503，不因等空位停止分发。
- [x] `/active` 等仍会同步调用对端的处理不能使用副本 worker；鉴权和来源校验继续由原 handler 执行，不因为路径分流而放行。新增接口需要维护这一“副本处理不再转发”的约束。
- [x] `runtime/ha_write.rs` 共享 blocking reqwest Client。请求单独加载 token，响应体完整消费；连接超时 3 秒、读总超时 5 秒、写总超时 10 秒，每 host 最多 2 条空闲连接、空闲 30 秒回收。
- [x] peer 直连、不读取环境代理、不跟随重定向；User-Agent 取编译版本。响应体读取失败不再转换成空字符串，以免上游误把不完整响应视为成功。

新增 5 项回归：

1. 精确校验保留 worker 的方法/路径；query 不影响分流，旧路径、子路径、错误方法和 `/active` 不获得保留处理能力。
2. 两个真实 loopback HTTP server 使用生产分发器。4 个 BACKUP handler 同步等待全部到齐，再向 MASTER 发起请求，MASTER 回调 BACKUP `/replica` 后返回，4 个请求均成功。业务落盘与鉴权在该用例中由测试 handler 替代，验证的是调度等待环，不是完整 HA 集群。
3. 4 个普通 handler 阻塞时填满 32 槽队列，额外请求得到 503，期间副本请求仍得到 200；随后释放并回收所有测试工作线程。
4. 连续两次 peer client 请求，服务器观测到相同 TCP 源端口；第二次使用新 token，不复用旧认证头。
5. peer 返回 307 时客户端原样返回，不跟随 Location。

验证：`make test` 在 Linux 特权容器中 **177 passed, 0 failed**；`make check`、`make clippy`（`-D warnings`）、`cargo fmt --all --check`、`git diff --check` 通过。没有运行服务器部署或真实 HA/PPS 压测，不承诺吞吐提升百分比。

仍未完成：

- 副本单线程按到达顺序处理，不代表 MASTER 提交顺序。任期、版本屏障、op_id、事务 outbox、复制失败重试和本机提交后 502 语义仍是下一批 H2 内容；不得将本批标记为 H2 全部完成。
- 请求仍是 blocking HTTP；这里只保证普通 worker 等待不会占用副本的执行能力。慢客户端、恶意请求、body 大小、tiny_http 内部队列、响应写入阻塞和队列等待期限没有全面治理，不能把两个有界业务队列当作整体 DoS 防护。
- 配对鉴权、切主中的旧操作晚到和真实双机数据库内容一致性仍需端到端验证。未提交、打 tag 或部署。

## 22. 第五批实施记录：2026-09-09

范围：S1/H2 的监听与目标组版本化快照、持久化待发送状态和独立重试 worker；不扩展到通知、模板自身的复制，也不修改 BFD、xSync flow 或 VIP 接管逻辑。

- [x] 新增 `storage/proxy_replication.rs`。canonical 两份文档与 `proxy_replication/config` 的 sequence/source/pairing_id/hash/pending/last_error 一次 CAS 提交；复制游标写失败会回滚业务写入。
- [x] Repository 支持只读版本条件，事务检查 HA 配置、配对凭据和 active 选择未变化。BACKUP 不能权威写入，MASTER 不接受副本快照，active 缺失或不属于当前 pair 时拒绝推测写权限。
- [x] 副本从原始操作重放切换为完整快照。配对身份相同的旧版本拒绝，同版本异内容拒绝，同版本同内容可重发且不写入；新配对允许新权威基线，旧配对快照拒绝。不再保留旧 replica 操作兼容分支。
- [x] pending 是和 canonical 配置绑定的最新状态发送槽，后续提交可覆盖尚未发送的中间版本；传输包含监听和目标组整体，删除用空列表表达，不依赖逐条操作顺序。
- [x] 新增 `runtime/proxy_replication.rs`，gateway daemon 启动独立 worker。每轮最多发一份，结束等待 3 秒；失败保留 pending，重启可再次读取发送；稳定状态每 30 秒发送相同版本校验基线。ACK 必须匹配 sequence/source/pair/hash，迟到 ACK 不能清掉新版本任务。
- [x] 每次升主或配对变化准备新发送版本只改复制元数据；副本收到更高版本、内容未变化时也不更新业务文档、不设置 dirty。VIP 列表始终由本机展开，显式 VIP 的副本报文拒绝。
- [x] Repository 启动读取已存最大 revision 更新进程分配下限，避免时钟落后时重启分配重复版本；复制 sequence 则完全从持久化游标递增，不比较主机时钟。
- [x] HA 写入返回 202，`sync.authority_committed=true` 和 authority 表示 MASTER 已持久化，`replica_confirmed=false` 明确未等待副本。新增 GET `/api/v1/ha/proxy-config-sync` 查询本机复制游标。转发到 MASTER 的请求超时仍返回“提交结果未知”，不能假定未提交。

测试与证据：

1. 两个独立 SQLite repository 模拟同一配对：先交付新版本、再交付旧版本，拒绝倒退；同版本异内容及显式 VIP 拒绝，重复相同快照保持文档 revision 不变。
2. 关闭并重新打开 repository，pending/version/hash 保留；旧 ACK 不清理后续写入任务；重复 ACK 不写入。此测试是数据库重开，不冒充进程 SIGKILL 实测。
3. 在读取快照与提交之间修改 SQLite active 选择，旧 CAS 失败；升主后的节点拒绝副本写，重新发布保持监听/目标组文档 revision 不变。
4. 更换配对 ID 后拒绝旧报文，接受当前权威的基线。注入游标 INSERT trigger 故障，业务配置与游标全部回滚。
5. loopback HTTP server 实际调用副本 SQLite 提交，第一次成功落盘后返回 500 模拟回执不可用；发送方保留 pending，重发相同快照收到匹配 receipt，副本第二次不再写库。
6. 空快照整体删除监听和目标组；数据库存在超过当前时间的 revision 时，重开后的新写入分配更高版本。
7. 原 HTTP 队列满载测试在并行全量回归中曾等待超时，已改为直接 TCP 连接、先确认 4 个普通 handler 进入再填满队列，排除压测客户端调度对队列压力的影响；仍验证超额 503 和副本 200，而不是删除或放宽断言。

全量 `make test`：**182 passed, 0 failed**，`make check`、Clippy（`-D warnings`）、格式与差异检查通过。删除旧逐操作 replica 的 3 个测试，新增 8 个快照/事务/HTTP 用例；总数不是简单追加。本批无 UI 修改、无浏览器测试、无服务器变更。

部署门槛及剩余边界：

- [ ] 本批结束时 UI 尚未展示 accepted/pending；后续第 23 节已补代码及 API/mock 回归，浏览器和真实双机验收仍待完成。不能把 202 显示成“两端均同步成功”。
- [ ] 两端需使用新快照协议一起升级，并保证 SQLite HA active 记录和配对凭据一致。没有旧报文兼容，也未验证滚动升级、真实 token 轮换和 daemon 重启的端到端效果。
- [ ] 没有客户端 operation_id：向 MASTER 转发请求后丢失响应仍存在提交结果不明。全量状态复制幂等不代表客户端创建/更新恰好一次。
- [ ] 没有 quorum/仲裁任期或晋升前追平屏障。3 秒检查及网络超时内仍可能有未复制配置，故障接管不能保证 RPO=0；分区两侧独立写入后需要权威确认，不自动合并相同序号的冲突配置。
- [ ] 相同内容的主备切换已避免业务文档/dirty 修改，但更广泛的 D2 map 世代发布、配置提交与数据面应用之间崩溃恢复仍待做。
- [ ] 通知/模板的权威复制、SQLite 连接参数/多进程并发、日志历史清理、真实 HA 网络故障与完整 HTTP 鉴权回归仍待做。单进程 repository 的版本下限不等于多进程全局序号分配。

没有提交、打 tag 或部署。下一批先处理异步写入状态的 UI/API 联动和真实服务级测试，再评估晋升追平与客户端操作去重。

## 23. 第六批实施记录：2026-09-09

范围：补齐 H2 的前端异步可见性，不改复制调度周期、BFD、VIP 或数据面 map。

- [x] 202 响应增加可选 `sync.barrier`；提交后游标读取失败也维持 accepted。它可能包含后续并发版本，不冒充操作唯一回执；没有引入 operation_id 或 exactly-once 承诺。
- [x] 前端 API 增加业务写入响应类型与复制状态查询；API fetch 禁用 HTTP 缓存。目标组保存/删除/导入和监听导入保留响应，不再丢弃 202 元数据或重复执行额外刷新。
- [x] 仅 accepted 写入启动查询，每轮读取结束后间隔 1 秒，总计最多 30 秒，包含阻塞中的状态请求。无写入时不新增常驻轮询；超时可手动重新检查，绝不自动重发业务写。
- [x] 版本判定检查 pairing_id 和 sequence，同版本要求 source/hash 一致。旧副本 pending=false 不代表追平；BACKUP 显示本机已收到，MASTER 需 pending=false 才显示副本确认；重新配对/版本冲突不显示同步成功。
- [x] 查询达到版本下限后只刷新当前页面需要的数据。新 accepted 写取消旧查询，退出/认证失效/页面卸载取消查询，迟到回执不覆盖新的状态；监听/目标组/节点读取增加会话检查，避免退出后重新填回列表。
- [x] 监听编辑器改为等待写结果，失败保留弹窗和输入；成功后关闭。确认同步超时不改写已持久化结果。状态提示提供中英文，不将“MASTER 已保存”与“副本已确认”混为一谈。

验证记录：

1. `make test`：Linux 特权容器 **184 passed, 0 failed**。新增两项 API 响应测试，覆盖 barrier 内容、保留资源字段、缺失/外来游标仍返回 202，以及不假定 replica ACK。
2. `cd ui && bun run test`：**17 passed, 0 failed**。覆盖空/旧游标、同版本冲突、较新版本、不同配对、MASTER pending、瞬时读取失败、30 秒机制的缩短时限定时测试、注销/认证失败/新写取消、BACKUP 列表自动刷新和监听编辑失败保留输入。
3. 前端类型检查及生产构建、Clippy（`-D warnings`）、格式与差异检查通过。

限制与下一步：

- 本会话没有可调用的 Browser/Node REPL 工具，未做浏览器视觉和真实点击验收；前端测试使用 mock API，不替代实际 token、网络、双机 SQLite/daemon 联调。
- 轮询只追踪当前页面会话内最新 accepted 写入，刷新浏览器后不恢复历史待确认提示；不新增另一份客户端持久化状态。页面间切换不取消短期查询，成功时只刷新当前 tab。
- 版本下限可见性依赖既有单 MASTER 写入约束，不是仲裁、配置晋升追平或数据面已应用证明。没有扩展为通知/自动化模板复制，也不表示 flow-sync 已验证。
- 未部署、提交或打 tag；真实双机鉴权/重启/切主和浏览器验收仍是部署门槛。继续按第 22 节列出的剩余正确性问题推进，不宣称性能提升比例。

## 24. 第七批实施记录：2026-09-09

范围：HA 配置复制的生产入口与进程级回归，不操作真实服务器或 BFD/VIP/数据面。

- [x] 修复 `ui serve` 接受 HA 写入却没有复制 worker 的缺口；gateway 角色的独立 API 入口也启动持久化复制 worker。该进程必须独占本机 state_dir，不支持与 gateway daemon 共用数据库同时运行；未新增第二条复制实现。
- [x] 新增 `edge-lb/tests/ha_proxy_service.rs`。Cargo 启动两个生产二进制（`CARGO_BIN_EXE_edge-lb`），分别使用临时 SQLite 和 loopback HTTP，走生产 bearer 鉴权、路由、handler、转发与复制 worker，不走 `cfg(test)` 下的 HA JSON 存储。
- [x] 副本离线时 MASTER 创建空目标组和 TCP+UDP 监听，收到 202 并检查 pending/last_error；SIGKILL MASTER，重启后 sequence/hash/pending 保留。副本随后上线，两份 canonical 文档及复制游标追平。
- [x] 从 BACKUP 创建另一目标组、更新监听空闲超时，响应 authority 均指向 MASTER；查询和 SQLite 均显示更新。配对 token、标识及 active 选择在停机后调整，重启后从新 BACKUP 发起新配置写入、删除监听及目标组，副本正确传播删除状态。
- [x] 缺失/错误/管理 token 不能写 peer 副本接口；peer token 不能读取管理同步状态接口；当前 token 可以重发相同快照，旧 sequence 得到 409。轮换后旧 token 得到 401，当前 token 携带旧配对快照仍得到 409；MASTER 拒绝副本写、BACKUP 拒绝 peer `/active` 权威写。
- [x] 更新实现约束、README 和验证结果；保留真实网络分区、自动选主、浏览器、数据面验证的未完成标记。

验证：

- `make test`：184 个单元测试及 1 个生产双进程集成测试通过。随后扩展监听更新/删除断言，单独运行 `cargo test -p edge-lb --test ha_proxy_service` 再次通过，耗时约 22 秒；该次容器没有使用 `--privileged`，测试不修改路由、sysctl、VIP、TC 或 eBPF。
- `cargo clippy -p edge-lb --bin edge-lb --test ha_proxy_service -- -D warnings` 通过；格式、差异检查通过。
- 扩大到 workspace `--all-targets` 的 Clippy **未通过**：发现 12 处既有测试告警，涉及 config、control/snapshot、linux/nftables、linux/sysctl、provider/native/probe、storage/mod 的默认值后赋值、立即调用闭包和测试模块后定义。没有用 allow 掩盖，也未在本批顺带改动这些测试；列为后续测试质量清理项。

边界：

- 两个进程使用同一 Linux 容器的不同临时目录，不是两台物理/云主机；HA 配对、active 变更由停机后的 SQLite fixture 设置，未验证配对 API、BFD 选举、实时切主、GARP、VIP、xSync 或业务包不断流。
- HTTP 均来自 loopback，测试验证 bearer 权限隔离，不覆盖非 loopback trusted-source CIDR、防火墙或 TLS。进程退出后自动回收子进程和临时目录。
- 没有提交、打 tag 或部署。本批证明 API-only 模式也能驱动持久化重试，并补齐生产存储链路的过程验证；不能据此解除真实 HA/浏览器验收门槛。

## 25. 第八批实施记录：2026-09-09

- [x] 清理第 24 节发现的 12 处测试 Clippy 告警，不用 allow 隐藏。默认字段移到结构体初始化中，删除没有行为的 SeaORM 类型占位函数；不改测试预期。
- [x] sysctl 测试改为调用实际 `ensure_sysctl_floor/ceiling`，对临时文件验证达到阈值时原字节保持不变、越界时正确调整；新增非法内容不覆盖、缺失文件不创建的回归。没有修改运行时调优阈值或宿主机参数。
- [x] 初始化与 repository 使用同一 `connection_options`，显式配置单连接池、WAL、FULL、外键和 5 秒 busy timeout；连接级参数在 SQLx 创建每条连接时应用，不仅是初始化后的单次 PRAGMA。
- [x] 核对本地锁定依赖源码确认：SQLx 0.8.6 已默认 foreign_keys=ON/busy_timeout=5s/synchronous=FULL，SeaORM 1.1.20 的 SQLite 默认单连接。本批是消除隐含默认值和两处配置分歧，不声称发现了运行期外键关闭故障，也没有为了性能将 FULL 降级为 NORMAL。
- [x] 文件数据库初始化后，测试临时将池上限设为 2，持有第一条连接的事务迫使第二条连接创建；分别读回 journal_mode=wal、foreign_keys=1、busy_timeout=5000、synchronous=2，实际插入孤立 resource_document 必须外键失败。关闭连接池后重开并重复；生产池上限仍为 1。

验证结果：

- `cargo clippy --workspace --exclude edge-lb-ebpf --all-targets -- -D warnings`：通过，前一批的 12 处告警已消除。
- `make test`：**186 个单元测试、1 个生产双进程集成测试通过**；后者约 22 秒，包含 pending 持久化、SIGKILL 重启重试、鉴权、更新与删除传播。
- `cargo fmt --all --check`、`git diff --check`、`make check` 均通过。

边界与待办：

- busy_timeout 是 SQLite 锁竞争等待参数，不是 API 总超时，也不保证 BUSY_SNAPSHOT 自动重试；多进程共用数据库、revision 全局分配和独占管理仍不是本批解决的能力。
- 这里没有验证磁盘掉电行为或吞吐提升，不改 schema、HA 协议、VIP/BFD/flow。真实双机网络/浏览器验收、晋升追平及客户端提交结果未知等问题仍按前文待办推进。

## 26. 第九批执行记录：R2 自动 MTU 的证据与安全边界

范围：先删除 UDP send 成功即判定 PMTU 已验证的实现，不引入另一套自研探测协议。

- [x] auto 只读取设备 MTU、绑定 underlay 设备/源地址后的内核已知 IPv4 路由 MTU，不发测试数据报；日志明确 path_verified=false。
- [x] 未经端到端验证不得自动启用 jumbo frame；IPv4 上限 1450，同时遵守更小的设备/路由 MTU。已知上限不足最小 VXLAN MTU 时返回错误，禁止反向回退到 1450。
- [x] IPv6 对端不冒充已完成探测，预算按 70 字节计算；这不代表新增 IPv6 数据面支持。显式数值 MTU 保持原行为。
- [x] 补充六项 MTU 边界、多对端、无反馈、设备读取失败、MSS 和 Linux socket 回归；更新配置文档和合同。

内核 `IP_MTU` 返回 connected socket 当前已知的路径 MTU，并不是本次端到端探测证明，参见 [Linux IP_MTU](https://man7.org/linux/man-pages/man2/IP_MTU.2const.html)。带反馈/错误队列的主动探测和真实跨低 MTU 链路验收仍保留为后续任务，不将本批标为 R2 全部完成。

验证：

- `make test`：192 个单元测试和 1 个生产双进程 HA API 集成测试通过；Linux socket 用例实际读取 lo 路由 MTU，并用本机 UDP 接收器确认没有收到探测数据。不存在的设备必须返回错误，不能悄悄改走其他设备。
- 首轮发现测试假设不准确：lo 的设备 MTU 为 65536，而 IPv4 IP_MTU 为 65535；断言已按 IPv4 长度上限修正，没有修改内核返回值或放宽为任意正数。
- Linux `cargo clippy --workspace --exclude edge-lb-ebpf --all-targets -- -D warnings` 通过。
- `make check`、`cargo fmt --all --check`、`git diff --check` 通过。

边界：真实 PMTU 黑洞、ICMP 被阻断、多跳较小 MTU、动态新节点与路径变化仍需主动探测/网络验收；缓存路由 MTU 可能只反映本地出口。1500 只是保守预算，不是路径可达性保证。未改 HA、flow、前端、项目版本，未部署或提交；没有 PPS 提升测量。

## 27. 第十批执行记录：state_dir 进程级独占

评估发现，文档原先只声明“不支持多个进程共用 state_dir”，实现却没有强制约束。现已在存储初始化前创建并以 `flock(LOCK_EX|LOCK_NB)` 持有 `edge-lb.process.lock`，锁文件句柄保存到进程生命周期结束；第二个管理进程会在打开 SQLite 前失败。新增测试覆盖同一目录第二个锁被拒绝、首个释放后可重新获取。

这解决的是本机 edge-lb 管理进程之间的并发覆盖，不是对其他程序的安全隔离，也不支持两个独立 edge-lb 实例共享业务数据库。路由收敛仍保留自己的更细粒度锁；backend 与 gateway 应使用不同 state_dir。若残留锁文件存在但没有持有者，内核会在进程退出后释放锁，文件本身无需删除。
- 本批未部署、提交或打 tag。

## 28. 第十一批执行记录：API 请求体上限与读取错误

范围：只收紧 tiny_http API 请求体读取，不调整路由、HA、SQLite 事务、静态资源缓存或数据面。

- [x] API handler 不再忽略 `read_to_string` 错误，改为统一 helper 读取 body。
- [x] 有 `Content-Length` 且超过 1 MiB 时，在进入业务 handler 前返回 413。
- [x] chunked/未知长度请求也按实际读取 `limit + 1` 字节判断，超过 1 MiB 返回 413，不能绕过声明长度检查。
- [x] body 读取 IO 错误和非法 UTF-8 返回 400；业务 handler 只接收完整、合法 UTF-8 字符串。
- [x] 新增三项单元测试覆盖正常小 body、声明超限和 chunked 实际超限。

验证：

- `make test`：196 个单元测试和 1 个生产双进程 HA API 集成测试通过。
- `cargo fmt --all --check`：通过。

边界：这不是完整 DoS 防护。tiny_http 内部连接读取、慢客户端、请求头大小、响应写阻塞、状态查询缓存和运维接口并发上限仍按 §12.3/§12.4 继续处理。本批未部署、提交或打 tag。

## 29. 第十二批执行记录：通知响应限量读取

范围：通知 dispatcher 的 HTTP 响应体消费，不改变渠道模型、重试次数、队列容量或 HA 复制。

- [x] `response()` 不再调用 `resp.text()` 全量读取，改为 `read_limited_text()`。
- [x] 每次通知响应最多读取 2049 字节；超过 2048 字节时截断并追加 `...`，日志和 delivery 记录继续使用有限诊断文本。
- [x] 读取错误不再被转换为空成功响应；会作为本次投递错误进入既有重试路径。
- [x] 非 UTF-8 响应按有损文本保存为诊断内容，不让编码错误影响 HTTP 状态判断。
- [x] 新增三项单元测试覆盖小响应、大响应限量截断和 UTF-8 边界。

验证：

- `make test`：199 个单元测试和 1 个生产双进程 HA API 集成测试通过。
- `make check`：通过。
- `make clippy`：workspace 排除 eBPF crate，`-D warnings` 通过。
- `cargo fmt --all --check`、`git diff --check`：通过。

边界：通知仍是单 dispatcher 串行投递，失败渠道仍可能因 8 秒超时和最多 5 次重试延迟同队列后续事件；delivery 历史保留在 §30 处理，Retry-After、按渠道并发、慢响应读取时间上限和 durable outbox 仍未实现。本批未部署、提交或打 tag。

## 30. 第十三批执行记录：通知投递历史保留上限

范围：SQLite 中 `notification_deliveries` 历史记录的增长边界，不修改通知渠道配置、发送协议、重试策略、HA 复制或业务配置 revision 语义。

- [x] Repository 增加受限的 `prune_resource(resource_type, keep_latest)`，按资源类型仅保留最新 N 条文档。
- [x] 通知投递记录写入后保留最近 512 条 `notification_deliveries`，清理失败按既有通知记录错误告警，不影响原通知 HTTP 请求结果。
- [x] 清理不写新的 `config_revisions`，因为投递历史是运行诊断数据，不是业务配置变更；监听、目标组和 HA 配置不通过该接口清理。
- [x] 新增 repository 单元测试，验证只清理指定 resource_type，保留最新记录，不影响其他资源。

验证：

- `cargo fmt --all --check`：通过。
- `git diff --check`：通过。
- `make test`：200 个单元测试和 1 个生产双进程 HA API 集成测试通过。
- `make check`：通过。
- `make clippy`：workspace 排除 eBPF crate，`-D warnings` 通过。

边界：512 条是本地诊断保留上限，不是审计日志；需要长期审计时应接入外部日志/通知系统。`config_revisions` 自身的长期保留、通知按渠道独立队列、Retry-After 和 durable outbox 仍未实现。本批未部署、提交或打 tag。

## 31. 第十四批执行记录：通知与自动化配置 no-op 写入

范围：通知渠道配置和自动化模板配置的 SQLite 写入路径，不修改监听/目标组事务模型、HA 主备写入路径、通知投递历史或数据面。

- [x] Repository 增加 `put_if_changed()` 串行命令，在同一个 storage worker 内读取当前 payload；内容相同时不写 `resource_documents`，也不产生新的 `config_revisions`。
- [x] 通知配置 `notifications/config` 和自动化配置 `automation/config` 改用 `put_if_changed()`，重复保存相同内容不会放大 WAL、revision 和 HA 副本写入。
- [x] HA 同步语义不变：MASTER 仍可向 BACKUP 发送当前配置，BACKUP 收到相同配置时本地 no-op；不能把本地 no-op 当作远端已确认。
- [x] 新增 repository 单元测试，验证首次写入和变更写入生成 revision，相同 payload 不生成 revision。

验证：

- `cargo fmt --all --check`：通过。
- `git diff --check`：通过。
- `make test`：201 个单元测试和 1 个生产双进程 HA API 集成测试通过。
- `make check`：通过。
- `make clippy`：workspace 排除 eBPF crate，`-D warnings` 通过。

边界：该优化只比较序列化后的完整 JSON 字符串；字段顺序由当前 serde 输出决定，不做语义级 JSON canonicalization。监听/目标组已有独立事务 no-op 逻辑，不通过此接口处理。`config_revisions` 长期保留策略仍未实现。本批未部署、提交或打 tag。

## 32. 第十五批执行记录：native flow 保留与稳定 listener_id

范围：native DNAT/SNAT 数据面发布第一阶段，覆盖 D1/D2 中“已有连接被配置变化破坏”和“listener_id 依赖配置顺序”的问题；不修改 API、UI、HA 配置复制、xSync 协议或 map ABI。

- [x] `listener_id` 改为由 VIP、端口、协议稳定派生，碰撞按排序后的监听 key 线性探测；配置数组顺序变化不改变同一监听的 ID。
- [x] eBPF ingress 改为先查已有 `NATIVE_FLOWS`，再查当前 `NATIVE_LISTENERS`。监听删除、改名、目标组变化后，已建立 flow 继续按创建时的 reverse-NAT 信息转发直到 idle timeout/GC。
- [x] gateway apply 在设备和 TC priority 未变且程序仍挂载时，优先同步 pinned `NATIVE_LISTENERS` 与 `NATIVE_TARGETS`，保留 `NATIVE_FLOWS`、TC attachment 和 ring buffer；map 刷新失败才重挂载。
- [x] IPv4 分片包显式不进入 native NAT：首片带 MF 或后续片直接 `PIPE`，不创建半截 flow。DSCP marker 仍按独立规则处理端口命中。
- [x] 新增单元测试，验证稳定 listener_id 不依赖配置顺序。

验证：

- `cargo fmt --all --check`：通过。
- `git diff --check`：通过。
- `make ebpf`：通过，`edge-lb-ebpf` for `bpfel-unknown-none` release 对象编译成功。
- `make check`：通过。
- `make clippy`：workspace 排除 eBPF crate，`-D warnings` 通过。
- `make test`：202 个单元测试和 1 个生产双进程 HA API 集成测试通过。

边界：listener/target map 更新不是跨 map 原子事务，极短时间内新连接可能看到新旧表过渡；已有 flow 仍依赖 LRU map 双 key 插入，不保证两个方向绝对事务一致。IPv4 options、GRO/GSO、ICMP 差错、分片重组和真实配置更新期间连接保留仍需报文级/实机验证。xSync 的时间域、顺序和重连基线未在本批处理。本批未部署、提交或打 tag。
