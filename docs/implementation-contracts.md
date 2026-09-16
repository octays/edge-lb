# 实现约束与行为契约

本文档记录已经确认的实现语义。新增功能、问题修复和 UI 调整必须先更新本文档或对应的架构/API文档，再修改代码；不得为了临时解决问题引入未记录的数据模型或隐式回退。

## 1. 变更规则

- 涉及 gateway/backend 边界、xDS snapshot、数据面回程语义、HA ownership 或
  API 资源模型的架构变更，必须先同步设计并得到确认，再修改代码和部署。
- 监听配置和目标组是 edge-lb 自有模型，不映射成外部负载均衡器的业务对象。
- 监听配置只负责对外地址、对外端口、协议、调度策略、转发模式、目标组绑定和连接超时。
- 目标组只负责后端地址、权重和健康探测配置；监听配置负责目标转发端口。
- `Config.services` 和 `TargetEndpoint` 已删除；监听配置和目标组是唯一业务模型。
  native map 写入和 DSCP 端口推导都必须直接从 `listeners + target_groups`
  计算，不能重新引入运行期 service 投影。
- backend xDS 只下发 backend 配置回程 VXLAN/DSCP 所必需的 contract：
  gateway underlay IP、gateway overlay IP、backend overlay IP、VXLAN
  设备/VNI/端口/MTU，以及每个 gateway 的 DSCP、fwmark 和 route table。
  不能下发监听、目标组、目标端口、健康探测、backend inventory、公网 IP 或任何
  gateway 业务配置字段；也不能下发 active gateway 状态或 UDP service port。
- DNAT 必须使用目标组显式配置的业务地址；仅按 backend 名称引用且地址未指定时，
  才解析为该 backend 的 underlay IP。健康探测、健康状态身份和 native target 使用同一
  解析语义，不得自动用 backend overlay 替换业务地址。
- backend 在所有 IPv4 ingress 的 conntrack original 方向按已订阅 DSCP 设置 ct mark，
  不依赖 VXLAN ingress 设备、L4 协议、业务端口或 active gateway。reply 方向只恢复
  当前有效 contract 的 routing fwmark，经 VXLAN 返回 gateway；不改写业务源 IP。
- DSCP 是受信网络内的回程分类标记，不是身份认证。直连流量若携带相同 DSCP，也会
  被分类；部署方必须隔离这些 codepoint，不能再声称“同 DSCP 直连一定不被接管”。
  contract DSCP 必须为 1..63，多个 gateway 的 DSCP、非零 mark 和路由表不能冲突。
  非法或歧义 contract 必须在修改内核状态前拒绝，不以规则顺序决定回程。
- 快照恢复必须匹配业务地址和端口，不按目标下标把旧 overlay 会话改写到另一地址。
- 删除 UDP 的 client_ip/client_port 动态 set、30 秒学习和 overlay 源修正规则，
  TCP/UDP 统一使用 conntrack 完整连接元组与 mark。规则重装不主动清空 conntrack。
  同一完整 UDP 五元组若先后从两个 gateway 进入，最近的已分类请求更新连接 mark；
  无法区分同一五元组内不同应用事务，不能宣称按请求级别保证回包归属。
- UDP 服务必须以收到请求的业务地址作为回复源。普通单 underlay 主机的 wildcard
  socket 纳入内核测试；多地址主机应绑定业务 IP 或使用 IP_PKTINFO 保持源地址。
  不再用跨业务地址的二元 tuple 猜测修正源地址；已有 overlay 连接需排空后升级。
- HA backend 同时订阅多个 gateway 时，必须等所有配置中的 gateway snapshot 都收到
  后再 apply。部分快照只能 ACK 等待或保持现有数据面，不能把已安装的多 gateway
  return path 收窄成单 gateway。
- 自动配置模板只生成或覆盖目标组，字段名必须是 `target_group`；不接受
  `listener` 字段别名。
- 自动配置目标组在没有匹配节点时仍保留组对象，方便监听提前绑定。
  gateway 启动和节点变动统一等待 3 秒订阅防抖；稳定后无匹配必须清空旧目标，
  不能以“订阅恢复”为由无限保留已离线节点。API 显式修改模板立即按当前在线集合计算。
- 一个监听可以同时包含 TCP 和 UDP，但 API、持久化和 eBPF 规则中仍保持一个监听对象，不拆成两个业务监听。
- 监听未填写对外地址时，运行时使用本机 `underlay_ip`；启用二层 HA 时，L2 VIP 作为附加对外地址参与数据面规则。VIP 不通过 HA 配置同步到对端，主备只同步配置，VIP 由 L2 接管状态负责绑定和解绑。VIP 地址默认绑定到 `lo`，需要云网络或二层交换机直接看到 VIP 地址时才在 UI 高级配置中改为 `underlay` 或指定设备。
- HA 主备切换路径只允许更新 active gateway 状态、执行本机 VIP bind/release、
  发送 GARP 以及同步 active 状态到 peer。切换过程中禁止修改 listener、
  target group、native listener/target map、DSCP map 或 native flow map，
  也禁止触发完整 datapath reconcile。这样切主只改变 VIP 所有权，不制造 TC
  detach/attach 空窗，也不丢失 xSync 已同步的 flow state。
- HA VIP 接管方式只暴露 `l2` 和 `hook`。BGP 接管模式已从产品配置面移除，
  API/UI 不得继续提供 BGP 表单或 capability；历史/外部传入的 `bgp` provider
  在运行期归一化为 `hook`，不能产生“保存成功但没有执行器”的状态。
- `hook` 模式的脚本路径是固定 contract，UI/API 不允许修改：
  `/usr/local/bin/edge-lb-promote`、`/usr/local/bin/edge-lb-demote`、
  `/usr/local/bin/edge-lb-verify-vip`。`edge-lb install` 和 gateway daemon
  必须自动创建缺失脚本并设置 `0755` 权限；已有脚本内容不覆盖，只修正权限。
- `hook` 模式状态切换必须按顺序执行：本机成为 `MASTER` 时执行
  `edge-lb-promote`，本机成为 `BACKUP` 时执行 `edge-lb-demote`，两种状态变化后
  都执行 `edge-lb-verify-vip`。脚本第一个参数是配置中的 VIP（没有则为空），
  同时注入 `EDGE_LB_HA_ACTION`、`EDGE_LB_HA_STATE`、`EDGE_LB_VIP`、
  `EDGE_LB_NODE`、`EDGE_LB_UNDERLAY_IP` 和 `EDGE_LB_STATE_DIR` 环境变量。
  任一脚本返回非 0 都表示切换失败，不能吞错继续宣称成功。
- gateway 节点列表中的 HA peer 必须使用配对时学习到的 peer `overlay_ip` 和
  `overlay_cidr`。peer overlay 允许属于对端网段，不能用本机 `gateway.overlay_ip`
  覆盖，也不能要求所有 `gateway_nodes[].overlay_ip` 都属于本机
  `network.overlay_cidr`。
- 后端只接收并执行 VXLAN/DSCP 回程数据面配置，不判断 active gateway，不保存
  gateway 的 HA 运行来源，也不接收 listener/target group/service port。
- IPv4 forwarding 由 gateway 和 backend 启动时幂等开启：gateway 用于 DNAT 后转发，backend 用于容器、桥接地址或其他本地路由目标的回程转发；cleanup 不关闭这个主机级能力。

## Backend VXLAN reachability

VXLAN reachability is runtime kernel state and is reconciled during every
backend heal pass. The agent restores the managed device, local overlay
addresses, and configured gateway underlay peer FDB entries with netlink.
Learned entries are preserved and foreign entries are never removed. A
missing overlay neighbour is recovered by restoring the peer FDB and allowing
normal kernel neighbour resolution; gateway MAC addresses are not invented or
persisted by edge-lb.

Managed backend return tables may contain `/32` gateway-underlay bypass routes
via the backend underlay device with the local backend `src` address. These are
edge-lb-owned routes derived from gateway return-path contracts and must not be
reported as external `route_table` conflicts.
Ownership is keyed by the known gateway underlay destination plus `/32` route
shape; it must not depend solely on a transient device-name string such as
`auto`, `eth0`, `eth0(2)`, or a cloud NIC alias.
When a backend combines two gateway xDS streams, it must merge gateway
return-path contracts from every stream. Every per-gateway return table must
include host routes for all known gateway underlay IPs. A real failure on backend-b showed table
`1104` only had `192.168.0.12/32`; VXLAN packets for gateway
`192.168.0.16` then recursively followed the table default via `edge-return`,
so only hash selections landing on that backend timed out.
Backend xDS-derived config validation is role-aware: gateway return-path
contracts may carry overlay addresses from multiple gateway CIDRs. Only the
snapshot network's own gateway overlay must belong to that snapshot CIDR; peer
gateway/backend overlays are return-path data for route/FDB convergence, not
members of the current overlay.

## Recorded incident: VXLAN return path

When a backend generated a reply on `edge-return` but the client did not
receive it, inspection showed the policy route was correct while the runtime
overlay neighbour/FDB state was incomplete. Re-adding the managed peer FDB and
refreshing neighbour resolution restored the path. The backend heal loop now
performs this idempotently. During implementation, the compiler also caught a
temporary overlay-address borrow in the heal path; the fix keeps the local
backend binding alive while constructing the VXLAN specification.

## 2. 健康探测

健康探测只在目标组被监听配置引用且目标组开启探测时运行。关闭开关等价于 `probe_type = none`，不向用户暴露 `none` 选项。

支持的探测类型：

- `ping`：ICMP 探测，不使用端口、发送内容或响应匹配。
- `tcp`：建立 TCP 连接；可选发送内容和响应子串匹配。未配置响应匹配时，连接成功即健康。
- `udp`：发送可选内容；可选响应子串匹配。未配置响应匹配时，收到响应或在超时窗口内未收到 ICMP 不可达按当前 UDP 探测策略处理。
- `http`：使用探测路径发起 HTTP GET；默认按 `2xx/3xx` 健康，可选指定 HTTP 状态码和响应匹配。
- `https`：行为同 HTTP，可选跳过证书校验。

字段语义：

- `probe_port` 是健康探测端口，和监听的目标转发端口独立。
- `probe_req` 对 TCP/UDP 表示发送内容，对 HTTP/HTTPS 表示探测路径。
- `probe_resp` 表示响应内容子串匹配。
- `probe_status` 只适用于 HTTP/HTTPS，范围为 `100..=599`。
- `period_secs` 默认 15 秒，必须大于 0。
- `retries` 默认 3 次，失败达到阈值后标记不健康；成功恢复立即标记健康。
- 所有端口必须在 `1..=65535`；ping 不允许配置端口。
- UI、API normalization 和自动化模板必须保留 TCP/UDP 的 `probe_req` 与 `probe_resp`；只有关闭探测或选择 ping 时才清空这两个字段。

探测器使用可复用的 reqwest client 处理 HTTP/HTTPS。探测结果是观测状态，不修改目标组期望配置；状态变化才刷新数据面。

目标组 API 和 UI 的健康状态只展示三类：`ok`、`nok`、`unassociated`。
目标组未被任何监听引用时展示 `unassociated`；被监听引用后，缺失观测记录
或暂未收到探测结果都按 `nok` 展示，不能把 `unknown` 暴露给用户。

## 3. DSCP 统计

网关 DSCP TC 程序只记录：

- `matched`：IPv4 TCP/UDP 目标端口命中配置端口的包数。
- `changed`：命中后实际修改 DSCP 的包数。

不再记录 `seen` 和 `ipv4`。这两个计数需要在每包路径中额外更新，且不能提供必要的运维信号。native DNAT 的 stats 结构也移除了 `seen` 字段，只保留 `listener_hit`、`rewritten`、`return_miss`、`target_miss` 等能直接定位转发问题的计数。

- `TARGET_PORTS` 使用 `HashMap<u32, u32>`（主机字节序端口 -> 1），每包仅一次端口 lookup。
- 保持最多 16 个不同端口，输入去重。map 容量 32 为更新时的新旧端口集合预留空间，不是扩大配置上限。
- 更新先写新增项再删旧项，共同端口不中断；未变化的项不写 map。此过程不是跨 key 原子事务，短暂的新旧集合并存是明确边界。
- 空集合不标记任何端口，无隐式默认 80 端口；不再通过清空整个 map 实施更新。
- 加载时检查端口 map 类型和容量、配置和统计 map 的类型/布局。旧 Array 不可按 HashMap 复用。
- 当前 Aya 版本按差量逐项 upsert，不声称使用了内核 `BPF_MAP_UPDATE_BATCH`。提高 PPS 的幅度仍需同环境 A/B 测试。

## 4. native DNAT/SNAT 数据面发布

- native listener_id 必须由监听 socket 身份（VIP、端口、协议）稳定派生，不能依赖
  配置数组顺序。仅 listener/target/health 变化时必须刷新 pinned map，保留已挂载
  TC 程序和 `NATIVE_FLOWS`；只有设备、TC priority、程序丢失或 map ABI 不匹配时才
  允许重挂载并丢弃 flow。
- native ingress 必须先查已有 flow，再查当前 listener map。已建立连接在监听删除、
  改名或目标组变化后继续按创建时的 reverse-NAT 信息转发，直到 idle timeout/GC
  删除；新连接才使用新的 listener/target 配置。
- native datapath 不支持 IPv4 分片 NAT。首片带 MF 或后续片必须直接 `PIPE` 给内核，
  不得创建 flow、不得只重写部分分片。后续若支持分片，必须增加独立的分片重组或
  conntrack 辅助设计。

## 5. 状态与生命周期

- 配置和业务对象持久化到 SQLite；运行时 eBPF map、连接流表和内核网络对象由 edge-lb 管理。
- 通知渠道配置和自动化模板配置保存时，若序列化后的 payload 与当前 SQLite
  文档完全一致，不得写入 `resource_documents`，也不得产生新的
  `config_revisions`。HA 复制仍允许发送当前配置；副本收到相同 payload 时本地
  no-op，不能把本地 no-op 解释为远端已经确认。
- native DNAT/SNAT 的连接状态源是 pinned eBPF `NATIVE_FLOWS`，不是 Linux
  内核 `nf_conntrack` 表。xSync 只能同步 native flow map 里的五元组和
  reverse-NAT value；`conntrack -L` 只能作为旁路诊断，不能作为 HA 同步、
  API 状态或正确性判断的依据。
- eBPF 程序由进程持有 link 生命周期；停止时只清理 edge-lb 自己创建的对象，不清理外部防火墙或其他程序对象。
- DSCP pinned map 的 ABI 变化必须在加载时检测；发现不匹配当前 ABI 的布局时自动重新挂载，不能静默按错误布局读取。
- reconcile 必须幂等：没有业务状态变化时不得反复 detach/attach eBPF、重写 SQLite 或重建路由。
- HA 手动切换、BFD 自动 promote 和 ka_hook MASTER/BACKUP 事件不能设置 native
  proxy dirty 标志。该 dirty 标志只表示监听配置、目标组、健康状态或自动目标组
  等业务数据发生变化，不能用作 HA VIP 所有权变化信号。
- 数据库查询和稳定的 reconcile 细节使用 `debug`；`info` 只保留启动、状态变化、真正的配置变更和错误恢复。
- 通知 webhook/IM 响应体只作为诊断文本保存和打印。每次响应最多读取
  2049 字节；超过 2048 字节时截断并追加 `...`。读取错误进入既有重试路径，
  不能转换为空字符串后伪装成功。非 UTF-8 响应用有损文本记录，HTTP 状态仍按
  实际响应码判断。
- 通知投递历史是本机运行诊断数据，不是业务审计日志。SQLite
  `notification_deliveries` 只保留最近 512 条；清理历史不写入
  `config_revisions`，也不参与 HA 配置复制。需要长期审计时必须接入外部日志或
  通知系统。

## 6. 回归要求

### 监听与目标组事务

- `listeners/config` 与 `target_groups/config` 是业务权威，通过同一 SQLite 读取事务取得快照；不能用 native 投影补写或推断业务配置。
- 所有监听/目标组 CRUD 和导入共用 `storage::proxy_config::mutate`。提交时比较业务文档及复制游标版本，校验 HA 配置、配对凭据和 active 选择的只读版本条件；将两份业务文档、复制游标与一个新版本记录原子提交。任一写入失败必须全部回滚。
- 引用检查、重名和端口冲突检查基于该快照。CAS 冲突重新读取并重新校验，最多 16 次，耗尽返回 409；可重试回调不得有网络或内核写入副作用。
- 单次资源导入是整批事务，不允许前半批提交后用通用错误掩盖部分成功。同内容更新不产生新版本，不触发 dirty；读取、导出不写回配置，读取损坏数据返回错误而非成功空列表。
- 只有提交成功且内容变化才通知派生状态收敛；派生重建保留有效健康观测，删除不再需要的记录。该通知目前不是持久化 outbox，不能宣称提交即数据面生效。
- 监听/目标组副本使用完整版本快照，不重放创建/改名/删除操作。本机展开的 VIP 不参与复制；业务请求自身的 operation ID 和集群仲裁任期仍未实现，不能将快照幂等当作客户端写请求恰好执行一次。
- 回归覆盖并发写保留、删除与新增引用竞争、SQL 中途失败回滚、无变化版本不变、空配置不复活、改名副本重放与派生状态清理。单机 SQLite 测试不能替代双机 HA 故障验收。

### SQLite 连接约束

- schema 初始化和 repository 必须共用 `storage::connection_options`：连接池上限 1、WAL、synchronous=FULL、foreign_keys=ON、busy_timeout=5000ms，SQL 查询日志保持关闭。连接本地参数在每次创建连接时配置，不能仅在初始化连接上执行一次 PRAGMA。
- 不为降低写入开销隐式切换到 NORMAL/OFF。每个 state_dir 启动时持有 `edge-lb.process.lock`，第二个 edge-lb 管理进程必须拒绝启动；单连接池对应本机串行 repository worker。busy timeout 不等于操作总超时或任意锁失败自动重试。
- 回归在文件数据库上强制创建第二条池连接，再关闭重连，逐一读回 PRAGMA 并实际验证外键拒绝孤立记录；测试增加连接数不改变生产池上限。

### HA HTTP 工作线程与连接复用

- 普通 API 保留 4 个工作线程；仅三个终结型副本接口使用独立的 1 个工作线程：POST `proxy-config/replica`、PUT `notifications/replica`、PUT `automation-templates/replica`，均位于 `/api/v1/ha/peer/`。
- `/active`、切主和普通管理请求不能占用副本线程；副本处理函数不得再同步调用对端。新增副本接口必须核对该约束，不能仅凭 `/ha/peer/` 前缀分流。
- 两类队列各最多等待 32 个请求，分发使用非阻塞入队；满载返回 503 且不执行该请求的业务 handler。此上限不代表 tiny_http 内部连接、报文体和慢客户端已全面限流。
- API 请求体上限为 1 MiB。带 `Content-Length` 且声明超限时必须在业务 handler
  前返回 413；chunked 或未知长度请求按实际读取 `limit + 1` 字节判断，实际超限
  同样返回 413。读取 IO 错误和非法 UTF-8 返回 400；业务 handler 只能接收完整、
  合法 UTF-8 字符串。
- 分流不授予权限，副本请求仍必须通过原有 trusted source 与共享 session token 校验。队列过载时可以先返回 503，不承诺一定先返回认证错误。
- HA 读写共享 reqwest blocking Client 的连接池，token 每次从当前配置加载并附加到该请求，禁止缓存到 Client 的默认认证头。对端地址直接连接，不使用环境代理，不跟随 HTTP 重定向；证书验证保持开启。
- 连接超时 3 秒；读请求总超时 5 秒、写请求总超时 10 秒；每 host 最多保留 2 条空闲连接，空闲 30 秒回收。必须完整消费响应体；读取失败不能用空字符串替代成功响应。
- 回归使用两个 loopback HTTP server 和生产请求分发器，覆盖 4 个 BACKUP 普通 worker 同时转发、MASTER 回调、普通队列满载下副本可达、精确方法/路径分流、连接复用与请求 token 变更、重定向拒绝。该测试不替代实际配对鉴权、SQLite 双机复制与主备切换验证。
- 独立副本线程只打破工作线程等待环，不提供 MASTER 提交顺序、持久化重试、operation ID 或任期屏障；不得宣称解决了 HA 配置一致性。

### 监听与目标组 HA 快照

- SQLite `proxy_replication/config` 保存 sequence、source、pairing_id、content_hash、pending 与 last_error，和 canonical 配置一起提交。它是合并到最新期望状态的持久化待发送记录，不是逐操作审计队列；中间版本允许合并，空列表必须作为删除状态发送。
- sequence 从持久化游标递增，不使用主机 uptime 或 wall clock 比较两端业务版本。Repository 启动读取数据库最大 revision 为本地 revision 分配下限；此本地序号仍不是集群任期，不支持多个进程同时管理同一数据库。
- 副本在同一配对身份内拒绝较旧 sequence；同版本必须 source/hash 相同，重复接收不写数据库、不触发 dirty。副本角色必须是 BACKUP，source 必须是当前 peer；当前配对身份变化时旧配对报文拒绝，新配对允许权威端建立基线。
- 接收、发送准备和 ACK 写入都带 HA 状态及配对文档的事务版本条件。事务前发生切主/重新配对会使 CAS 失败并重新检查；不从未知 active 记录推断写权限。旧 ACK 不能清除较新版本的 pending。
- 对端不接受显式 vip_ips。收到更高版本但共享内容相同时只更新复制元数据，不写 listener/target group、不触发业务 map reconcile；升主后重新发布也只更新复制元数据。
- 独立后台 worker 每轮最多发送一份快照，轮次结束等待 3 秒后重查；网络写超时最多 10 秒。失败保留 pending 重试，重复错误不重复告警；last_error 最多 512 字符。稳定态每 30 秒重新发送相同版本做基线检查，同版本 ACK 不产生写入。该同步延迟不是 BFD 检测或流状态同步延迟。
- gateway daemon 和 gateway 角色的独立 `ui serve` 均须启动同一复制 worker；不能让 API 返回已提交的 202 却没有任务执行者。独立 `ui serve` 不启动 BFD 或数据面收敛，不允许与另一个 daemon 共用同一 state_dir。
- HA 监听/目标组写成功返回 HTTP 202，`sync.authority` 指明已落盘的 MASTER，`authority_committed=true`、`replica_confirmed=false`；不保证立即从 BACKUP 读到新值。非 HA 保留本地 200/201。转发超时返回 502 时提交结果未知，客户端不可盲目重复创建。
- GET `/api/v1/ha/proxy-config-sync` 返回本机持久化游标。对比两端 pairing_id、sequence、source、content_hash 并检查 MASTER pending 才能判断副本确认，不能只看 BACKUP pending=false。
- 写入响应可附加 `sync.barrier`（sequence/source/pairing_id/content_hash），它是提交后读取的可见性下限，可能包含并发的后续提交，不是该操作的唯一回执或 operation_id。游标读取失败、为空或来自其他节点时省略 barrier，仍返回已提交的 202，禁止转换成写失败。
- UI 保留 create/update/delete/import 的响应；仅显式 accepted 响应启动状态查询。每次读取结束后间隔 1 秒、总等待最多 30 秒，查询不重发业务写入。BACKUP 追平 barrier 后刷新当前页面并显示“本机已收到”；MASTER 还须 pending=false 才显示“副本已确认”。同配对的更高版本可满足下限，同版本不同 source/hash 或不同配对不视为成功。未收到过快照的空游标继续等待。
- UI 查询超时、失败或缺少 barrier 只表示同步未确认，不撤销 MASTER 已落盘的成功。可手动重新检查状态，不自动重试创建；新 accepted 写入取消旧查询，退出登录、认证失效或页面卸载取消查询。表单只在写成功后关闭，写失败保留输入。
- 通知、自动化模板自身的复制仍使用原路径/语义；自动化生成的目标组进入本机制。flow-sync 与 BFD 协议不受本批修改影响。
- UI 的 accepted/pending 提示与刷新已有 API/mock 回归，发布前仍须完成浏览器实际交互、真实双机鉴权/重启测试。两端需一起更新，不兼容旧 replica 操作报文。没有仲裁/quorum 和晋升前追平屏障；分区切主不能宣称零配置丢失，版本冲突应停止覆盖并人工确认权威基线。
- 生产二进制的双进程集成回归覆盖独立 SQLite、真实 HTTP bearer、BACKUP 转发、离线 pending、SIGKILL 后重试、轮换配对凭据和停机调整角色后的写入限制。它不运行 BFD/VIP/数据面，不能替代自动配对、实时主备切换和网络分区测试。

### 自动 VXLAN MTU

- auto 不得将 UDP send 成功、设备 MTU 或内核缓存路由 MTU 当作端到端探测证明；日志必须说明路径未验证。
- IPv4 查询使用绑定 underlay 设备/源地址的 UDP socket 和实际 VXLAN 目的端口，仅查询内核已知 MTU，不发送探测数据报。查询失败不扩大 MTU。
- 自动取设备、已知路由及 1500 外层上限的最小值，减去封装开销（IPv4 50，存在 IPv6 underlay 时保守按 70）。不自动启用 jumbo；结果不足 576 必须拒绝，不能回退为更大值。显式数值 MTU 不受本规则改写。
- 设备未知时使用 1500 预算，路径仍未验证；该回退不保证跨小 MTU 链路可达。backend MSS 只向下限制到 VXLAN MTU 减 40。主动 PMTU 与 ICMP 错误反馈另行实施和验收。

### 策略路由所有权

- mark/table 的派生区间、优先级、设备名以及“看起来符合预期”的路由形状，均不能单独证明创建者。
- backend 的本机 SQLite `route_ownership/local` 只记录 netlink 创建成功后的对象；不复制到 HA 对端，不从旧规则自动认领。记录按 boot ID 与网络命名空间隔离，重启主机后的旧 ifindex 不作为新对象所有权。
- apply/cleanup 使用本机 state_dir 内的文件锁串行操作；规则匹配包含 priority、mark、mask、table、protocol 和是否有额外选择条件。路由匹配包含地址族、前缀、gateway、oif、prefsrc，并限定支持的 static/unicast/作用域属性。未知属性或无法完整 dump 时必须拒绝操作。
- 所有期望表在首次路由修改前统一检查：有未记录路由、外来规则指向同表、或者 fwmark 掩码匹配冲突时，报错并保留原对象。preflight 与 apply 共用结构化校验，不解析展示字符串推断所有权。
- 新增路由使用 CREATE|EXCL，不替换检查后新出现的外来条目。已占用的规则优先级通过实际 dump 顺延，不假定内核会因相同 priority 返回 EEXIST。
- cleanup 只按记录清理；旧网关被删除或改地址后仍可清理其旧路由，无须在新快照中找到旧网关。同表内新增的可辨识外来路由保留。存在可能被同一删除键匹配的多条规则/路由时拒绝删除。
- 幂等轮次不写所有权记录、不删除重建路由。网络拓扑变化时仍可能需要先删除已记录的旧路由再创建新路由，不承诺这一过程无黑洞窗口；HA 切主不得触发此路径。
- 升级前已有规则没有创建记录时，需要停机核实并显式处理这些资源；不得自动按数值区间删除或迁移认领。SQLite 与内核没有跨系统事务，创建 ACK 后、记录提交前进程故障可能留下未认领对象，下一轮拒绝接管并报冲突。不得把此安全拒绝描述为自动恢复成功。
- Linux 不提供创建者 UUID；其他特权程序删除后重建完全相同的对象，或与检查/删除并发竞争，无法仅凭属性绝对区分。state_dir 和网络资源必须由单一本机 edge-lb 实例管理，不把这些约束宣称为对抗特权程序的安全隔离。

涉及上述语义的修改至少覆盖：

- TCP/UDP 无 payload、带发送内容、带响应匹配三种探测路径。
- ping 不带端口，HTTP/HTTPS 状态码和 HTTPS 证书校验。
- 监听 TCP+UDP 单对象保存、读取和数据面应用。
- 目标组未绑定时不启动探测，绑定后能看到健康/不健康状态。
- 目标组健康列只能统计健康、不健康、未关联监听三类；关联监听后不能展示 `unknown`。
- DSCP 统计只输出 `matched` 和 `changed`。
- 重复 reconcile 不产生 attach churn、配置重复写入或孤立状态。
- gateway 的周期 heal 只检查 VXLAN 设备和 DSCP attachment；业务配置从 SQLite hydrate、native datapath reconcile 和 DSCP map 更新只在启动、配置版本变化或 attachment 丢失后执行。
- backend 的 xDS 长连接收到相同合并版本时只发送 ACK，不重复执行 VXLAN、FDB、策略路由、nft 和 native datapath apply；只有版本变化或首次收到版本时才应用配置。
- backend 已应用版本与该次冲突观测必须一起缓存、提交；同版本 ACK 重发该观测，不得用空列表伪装已无冲突。
- gateway 仅完整 ACK（ack=true 且 version/response_nonce 非空）可以用空 conflicts 清除旧告警；不带版本/nonce 的心跳和空冲突 NACK 不代表新的健康观测。
- backend 订阅与其 overlay 分配索引在同一个注册表锁内更新。断线清理必须匹配当前 stream_id，旧连接的退出或 ACK 不得修改新连接；TTL 清理同步删除两个索引，防止并发重连时遗留孤立节点。
- 目标组保存弹窗只在 API 写入成功后关闭，失败保留输入与错误。保存后的列表刷新失败不能把已提交写入当作失败并诱导重复提交；保存路径只进行一轮页面刷新。
- native 调度器支持 `rr`、`hash`、`consistent_hash`、`priority`、`persist` 和 `lc`：`rr` 只在健康目标 slot 间轮询，不做权重展开；`hash` 必须保留现有语义，使用内核 `bpf_get_hash_recalc(skb)` 的 skb hash 对目标 slot 取模，不得在原枚举上改成一致性 hash；`consistent_hash` 是独立策略，使用 edge-lb 自己定义的稳定流身份和用户态预计算的一致性桶表选择；`priority` 按目标权重做加权轮询；`persist` 按客户端地址保持；`lc` 按活动 flow 数选择并轮转平局。未知选择器回退到 RR。`n2/n3` 不属于纯 TCP/UDP DNAT 数据面。
- `consistent_hash` 面向 SIP 等会话稳定场景。流身份只包含客户端 IPv4、客户端源端口、监听端口和协议，故意不包含 VIP；目标身份包含目标 IPv4 和目标端口。用户态按健康目标集合生成 1024 个 HRW/Rendezvous 一致性桶，bucket score 使用 64-bit 整数混合，eBPF 新流路径只计算流桶并查 `NATIVE_CHASH_BUCKETS`，然后二次校验 `NATIVE_TARGETS` 中目标仍 active/healthy。该策略只在 active/healthy 且未禁用的目标集合中选择，忽略权重数值；`weight = 0` 仍按不可选处理以兼容现有目标禁用语义。两台 gateway 只要配置、目标集合和健康观测一致，同一流身份必须选择同一 backend。目标增删或健康变化只允许导致一致性 hash 语义下的必要迁移。metrics 必须暴露实际 pinned bucket table 的 digest 以及 bucket hit/miss/unusable/fallback 计数，用于验证双 gateway 表一致和兜底路径是否异常。
- native flow 命中任一方向时必须刷新正反两个 flow key 的 `last_seen_ns`，避免长连接单向活跃时另一方向提前过期；xSync 新建/删除走 ringbuf 事件，刷新状态通过低频差量 reconcile 同步，不做每包 refresh 事件。
- native flow map 内部的 `last_seen_ns` 是本机 monotonic clock，只能在本机用于超时和新旧比较。xSync wire 层必须发送 `last_seen_age_ns`，接收端按本机 monotonic clock 还原 `last_seen_ns`；禁止跨 gateway 直接比较或复制绝对 monotonic 时间。
- xSync 建立新的 gRPC session 并完成握手后，发送端必须清空本地 replica 索引并执行一次全量基线差量发送。接收端 ACK 的 `applied` 当前语义是“已被已挂载 datapath 接受的操作数”，幂等 no-op 也计数；发送端只有确认数等于本批发送操作数时才能推进 replica 索引。BACKUP native flow map 未挂载时不能把 0 变更误判为已同步。
- xSync 单批最多发送 4096 个 flow 操作。达到上限时优先发送 upsert，delete 延后到后续补偿轮次；这样优先保证新建/活跃连接接管能力，同时限制单条 gRPC 消息和发送端内存峰值。
- native xSync 验收必须以 `/api/v1/ha/status` 的 `xsync.state`、
  `xsync.last_error`、`xsync.last_ack_applied` 和 VIP 切主后的业务连通性为准；
  不能要求 Linux kernel conntrack 表出现同一条记录。
- HA/xSync 回归必须覆盖 A -> B 和 B -> A 两个方向的手动切主，并至少验证一条
  切主期间保持发送的 TCP 长连接不断；只验证新连接恢复不足以证明 native
  flow state 同步可接管。
- HA 切换回归必须验证 active gateway 变化不会设置 native proxy dirty 标志；
  BFD promote 路径必须复用同一约束，不能绕过手动切换路径去触发完整
  datapath reconcile。
- `lc` 的 active flow map 由 eBPF 在 flow 新建和显式删除时快速更新，同时由 gateway heal/xSync 兜底从 `NATIVE_FLOWS` 重算并删除过期 flow。不能只依赖 LRU map 被动淘汰，否则 active flow 计数不会自动回落。
- `hash` 模式才允许调用 `bpf_get_hash_recalc(skb)`；`rr`、`consistent_hash`、`priority`、`persist`、`lc` 不应为 skb hash helper 付出额外新 flow 开销。`consistent_hash` 必须使用本项目内定义的纯整数 hash/mix 函数，不能依赖内核 skb hash 或每机随机 seed。
