# edge-lb 配置指南

配置文件路径：`/etc/edge-lb/config.toml`。部署模板按角色拆分：
`deploy/config.gateway.example.toml` 和 `deploy/config.backend.example.toml`。
安装时按节点修改 token 和必要的 xDS 入口地址。`node_name` 可省略，
默认取系统主机名。

```bash
sudo edge-lb config validate --config /etc/edge-lb/config.toml
sudo systemctl restart edge-lb
```

## 职责边界

| 配置区域 | gateway | backend | 说明 |
|---|---:|---:|---|
| 顶层 `node_role/node_name/public_ip/underlay_ip` | yes | yes | 本机身份和 IP 自动发现 |
| `[discovery]` | yes | yes | 环境变量、多个 STUN 服务器、UDP source IP 探测 |
| `[gateway.reconcile]` | yes | no | gateway 数据面和 xDS 巡检间隔 |
| `[gateway.xds]` | yes | no | gateway 监听 xDS-like 控制面；trusted_source_cidrs 为空时自动取 underlay 网段 |
| `[gateway.network]` | yes | no | overlay/VXLAN/DSCP 全局参数源 |
| `[gateway.api]` | yes | no | 管理 API/UI，gateway 必须启用 |
| `[gateway.metrics]` | yes | no | gateway-only Prometheus metrics 独立端口，默认关闭 |
| `[gateway.flow_persistence]` | yes | no | gateway-only native flow map 本地快照，默认关闭 |
| `[gateway.network]` | yes | no | native VXLAN、overlay 和 DSCP 参数 |
| `[backend.xds]` | no | yes | backend 连接 gateway 控制面 |
| `[backend.return_path]` | no | yes | backend 本机 nft、策略路由、MSS 参数 |
| 目标组 / 监听配置 | yes | no | 业务配置，通过 gateway UI/API 写入 native state |

`[discovery]` 中的 `stun_servers` 是按顺序尝试的 STUN 地址列表，支持域名或
`host:port`，例如：

```toml
[discovery]
stun_servers = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"]
```

环境变量 `public_ip_env` 优先级高于 STUN；只有环境变量未提供有效地址时才会
依次请求列表中的服务器。列表为空时使用 Google 默认服务器。

backend 不配置 HA、API/UI，也不持久化 gateway 下发的业务配置。xDS 断线时
backend 保留当前内核 VXLAN/nft/route 状态并重连；重启后需要重新连上 gateway xDS
才能恢复下发数据面。

配置 `node_role = "gateway"` 时，无子命令启动会固定运行 gateway daemon 并启动管理 API/UI。`[gateway.api].listen` 监听非 loopback 地址时
必须配置 `auth_token`，并使用 Bearer token 访问。`[gateway.api].trusted_source_cidrs`
为空数组时自动信任本机 `underlay_ip` 所在网段；显式配置时只允许这些 CIDR 调用
`/api/*`。

gateway 可通过 `[gateway.metrics]` 启用独立 Prometheus metrics 端口：

```toml
[gateway.metrics]
enabled = true
listen = "0.0.0.0:19090"
trusted_source_cidrs = ["192.168.0.0/24"]
```

metrics 只在 gateway daemon 中启动，backend 不提供 metrics HTTP 端口。metrics 只接受
`GET /metrics`，不属于 `/api/v1`，也不使用 Bearer token。`trusted_source_cidrs`
为空数组时只允许本机 `underlay_dev` 所在接口网段；如果需要本机 Prometheus 通过
`127.0.0.1` 抓取，需要显式加入 `127.0.0.1/32`。

gateway 可通过 `[gateway.flow_persistence]` 启用 native flow map 本地快照：

```toml
[gateway.flow_persistence]
enabled = false
interval_secs = 30
min_remaining_ttl_secs = 5
max_records = 524288
restore_on_start = true
flush_on_shutdown = true
```

该能力只在 gateway 生效，默认关闭。开启后后台周期性将 pinned `NATIVE_FLOWS`
写入 `state_dir/native-flows.snapshot`，启动时在 native datapath reconcile 后恢复仍未过期、
仍匹配当前 listener/target endpoint 的 flow pair。快照保存 age/TTL 语义，不保存本机
monotonic `last_seen_ns` 绝对值；恢复时会按当前配置重新映射 `target_id`。

## Gateway HA 与 VIP

带连接同步的 active-backup 需要配置副本、native flow state 同步和入口 VIP 切换。
HA 只支持一对 gateway；MASTER 权威写入，BACKUP 转发写入请求并接收副本。

当前支持两种 VIP provider：`l2`、`hook`。BGP 接管模式已从配置面移除；
不内置云公网 IP/EIP API provider。

HA 集群配置不写入 TOML。配置文件只保留启动单机 gateway 所需的 bootstrap；
`[gateway.reconcile]` 只控制本机巡检间隔。
gateway peer、VIP 接管方式、hook 接管状态和当前 active gateway 状态都由 UI/API
管理，保存在 SQLite 资源中，例如：

```text
`ha/config`
`ha_active_gateway/current`
```

## VXLAN MTU 自动取值

`[gateway.network].vxlan_mtu` 支持数字或 `"auto"`。写 `"auto"` 时，edge-lb
读取 underlay 设备 MTU，再查询已知 IPv4 对端的内核路由 MTU。查询 socket 绑定本机
underlay 地址和设备，使用 VXLAN 目的端口，只 connect/getsockopt，不发送测试报文。
这不是 DF ping 或端到端 PMTU 实测。IPv4 underlay 最终取：

```text
vxlan_mtu = min(1500, underlay_dev_mtu, available_cached_route_mtus...) - 50
```

没有对端或路由查询失败时，只使用设备上限及 1500 的保守上限；设备读取失败也使用
1500。普通 IPv4 `eth0 MTU=1500` 得到 `1450`，jumbo 设备不会自动提高该值。
本机 underlay 或已知对端为 IPv6 时按 70 字节预算，保守上限为 1430；目前不查询
IPv6 路由 MTU，也不代表新增 IPv6 数据面支持。结果低于 576 时拒绝自动配置，
不得回退成更大的 1450。日志明确 `path_verified=false`：即便得到 1450，也不能
保证未知的中间链路可通过该大小的报文。需使用更大 MTU 时，先独立验证完整路径，
再显式设置数值；数值配置行为不变。主动带反馈 PMTU 探测仍未实现。
backend 从 xDS 接收 gateway 下发的 VXLAN MTU；本地 `mss` 仍是 backend 可调参数，
必须小于等于 `vxlan_mtu - 40`。

运行期 HA 配置示例：

```json
{
  "enabled": true,
  "mode": "active_backup",
  "self_index": 0,
  "preferred_active": "gateway-a",
  "connection_sync": true,
  "xsync_rpc": "grpc",
  "failover": "bfd_auto",
  "peers": [
    {
      "name": "gateway-b",
      "underlay_ip": "192.168.0.16",
      "public_ip": "203.0.113.11",
      "api_addr": "192.168.0.16:18080",
      "xds_addr": "192.168.0.16:22222"
    }
  ],
  "vip": {
    "provider": "l2",
    "private_vip": "192.168.0.6",
    "bind_device": "loopback",
    "bind_timeout_secs": 15,
    "verify_timeout_secs": 10,
    "garp": {
      "count": 10,
      "interval_ms": 100,
      "repeat_after_ms": 1000,
      "repeat_count": 1
    }
  }
}
```

`l2` 使用本机 VIP 地址和 GARP；`hook` 执行固定外部
promote/demote/verify 脚本。只有 provider verify 确认 VIP 已命中新 `MASTER` 后，
failover 才算完成。
L2 VIP 默认绑定到 `lo`，主备切换时由当前 MASTER 自动绑定、BACKUP 自动解绑；
只有 L2/云网络明确要求时才将 `bind_device` 改为 `underlay`。
`vip.garp` 只在 `provider=l2` 时作为高级配置显示，控制 edge-lb 内置
GARP 行为：每轮发送 `count` 组 gratuitous ARP request + reply，组内间隔
`interval_ms`；初始发送完成后再补发 `repeat_count` 轮，每轮之间等待
`repeat_after_ms`。默认值表示先发 10 组，1 秒后再补发 10 组。
`hook` 模式固定使用 `/usr/local/bin/edge-lb-promote`、
`/usr/local/bin/edge-lb-demote` 和 `/usr/local/bin/edge-lb-verify-vip`；
UI/API 不允许修改路径。`edge-lb install` 和 gateway daemon 会自动创建缺失脚本并
设置 `0755` 权限，已有脚本内容不会被覆盖。
native listener 的 `vip_ips` 是可选附加入口地址列表，空列表时由 gateway 自动使用本机
入口地址及已生效的 HA VIP；TCP/UDP 监听不需要额外入口地址字段。
监听表单第一阶段隐藏 `mark/security/host/BGP/proxyProtocolV2/egress`，提交时
固定写 native 默认值；这些字段只在流量隔离、L7/TLS、BGP 发布、后端解析
Proxy Protocol 或出站 LB 场景明确需要时再开放。
HA 模式固定为 active-backup，连接同步固定开启，xSync 使用 gRPC，故障切换由
BFD 自动触发；UI 不再提供这些等价选项。
发起 HA 自动配对的一端固定 `self_index=0`，对端 reciprocal 配置自动使用
`self_index=1`；`preferred_active` 在自动配对时固定写为发起配对的 gateway 名称。

`bfd_auto` 时由 native HA 状态机和 peer 探测决定 active gateway，并更新
SQLite `ha_active_gateway/current` 后发布 xDS。

HA 第一阶段只支持两台 gateway。当前策略是非抢占式：故障期间 peer 升为
`MASTER` 后，原 `preferred_active` 节点恢复不会自动抢回 VIP，避免恢复时二次
切换影响已有连接。`preferred_active` 只作为自动配对时的初始主节点，以及双
`MASTER`/双 `BACKUP` 冲突时的 tie-breaker；需要切回初始主节点时，通过 UI/API
主备切换显式执行。

peer API/xDS 地址用于配置转发、状态聚合和副本同步；两台 gateway 的
`self_index` 由自动配对分配为 0 和 1，不允许重复。

HA 配置写入 state_dir 后由 native HA runtime 立即重载；不需要重启外部代理容器。

backend HA 模式下建议使用多 gateway xDS：

```toml
[backend.xds]
gateways = ["192.168.0.12:22222", "192.168.0.16:22222"]
token = "change-me-token-123456"
reconnect_interval_secs = 3
```

`gateways` 是 backend 连接 gateway 控制面的地址列表，单 gateway 写一个地址，
active-backup HA 最多两个地址；超过两个会配置校验失败，不会只取前两个。

## xDS 下发内容

gateway 下发的是 backend 回程数据面所需的快照，不下发 gateway 业务配置或运行参数。允许下发：

- VXLAN 参数：`overlay_cidr`、gateway VXLAN 接口名、`vni`、`vxlan_port`、`vxlan_mtu`。
- 本 gateway 节点信息：名称、underlay 地址和 overlay 地址。
- return path contract：每个 gateway 的 underlay IP、overlay IP、DSCP、fwmark
  和 route table，以及本 backend 在对应 overlay 中使用的 overlay IP。

backend 不订阅 listener、target group、目标端口、健康探测或运行期服务投影。
backend nft 在所有 IPv4 ingress 的 original 方向按 DSCP 识别连接，不匹配 L4
protocol 或 backend port。业务监听端口由 gateway DSCP marker 负责限定。
同 DSCP 直连流量也会被分类，部署方必须在网络边界隔离这些 codepoint。

不下发：`[gateway.api]`、`[gateway.reconcile]`
的本地管理细节，以及 active gateway 运行期状态、
API token、backend inventory 和公网 IP。
`underlay_dev` 和 `[backend.return_path].vxlan_dev` 是 backend 本机配置，不由
gateway 覆盖。推荐命名：gateway 使用 `edge-hub`，backend 使用 `edge-return`。

backend 同时订阅两个 HA gateway 时，收到其中一个 gateway 的 snapshot 后不会立刻
收窄数据面；必须等配置中的两个 gateway snapshot 都到齐，才合并并 apply 多 gateway
return path。重复收到相同合并版本只 ACK，不重复重建 VXLAN、nft 或策略路由。

gateway 运行时会从 SQLite HA 配置合并 HA peer 到 gateway 节点清单；
如果某个 HA peer 的 underlay IP 曾经作为 backend 注册过，会从 backend inventory
中移除，避免同一节点同时被视为 gateway 和 backend。

## xdp-firewall 共存

xdp-firewall 挂在 gateway 对外网卡 XDP 层时，会早于 edge-lb TC datapath 和
edge-lb DSCP filter 执行。可以共存，但白名单必须让 edge-lb 相关流量
直接 PASS；edge-lb 不会主动卸载外部 XDP 程序。

至少需要放行：

- 业务监听端口，例如 TCP/UDP `80`。
- VXLAN UDP `4789`。
- gateway 间 HA/BFD 或控制面使用的端口。
- backend 到 gateway 的 xDS TCP `22222`。
- 管理 API TCP `18080`，仅限可信来源。
- metrics TCP `19090`，仅在 `[gateway.metrics].enabled = true` 时放行可信来源。

gateway 启动和巡检会检测 `underlay_dev` 上的 XDP attachment。如果发现外部 XDP，
日志会提示需要配置的 PASS 端口，`/api/v1/status` 也会返回
`underlay_xdp_attachment` 供 UI 展示。

edge-lb 会额外创建自管 nftables 表 `inet edge_lb_guard`，在 input hook 上保护
管理 API 端口：只允许 loopback、本机 underlay IP 和 HA peer underlay IP 访问，
其余管理流量按规则拒绝。该保护不依赖宿主机安装 `nft` 命令；正常 daemon 停机
不会删除规则，只有执行 gateway cleanup 时才删除。

### HA 安全边界

管理 API 默认启用 Bearer token 和 trusted source CIDR。HA 控制面只允许两台
gateway 的 underlay 地址互联；xdp-firewall 位于更早的 XDP 层时，必须放行 HA、
xDS 和业务所需端口，否则 edge-lb 内部规则无法挽救已被 XDP 丢弃的报文。

backend 收到 xDS snapshot 后必须以 gateway 分配的 overlay 地址为准收敛
`edge-return`。如果接口已存在，也要重新设置地址、MTU 和 up 状态，并清理同一
IP family 下的过期 overlay 地址，避免多 backend 出现重复 overlay 地址。

backend 在应用 snapshot 前会检查本机 VXLAN/路由冲突，并通过 xDS 上报给 gateway：

- planned overlay CIDR 与本机非 `edge-return` 网卡地址段重叠。
- planned overlay IP 已落在本机其他网卡地址段内。
- 主路由表已有覆盖 planned overlay 网段的非 `edge-return` 路由。
- planned fwmark rule priority 已被非预期规则占用。
- planned return route table 中存在非 edge-lb 预期路由。

这些冲突作为预警展示在 gateway 的 VXLAN 节点页面。第一阶段不自动修改冲突对象，
避免误删其他业务网络；管理员应调整 `[gateway.network].overlay_cidr`、DSCP 或
backend return-path 路由表参数后重新应用。

backend 发起 xDS 注册时必须上报本机实际 `public_ip`、`underlay_ip`，以及对应
发现模式和来源。模式为 `auto` 或 `static`；常见来源包括 `env`、`stun`、
`udp_source`、`underlay_fallback`、`config`。gateway 的节点列表以这些运行态
注册信息为准，UI 不应只展示 TOML 中的 `auto`。

gateway 的 VXLAN 节点列表是在线视图，只展示当前仍保持 xDS gRPC 订阅的 backend。
edge-lb 不持久化 VXLAN/backend 在线列表。自动配置目标组只使用当前在线 xDS
订阅，不能从缓存文件或 TOML 中的静态 backend 清单取节点。

backend policy routing 只能管理 edge-lb 自己的对象：删除规则时必须精确匹配
fwmark、mask、priority 和 table；写 route table 前必须确认表内没有外部路由。
如果 table ID 已被 CNI、防火墙或其他程序使用，应上报冲突并停止覆盖。自动寻找未
使用 table ID 可以作为后续增强，但必须同时记录实际分配表，保证 heal/cleanup 不
残留路由。

`ct_mark`、`fwmark`、`route_table_id` 和 `rule_priority` 的自动化边界：

- `ct_mark`/`fwmark` 可以由 gateway 按 DSCP 或 gateway index 生成并通过 xDS 下发。
- `rule_priority` 可以从起始值开始自动避让外部规则；当前实现已避免覆盖外部规则。
- `route_table_id` 可以自动分配，但必须持久化最终分配结果；当前版本先做冲突保护，
  发现外部表占用时停止覆盖并上报。

## 最小 backend 配置

```toml
node_role = "backend"
# node_name = "backend-1" # 可选；省略时默认取系统主机名
public_ip = "auto"
underlay_ip = "auto"
log_level = "info" # EDGE_LB_LOG 或 RUST_LOG 环境变量优先
state_dir = "/var/lib/edge-lb"

[backend.xds]
# 单 gateway 可写 gateway = "192.168.0.12:22222"。
# HA active-backup 模式最多写两个 gateway，backend 会按顺序尝试连接。
gateways = ["192.168.0.12:22222", "192.168.0.16:22222"]
token = "change-me-token-123456"
reconnect_interval_secs = 3

[backend.return_path]
# 本节可以整体省略；以下只是可调的本机行为参数。
vxlan_dev = "edge-return"
nft_table = "edge_lb_return"
mss = 1410
```

backend 回程固定使用 nftables/conntrack 语义：所有 IPv4 ingress 的 original 方向按 DSCP
设置 `ct mark`，reply 方向按 `ct mark` 设置 `fwmark`，再由 policy route 送入
`edge-return`。该路径适用于 TCP、UDP 和 OpenSIPS 这类长期 UDP listener，
不要求业务进程重启。当前实现通过 edge-lb 内置 nf_tables netlink 收敛，不依赖
宿主机安装 `nft` 命令。

`ct_mark`、`fwmark`、`route_table`、`route_table_id` 和 `rule_priority` 不需要
配置。单 gateway 和 HA xDS 都按 default-mode listener 的 DSCP 派生：
`mark=0x1000|((gateway_slot+1)<<6)|dscp`、
`table=1000+(gateway_slot+1)*64+dscp`。`gateway_slot` 按 gateway underlay IP
排序得到。各 gateway 必须使用不同的非零 DSCP（1..63）；slot 隔离并不能消除
相同 DSCP 的分类歧义。UDP 不学习二元 tuple、不改写 overlay 源地址，完整语义见
[业务地址与回程修复](dnat-service-address-fix.md)。

运行日志使用 `tracing`。`log_level` 支持 `error`、`warn`、`info`、`debug`、
`trace`，也支持 tracing env-filter 表达式，例如 `edge_lb=debug,tower=warn`。
环境变量优先级为 `EDGE_LB_LOG`、`RUST_LOG`、配置文件 `log_level`。当只配置
`info`、`debug` 这类简单等级时，edge-lb 会追加默认过滤规则，压制
`netlink_packet_route` 在新内核 IPv6 link attribute 长度变化上的已知噪声。
如果需要完全自定义 target 级别，设置带 `=` 或 `,` 的完整 filter。

## 监听与目标组

native 模式的配置真相源是 `target_groups` 和 `listeners`：目标组维护
backend 地址、权重和健康探测；监听维护对外地址、对外端口、目标端口、协议、策略
以及目标组引用。一个监听可以配置多个对外地址，例如：

```toml
[[target_groups]]
name = "api-targets"
targets = [{ address = "192.0.2.20", weight = 3 }]

[[listeners]]
name = "tcp-80"
vip_ips = ["192.0.2.10", "192.0.2.11"]
port = 80
target_port = 8080
protocols = ["tcp"]
target_group = "api-targets"
```

`vip_ips` 为空时使用本机网关地址和启用的 HA VIP。native eBPF 会把每个 VIP
展开为独立运行时 key，但配置中仍只有一个监听和一个目标组。目标组的健康列展示
运行态健康观测，不存在独立后端目标配置入口。

转发模式固定为 `default`，并参与 DSCP/VXLAN 回程。健康探测由目标组配置，失败的
目标会从新连接的选择中排除，已有 flow 不会被重新分配。

API 入口：

```text
GET/POST/PUT/DELETE /api/v1/target-groups[/{name}]
GET/POST/PUT/DELETE /api/v1/listener-configs[/{name}]
GET /api/v1/target-groups/export
POST /api/v1/target-groups/import
GET /api/v1/listener-configs/export
POST /api/v1/listener-configs/import
```

backend 物理节点目录由 xDS 注册学习，不再要求在 TOML 里维护。目标组表单中的
后端目标从在线 VXLAN 节点选择地址并配置权重；监听配置负责填写目标端口。节点必须
在线注册后，gateway 才会把它纳入自动配置目标组。健康探测由目标组直接配置；
native 运行态不提供独立后端目标资源，后端目标、权重和健康探测统一由目标组维护。

## Native Datapath

当前版本不依赖外部负载均衡器、容器运行时或第三方 LB API。gateway 负责加载
native DNAT/SNAT eBPF，backend 通过 xDS 接收 return path contract，并配置
VXLAN、nftables 和策略路由。

控制面请求使用短超时和有限重试；配置写入按请求幂等性处理，不对 POST 做通用盲重试。

## DSCP 计数与内存

gateway DSCP 计数使用单槽 eBPF `Array<Stats>`，实际只有几十字节，不会随连接数
增长。backend 回程依赖内核 conntrack 生命周期，不维护 edge-lb 自有 flow map。

排查 OOM 时优先看 `systemd-cgtop`、edge-lb service 的 memory.current 和 `dmesg`，
不要把 DSCP 计数误认为会随连接数增长。

## 验证

```bash
sudo edge-lb config validate --config /etc/edge-lb/config.toml
sudo edge-lb --config /etc/edge-lb/config.toml
sudo journalctl -u edge-lb -f
```

数据面验证重点：

- `http://203.0.113.10:80/health` 经过 gateway 正常。
- `http://203.0.113.12:8080/health` 后端直连正常。
- gateway 入方向 DSCP 打标，backend 回程走 VXLAN，后端应用能看到真实客户端 IP。
