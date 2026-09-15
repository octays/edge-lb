# Metrics 独立暴露实现说明

本文记录 edge-lb Prometheus metrics HTTP 暴露实现。metrics 属于运维观测面，使用独立监听端口和独立来源白名单，不复用管理 API/UI 端口。

## 目标

在 gateway 新增一个独立 metrics server：

- 独立监听地址和端口。
- 暴露 Prometheus text format。
- 支持来源 CIDR 白名单。
- `trusted_source_cidrs = []` 时，不表示允许所有来源，而是自动解析 `underlay_dev` 所在网段。
- 显式配置白名单时支持多个 CIDR。
- 只在 gateway daemon 中启动，backend 不提供 metrics HTTP 端口。

## 非目标

第一阶段不做以下内容：

- 不把 metrics 放到 `/api/v1`。
- 不要求 Bearer token 或 session 认证。
- 不引入 Pushgateway。
- 不引入外部 Prometheus 客户端库作为强依赖，优先直接生成 text format。
- 不在 metrics 接口返回业务配置详情、token、peer session、公网 IP 或其他敏感配置。
- 不通过 metrics 接口触发 map 重建、健康探测或数据面 reconcile。

## 配置模型

新增 gateway 配置块：

```toml
[gateway.metrics]
enabled = true
listen = "0.0.0.0:19090"
trusted_source_cidrs = []
```

字段语义：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `enabled` | `false` | 是否启动 metrics HTTP server。 |
| `listen` | `"127.0.0.1:19090"` | metrics 监听地址。生产环境如需远程抓取可改为 underlay 地址或 `0.0.0.0:19090`。 |
| `trusted_source_cidrs` | `[]` | 允许访问 `/metrics` 的来源 CIDR。空数组时自动取本机 `underlay_dev` 的接口网段。 |

白名单统一语义：

- 有显式 CIDR：只允许来源 IP 命中任一显式 CIDR。
- 空 CIDR：只允许来源 IP 命中 `underlay_dev` 所在接口网段。
- 如果无法解析 `underlay_dev` 网段，则 metrics server 启动失败，避免意外放开。
- 需要本机抓取时显式写入 `127.0.0.1/32` 或 `::1/128`，不额外叠加隐藏规则。

示例：

```toml
[gateway.metrics]
enabled = true
listen = "0.0.0.0:19090"
trusted_source_cidrs = [
  "192.168.0.0/24",
  "10.0.16.0/20",
]
```

## 访问控制

metrics 只接受：

```text
GET /metrics
```

其他 path 返回 `404`，非 GET 返回 `405`。

请求处理流程：

```text
remote_addr
  -> source IP
  -> effective trusted CIDRs
  -> match CIDR
  -> render metrics
```

不做 token 是为了保持 Prometheus 抓取简单；安全边界由监听地址、CIDR 白名单和宿主机防火墙共同承担。

需要复用现有 API CIDR 匹配实现，但要抽出通用模块，例如：

```text
api/auth.rs
  -> runtime/access.rs 或 linux/cidr.rs
```

避免 API 和 metrics 各自维护一套 CIDR 解析逻辑。

## 指标范围

第一阶段只暴露 gateway 已有、稳定、读取成本低的指标。

通用指标：

```text
edge_lb_node_info{role="gateway",node="..."} 1
edge_lb_build_info{version="..."} 1
edge_lb_underlay_info{dev="...",underlay="..."} 1
```

gateway 指标：

```text
edge_lb_gateway_dscp_attached 0|1
edge_lb_gateway_native_datapath_attached 0|1
edge_lb_gateway_dscp_packets_matched_total
edge_lb_gateway_dscp_packets_changed_total
edge_lb_gateway_native_listener_hit_total
edge_lb_gateway_native_listener_miss_total
edge_lb_gateway_native_target_miss_total
edge_lb_gateway_native_return_miss_total
edge_lb_gateway_native_rewritten_total
edge_lb_gateway_native_checksum_error_total
```

说明：

- gateway 指标从现有 `dscp::stats()` 和 `native_dnat::stats()` 读取。
- 目标组健康状态后续可增加，但第一阶段只暴露聚合数量，避免 label 高基数。

后续可选指标：

```text
edge_lb_target_group_targets{group="...",state="healthy|unhealthy"} N
edge_lb_listener_configured{listener="...",protocol="tcp|udp",port="..."} 1
edge_lb_ha_role{role="master|backup|unknown"} 1
edge_lb_ha_peer_reachable 0|1
edge_lb_xds_backend_subscriptions N
```

这些指标需要先确认 label 边界，避免把 backend 地址、VIP、公网入口或动态 flow tuple 全部暴露成高基数 label。

## 代码结构

配置模型：

```text
edge-lb/src/config/model.rs
  MetricsConfig
  GatewayConfig.metrics
```

默认：

```text
enabled = false
listen = "127.0.0.1:19090"
trusted_source_cidrs = []
```

同步更新：

```text
edge-lb/src/config/render.rs
edge-lb/src/config/validate.rs
docs/config.md
deploy/config.gateway.example.toml
```

CIDR helper 统一：

```text
edge-lb/src/runtime/access.rs
```

主要接口：

```rust
pub fn underlay_device_cidr(cfg: &Config) -> anyhow::Result<String>;
pub fn source_allowed(ip: IpAddr, cidrs: &[String]) -> anyhow::Result<bool>;
pub fn metrics_trusted_source_cidrs(cfg: &Config) -> anyhow::Result<Vec<String>>;
pub fn api_trusted_source_cidrs(cfg: &Config) -> Vec<String>;
```

metrics 的 `metrics_trusted_source_cidrs` 使用严格模式：空列表必须成功解析 underlay CIDR，否则启动失败。API 保持现有兼容行为。

Metrics server：

```text
edge-lb/src/metrics/mod.rs
edge-lb/src/metrics/server.rs
edge-lb/src/metrics/render.rs
```

实现：

- 使用当前已有 `tiny_http`，不新增 HTTP runtime。
- 独立线程名：`edge-lb-metrics`。
- 每次 scrape 实时读取轻量指标。
- 单个请求不触发配置写入、不触发 reconcile。
- 渲染失败时返回 `500`，同时暴露日志。

Gateway daemon 启动集成：

gateway：

```text
role/gateway.rs::run()
  -> crate::metrics::spawn_gateway(&cfg)
```

backend daemon 和 `ui serve` 命令不启动 metrics，避免多角色或本地调试时意外占用端口。

测试：

单元测试：

- 多 CIDR 命中。
- IPv4/IPv6 CIDR prefix 边界。
- 空白名单解析 underlay_dev CIDR。
- 显式 CIDR 时不再隐式叠加 underlay CIDR。
- metrics text format 转义 label。

集成/回归：

```bash
curl http://127.0.0.1:19090/metrics
curl --interface <underlay-source> http://<node-underlay-ip>:19090/metrics
curl http://<node-underlay-ip>:19090/not-found
```

双机/部署验证：

- Prometheus 从同 underlay 网段 scrape gateway 成功。
- 非白名单来源返回 `403`。
- health target 变化后 gateway native miss/hit/rewrite 指标仍可读取。

## 文档更新

需要更新：

```text
docs/config.md
docs/architecture.md
docs/api-v1.md    # 说明 metrics 不属于 /api/v1
README.md
README.zh-CN.md
deploy/PACKAGE-README.md
```

README 只写最小启用示例和 scrape 地址，不写公网 IP。

## 实施顺序

已完成：

1. 配置模型、校验和 gateway 配置模板。
2. 通用 CIDR helper，API 行为保持不变。
3. metrics render 和独立 HTTP server。
4. gateway daemon 按 `[gateway.metrics].enabled` 启动。
5. 单元测试覆盖 CIDR 匹配和 metrics label 转义。

后续可选：

- 部署到测试环境，用 Prometheus/curl 验证白名单和指标内容。
- 确认目标组健康聚合指标 label 边界后，再加入第一阶段之外的健康聚合指标。
