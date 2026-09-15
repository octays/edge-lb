# 文档索引

## 必读文档

- `architecture.md`：当前架构真相源，说明 gateway/backend/native datapath 职责、xDS、
  数据面、持久化和 HA 边界。
- `config.md`：当前配置真相源，说明 `/etc/edge-lb/config.toml`、角色配置、
  xDS 下发内容和管理 API。
- `api-v1.md`：当前管理 API 资源模型，只保留 `/api/v1` 路径。
- `native-resource-model.md`：当前业务资源模型，说明监听配置、目标组和运行态投影边界。
- `implementation-contracts.md`：已确认的监听、目标组、健康探测、DSCP 统计和生命周期
  语义。
- `vxlan-dscp-verified.md`：当前线上验证方案，记录已验证节点、VXLAN/DSCP
  参数、验证命令和排障检查。
- `ha-pressure-test-report.zh-CN.md` / `ha-pressure-test-report.md`：HA 和并发压测报告。
- `forwarding-performance-options.md`：gateway 转发性能候选方案评估，比较当前 TC DNAT、
  veth、TC redirect、XDP 和 AF_XDP 的收益边界与验证顺序。
- `cloudflare-unimog-reference.md`：Cloudflare Unimog eBPF/XDP L4LB 公开实现参考，
  记录其 XDP、GUE、forwarding table、健康状态和 TC redirector 设计，以及与 edge-lb
  当前架构的差异。
- `metrics-endpoint-plan.md`：gateway-only 独立 metrics 端口、CIDR 白名单和
  Prometheus 指标范围。
- `metrics.md`：gateway metrics 指标清单、含义、PromQL 示例和采集开销说明。
- `flow-map-persistence-research.md`：native flow map 持久化调研，说明快照/恢复边界、
  时间语义、target remap、性能风险和推荐落地步骤。

## 参考资料

当前仓库只保留 edge-lb native 数据面版本的文档。过期 provider、独立后端目标
API 和阶段计划文档已删除，不再作为实现依据。
