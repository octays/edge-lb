# 文档索引

## 必读文档

- `dnat-service-address-fix.md`：业务 IP 与隧道地址分离、统一 DSCP/conntrack 回程，
  以及测试范围和协调升级要求。

- `architecture.md`：当前架构真相源，说明 gateway/backend/native datapath 职责、xDS、
  数据面、持久化和 HA 边界。
- `config.md`：当前配置真相源，说明 `/etc/edge-lb/config.toml`、角色配置、
  xDS 下发内容和管理 API。
- `api-v1.md`：当前管理 API 资源模型，只保留 `/api/v1` 路径。
- `native-resource-model.md`：当前业务资源模型，说明监听配置、目标组和运行态投影边界。
- `implementation-contracts.md`：已确认的监听、目标组、健康探测、DSCP 统计和生命周期
  语义。
- `vxlan-dscp-verified.md`：当前 VXLAN/DSCP 回程语义、人工验证命令和排障检查；
  本次修复的隔离测试不代表线上已部署。
- `ha-pressure-test-report.zh-CN.md` / `ha-pressure-test-report.md`：HA 和并发压测报告。
- `forwarding-performance-options.md`：gateway 转发性能候选方案评估，比较当前 TC DNAT、
  TC direct redirect 和 XDP optional fast path 的收益边界与验证顺序。
- `forwarding-optimization-implementation-plan.md`：`patch` 分支的 P0-P4 优先级、
  阶段进展、验证记录与合并条件。
- `patch-rollout-validation-2026-09-16.md`：本地重载回归、四机滚动部署摘要、旧版基线与
  三轮新版稳态测试；记录切流 UDP 超时、采样配额问题修复及 rp_filter 导致快路径未准入，尚未完成优化验收。
- `udp-return-ownership-diagnosis.md`：UDP 双归属的规则顺序、真实过期与显式源地址回归，
  HA 多余 reconcile 修复，以及待确认的有限 UDP 修复范围。
- `tc-direct-redirect-fast-path-plan.md`：TC direct redirect fast path 细化设计，记录
  BPF ABI、userspace reconcile、fallback、metrics、测试和回滚计划。
- `gateway-return-path-optimization-plan.md`：gateway 解封装后回程优化设计，记录反向
  NAT 后的 FIB 查询、redirect、TTL/MTU、HA、回退和双向性能对照。
- `backend-return-path-optimization-plan.md`：backend 回程优化候选方案，区分 host 与独立
  容器网络，记录 VXLAN/DSCP 约束、状态学习、回退条件、PoC 和性能验证计划。
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
