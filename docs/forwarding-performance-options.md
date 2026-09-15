# edge-lb 转发性能优化方案评估

本文记录 gateway 转发路径的候选优化方案，用于后续设计评审和压测排序。当前实现的主要转发逻辑已经在 TC eBPF 中完成；以下方案均不代表已经实现或验证。

## 结论

veth 本身不是性能提升点。只有当 veth 替代了 bridge、netfilter、namespace 等额外慢路径时，才可能带来收益；如果只是为现有路径增加一跳 veth，延迟和 CPU 开销反而可能上升。

若目标是继续提高 gateway 转发上限或降低转发延迟，优先验证的方向应是减少慢路径，例如 TC redirect fast path 或 XDP fast path，而不是先引入 veth。

## 方案比较

| 方案 | 延迟/吞吐潜力 | 复杂度 | 说明 |
| --- | --- | --- | --- |
| 当前 TC DNAT | 已经较高 | 中 | 当前主要转发逻辑已经在 eBPF，健康 target 通过 pinned map 原地增删，普通健康变化不重挂 TC 程序。 |
| TC eBPF + veth | 不一定更高 | 中高 | 如果只是多一跳 veth，可能更慢；只有在替代 bridge、netfilter、namespace 慢路径时才可能有收益。 |
| TC eBPF + redirect 直接出设备 | 可能更高 | 高 | 收益来自绕过 route、nft 或部分内核转发路径；需要重新处理邻居解析、L2 目的 MAC、MTU、checksum、fallback 和 flow/HA 一致性。 |
| XDP native driver | 最高潜力 | 很高 | 更靠近网卡入口，理论上延迟最低、吞吐最高；但 NAT、VXLAN、flow state、HA sync、分片和错误处理都会显著复杂化。 |
| AF_XDP/userspace datapath | 高但复杂 | 很高 | 可将转发逻辑移到用户态轮询路径，但需要自行承担更多协议栈能力、队列管理、CPU 绑核和运维复杂度。 |

## 当前 TC DNAT

当前 gateway 入口主要路径已经是 TC eBPF：

```text
underlay ingress -> TC eBPF native DNAT -> kernel forwarding -> backend
backend return via VXLAN -> TC eBPF reverse NAT -> client
```

健康状态变化时，gateway 原地刷新 pinned maps：

- `NATIVE_TARGETS` 只保留健康 target。
- `NATIVE_LISTENERS.weight_total` 随健康 target 重算。
- 普通健康变化不 detach/attach TC 程序。
- 已有 flow 优先命中 `NATIVE_FLOWS`，不会因为 target 健康抖动立即断开。

因此，在 gateway 当前路径上再单纯加入 veth，并不会天然减少转发步骤。

## veth 路径适用边界

veth 有价值的前提通常是它替代了更重的路径，例如：

- 容器 bridge 网络；
- iptables/nft/conntrack 慢路径；
- namespace 间的默认转发路径；
- CNI/kube-proxy 类规则链。

如果 backend 服务使用 host network，或 gateway 入口已经在 TC ingress 上完成主要 DNAT，veth 不应被视为默认加速手段。

## TC redirect fast path

TC eBPF + redirect 的潜在收益来自更早地完成转发决策，并减少后续内核路径：

```text
underlay ingress -> TC eBPF lookup/rewrite -> bpf_redirect(out_dev)
```

这条路径需要重新设计或验证：

- L2 目的 MAC 与邻居解析；
- MTU、GSO/GRO、分片边界；
- TCP/UDP checksum 更新；
- fallback 到内核慢路径的条件；
- flow map、HA xSync 与 redirect 路径的一致性；
- 与 VXLAN return path 的组合方式；
- 观测性、stats 和故障计数。

该方向比 veth 更可能带来 gateway 转发收益，但复杂度明显更高。

## XDP 与 AF_XDP

XDP native driver 的潜力最高，但也最容易扩大边界：

- NAT 和 reverse NAT 需要更早处理 L2/L3/L4；
- VXLAN、flow state、HA sync、健康目标切换都要重新对齐；
- 分片、ICMP 差错、MTU 和 fallback 更复杂；
- 不是所有云网卡或虚拟化环境都有同等 XDP driver 支持。

AF_XDP/userspace datapath 可以获得高吞吐轮询路径，但需要自行承担更多协议栈能力、队列管理、CPU 绑核和运维复杂度。它更像独立 datapath 项目，不适合作为小步优化。

Cloudflare Unimog 的公开实现可作为 XDP L4LB 参考，但它依赖自建 edge 网络、可控硬件/驱动、
GUE 封装、一致 forwarding table 和独立控制面。该实现已单独整理在
[cloudflare-unimog-reference.md](cloudflare-unimog-reference.md)，不应直接视为 edge-lb
的默认迁移路线。

## 验证顺序

1. 建立基线：记录当前 TC DNAT 的 CPS、PPS、p50/p95/p99、CPU、softirq、drop、eBPF stats。
2. 定位瓶颈：区分 backend 应用处理、host 协议栈队列、gateway TC path、nft/route/VXLAN 路径。
3. veth 对照：只在存在 bridge/netfilter/namespace 慢路径时测试 veth+TC，避免凭直觉引入额外跳转。
4. TC redirect PoC：实现最小 TCP/UDP 单 VIP 单 target 路径，验证 L2、checksum、fallback 和 stats。
5. 扩展语义：再加入多 target、健康切换、flow preserve、HA sync、VXLAN return path。
6. 最后评估 XDP/AF_XDP：仅当 TC redirect 仍无法满足目标，且复杂度可接受时推进。

## 与高并发压测的关系

2026-09-11 高并发测试中，timeout 随客户端阈值放宽而明显下降，TCP 在 3 秒和 5 秒阈值下均为 0 失败，UDP 仍有少量尾部 timeout。该现象更倾向于 backend 服务处理能力或主机协议栈队列压力，而不是固定 gateway 转发路径异常。

因此，本文的 fast path 方案应作为后续转发上限优化储备，不应替代 backend/host 队列瓶颈排查。
