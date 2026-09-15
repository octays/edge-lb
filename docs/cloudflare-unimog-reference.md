# Cloudflare Unimog eBPF 负载均衡实现参考

本文整理 Cloudflare 公开文章中披露的 Unimog L4 load balancer 设计，用作 edge-lb 后续转发性能优化和控制面设计的参考。该文档不是 edge-lb 的实施方案，也不代表当前架构要迁移到 XDP。

主要参考资料：

- Cloudflare Blog: [Unimog - Cloudflare's edge load balancer](https://blog.cloudflare.com/unimog-cloudflares-edge-load-balancer/)
- eBPF.io: [Cloudflare's eBPF Replatforming Part 1](https://ebpf.io/blog/cloudflare-replatforming-1/)

## 总体模型

Cloudflare 的 Unimog 是运行在每台 edge server 上的 L4 负载均衡器。外部路由器先通过 ECMP 把 VIP 流量打到任意 edge server；收到包的 server 在 XDP 程序中判断该连接应该落到哪个 DIP，然后通过封装转发到目标 server。

简化路径：

```text
client
  -> router ECMP
  -> any Cloudflare edge server
  -> XDP l4drop / Unimog
  -> GUE encapsulation + XDP_TX
  -> selected DIP server
  -> decap / local Linux stack
  -> application
```

这个模型的关键点是：每台服务器既是业务节点，也是负载均衡节点。ECMP 只负责粗粒度分散入口流量；真正的 L4 调度由服务器本机的 XDP 程序完成。

## 数据面

Unimog 的主数据面运行在 XDP。XDP 程序挂在网卡入口，早于常规 Linux 网络栈处理包。Cloudflare 将 DDoS 过滤和 L4 load balancing 都放在这条早期路径上：

- DDoS 过滤程序识别攻击流量并直接 drop。
- Unimog 判断目的 VIP 是否需要 L4LB 处理。
- 对需要转发的包，选择 DIP。
- 对原始包进行 GUE 封装。
- 使用 XDP TX action 从网卡发出。
- 不需要处理的包 pass 给正常 Linux 网络栈。

Unimog 不是普通 DNAT 模型。它使用封装而不是简单改写目的地址，目的是保留内层原始 client -> VIP 语义，让目标 server 解封装后仍能按 VIP 语义处理连接。

## 一致性选择

ECMP 可能把同一个 VIP 的不同连接打到任意 edge server，因此所有 Unimog 实例必须在不做 per-connection 通信的情况下，对同一条连接做出一致的 DIP 选择。

公开文章中描述的基本方法是：

- 从连接四元组计算 hash。
- hash 命中 forwarding table 的一个 bucket。
- bucket 中记录目标 DIP。
- 所有 server 持有同一份 forwarding table。

这样每台 server 可以独立做出相同选择，不需要在负载均衡节点之间同步每条连接状态。

## 加权与负载反馈

Unimog 通过调整 forwarding table 中 DIP 出现的比例实现加权。能力更强或当前负载更低的 server 会出现在更多 bucket 中，获得更多新连接。

Cloudflare 的控制面会消费多类信息：

- server 列表和 DIP 信息；
- server 级和 service 级健康状态；
- Prometheus 中的负载指标；
- VIP 地址资源信息。

控制面根据负载反馈周期性调整 forwarding table，让各 server 的负载逐步收敛到目标水平。

## 健康状态

Unimog 控制面会把不可用 server 或 service 从 forwarding table 中移除，避免新连接继续打到不健康目标。

这和 edge-lb 当前语义相似：健康状态不应只影响 UI 展示，也必须影响 datapath 中可选 backend 的集合。差异是 Unimog 更新的是 XDP forwarding table；edge-lb 当前更新的是 pinned eBPF maps 中的 listener、target 和 flow 相关状态。

## 老连接保持

更新 forwarding table 会影响新连接，但老连接可能仍在旧 DIP 上。Cloudflare 借鉴 Beamer 类设计，在 bucket 中保留当前 DIP 和前一个 DIP。

简化语义：

- 新连接优先去 bucket 的当前 DIP。
- 非 SYN 包如果到达当前 DIP 后没有本机 socket，说明它可能属于旧 DIP 上的既有连接。
- redirector 根据封装头中携带的第二跳 DIP，把包转发到旧 DIP。

Cloudflare 后续将早期依赖的 `glb-redirect` kernel module 替换为 eBPF TC classifier，也就是 `cls-redirect`。他们选择 TC 而不是 XDP 来做 redirector，是因为 redirector 大部分时候只 pass 流量，XDP 的性能优势在该位置不明显，同时 TC 更便于用 tcpdump 等常规工具调试处理前后的包。

## xdpd 与控制面下发

Cloudflare 使用 `xdpd` 管理 XDP/eBPF 程序及其 maps。公开文章提到的职责包括：

- 加载和组合多个 XDP 程序；
- 根据控制面信息填充 maps；
- 对程序中的固定配置做加载前 fix-up，避免运行时 map lookup；
- 暴露 eBPF 程序指标到监控系统；
- 支持平滑升级，减少 datapath 中断。

Unimog 控制面组件称为 conductor。每个 edge data center 中有一个 active conductor，并有 standby 实例。公开文章描述它使用 Consul KV 分发 forwarding table 和 VIP 信息，使用 Consul 健康检查作为健康来源，并从 Prometheus 获取负载指标。

## 和 edge-lb 当前架构的对比

| 维度 | Cloudflare Unimog | edge-lb 当前实现 |
| --- | --- | --- |
| 主 fast path | XDP | TC eBPF |
| 入口分发 | router ECMP 到任意 edge server | gateway VIP/入口流量 |
| 转发方式 | GUE 封装 + XDP_TX | TC DNAT/SNAT + VXLAN/DSCP return path |
| 后端语义 | decap 后保留原始 VIP 语义 | backend 只接收 VXLAN/DSCP return-path contract |
| 目标选择 | 四元组 hash + forwarding table bucket | listener/target map + flow map |
| 健康剔除 | 控制面更新 forwarding table | health 状态刷新 pinned eBPF maps |
| 老连接保护 | bucket 当前 DIP/前 DIP + TC redirector | flow map preserve，未实现 Beamer-style 二跳迁移 |
| 运维前提 | 自建 edge/bare-metal 网络，驱动和 MTU 可控 | 云 VM 环境，XDP native 支持不确定 |

## 对 edge-lb 的启发

Unimog 对 edge-lb 最有价值的参考不是“把 TC 换成 XDP”，而是以下设计原则：

1. 数据面选择应服务于明确瓶颈  
   Cloudflare 将主 L4LB 放到 XDP，是因为他们需要在入口早期处理巨量边缘流量，并且能控制硬件和驱动。edge-lb 在云 VM 上必须先确认 native XDP 可用性和瓶颈位置。

2. 一致性优先于 per-flow 同步  
   多 gateway 场景下，优先让各节点通过一致的表和 hash 独立决策，而不是依赖高频连接状态同步。

3. 健康状态必须进入 datapath  
   不健康目标应从新连接选择集合中移除；已有 flow 是否保留应由 flow preserve 和 drain 策略决定。

4. 封装是语义边界  
   Unimog 使用 GUE 保留 VIP 语义。edge-lb 当前使用 VXLAN/DSCP return-path contract，同样应避免让 backend 感知 active gateway、xDS 服务端口或其他控制面细节。

5. redirector 是辅助机制，不一定要放在最快 hook  
   Cloudflare 的 `cls-redirect` 说明：某些路径选择 TC 是为了调试性和工程边界，而不是所有逻辑都堆到 XDP。

## 不应直接照搬的部分

以下能力不应在没有验证前直接迁移到 edge-lb：

- 依赖 XDP native driver 的主转发路径；
- GUE 封装格式；
- Consul/Prometheus 作为强制控制面依赖；
- Beamer-style 二跳连接迁移；
- 每台 backend 同时作为全功能 load balancer 的部署模型。

这些设计与 Cloudflare 的自建 edge 网络、硬件控制能力、内部监控体系和大规模 anycast/ECMP 场景强相关。edge-lb 当前更应保持 native SQLite 配置、gateway/backend 职责边界和 VXLAN/DSCP contract。

## 后续验证建议

若将 Unimog 思路用于 edge-lb 后续优化，建议按以下顺序验证：

1. 明确当前瓶颈是否在 gateway 转发路径，而不是 backend 服务、host 协议栈队列或云 vNIC。
2. 在目标云主机上验证 XDP attach 模式，区分 native、generic 和不可用。
3. 先做 TC redirect PoC，验证 L2 rewrite、checksum、MTU、fallback 和 stats。
4. 如需 XDP PoC，先限定为单 VIP、单 target、UDP 或 TCP SYN 新连接路径。
5. 保持 backend 只接收 VXLAN/DSCP return-path contract，不引入 active gateway 或 xDS 服务端口感知。
6. 在设计变更前先完成方案评审，确认是否接受新增控制面和 datapath 复杂度。
