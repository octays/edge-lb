# HA 压力测试报告

报告版本：v1

测试日期：2026-09-07

## 测试范围

本报告记录 edge-lb 原生 active-backup HA 部署的压力测试结果。测试从压测机向 HA 私网 VIP 持续发送 TCP 和 UDP 请求，请求形态与手工验证保持一致：

```bash
(printf 'discover\n'; sleep 1) | nc -v -w 1 192.168.0.6 8080
(printf 'discover\n'; sleep 1) | nc -uv -w 1 192.168.0.6 8080
```

脚本不会只根据 `nc` 的连接提示判断成功，而是要求响应 body 匹配 backend discovery JSON。这样可以避免 UDP 场景里 `nc` 提示连接成功但实际没有收到业务响应的假阳性。

## 测试环境

| 角色 | 主机标识 | 节点名 |
| --- | --- | --- |
| Gateway | gateway-a | VM-0-12-ubuntu |
| Gateway | gateway-b | VM-0-16-ubuntu |
| Backend | backend-a | VM-0-14-ubuntu |
| Backend | backend-b | VM-0-13-ubuntu |
| 压测机 | load-generator | ubuntu |

部署后的运行状态：

| 项目 | 结果 |
| --- | --- |
| edge-lb 版本 | 4 台 edge-lb 节点均为 0.1.6 |
| 测试结束后的 HA 状态 | VM-0-12-ubuntu 为 MASTER，VM-0-16-ubuntu 为 BACKUP |
| BFD | up |
| xSync | connected |
| VIP 绑定 | 192.168.0.6/32 绑定在 MASTER 的 loopback |
| 监听配置 | tcp+udp/8080 |
| 目标组 | tcp-udp-8080 |
| 健康 backend | 192.168.0.13、192.168.0.14 |

## 测试工具

本次新增的压测工具：

- `scripts/edge-lb-ha-pressure.sh`：对指定 VIP 执行 TCP/UDP 压测，输出原始 TSV 和汇总统计。
- `scripts/edge-lb-ha-failover-pressure.sh`：在压测过程中触发 HA 切换，并按切换前、切换中、切换后汇总结果。
- `ha-bench`：Rust 实现的压测客户端，用真实 socket 往返耗时统计 RTT、源端口样本和后端分布，不再包含 `sleep 1` 和 `nc` 自身等待行为。

实际执行时，压测流量运行在压测机上；主备切换由操作端通过当前 MASTER 的本机 API 触发。这样压测机只负责产生业务流量，不需要持有 gateway 的管理权限。

Rust 客户端构建：

```bash
make ha-bench
scp target/x86_64-unknown-linux-gnu/release/ha-bench ubuntu@<load-generator>:/tmp/ha-bench
```

Rust 客户端基线压测：

```bash
/tmp/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol both \
  --duration 30 \
  --concurrency 8 \
  --payload discover \
  --timeout-ms 1000 \
  --out /tmp/edge-lb-ha-rust-bench.tsv
```

如果要更接近手工 `nc -N` 验证，可以增加每个 worker 的请求间隔：

```bash
/tmp/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol both \
  --duration 30 \
  --concurrency 8 \
  --payload discover \
  --timeout-ms 1000 \
  --interval-ms 10
```

Hash 稳定性验证时可以固定 UDP 源端口：

```bash
/tmp/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol udp \
  --duration 10 \
  --concurrency 1 \
  --payload discover \
  --udp-source-port 12345
```

TCP 测试会在发送 payload 后关闭写方向，对齐 `nc -N` 的请求结束语义。固定 UDP 源端口只允许单并发，因为同一个本地 UDP 源端口不能被多个 worker 同时绑定。未指定源端口时，每次 UDP 请求使用系统分配的临时源端口，更适合压测吞吐和观察分布。

## 测试结果

### Rust 客户端基线压测

`ha-bench` 不使用 `nc`，统计范围是一次 TCP/UDP 请求从发送到收到业务响应的真实 socket RTT。summary 会输出去重源端口数 `source_ports`，原始 TSV 包含 `source_port` 列。

执行命令：

```bash
/usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol both \
  --duration 30 \
  --concurrency 8 \
  --payload discover \
  --timeout-ms 1000 \
  --out /tmp/edge-lb-ha-rust-c8-reuse.tsv
```

| 协议 | 总请求数 | 成功 | 失败 | 成功率 | RPS | 平均 RTT | P50 | P95 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP | 30581 | 30386 | 195 | 99.36% | 1019.4 | 7.994 ms | 1.176 ms | 2.562 ms | 4.735 ms |
| UDP | 273385 | 273358 | 27 | 99.99% | 9112.8 | 0.879 ms | 0.802 ms | 1.501 ms | 2.270 ms |

backend 分布：

| 协议 | Backend | 成功数 |
| --- | --- | ---: |
| TCP | 192.168.0.13 | 15307 |
| TCP | 192.168.0.14 | 15079 |
| UDP | 192.168.0.13 | 146679 |
| UDP | 192.168.0.14 | 126679 |

失败类型：

| 协议 | 错误 | 数量 |
| --- | --- | ---: |
| TCP | timed out | 195 |
| UDP | timed out | 27 |

这里的 P50/P95 说明正常请求 RTT 在毫秒级；TCP P99 没有被 1 秒 timeout 拉高，UDP P99 约 2.27 ms。与 `nc` 脚本的 1 秒以上命令耗时不同，Rust 客户端能区分真实 RTT 和超时请求。

`ha-bench` 默认复用 UDP socket，更接近常见 UDP 服务长期持有 listener socket 的行为。
如需专门压测 flow 创建和回收压力，可显式使用 `--udp-new-socket-per-request`。

### Rust 客户端高并发梯度

Gateway 规格：2C4G。

压测目标：`192.168.0.6:8080`。

单轮时长：30 秒。

Payload：`discover\n`。

Timeout：1000 ms。

| 并发/协议 | 总请求数 | 成功 | 失败 | 成功率 | RPS | P50 | P95 | P99 | 主要失败类型 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 8/TCP | 30581 | 30386 | 195 | 99.36% | 1019.4 | 1.176 ms | 2.562 ms | 4.735 ms | timed out |
| 8/UDP | 273385 | 273358 | 27 | 99.99% | 9112.8 | 0.802 ms | 1.501 ms | 2.270 ms | timed out |
| 16/TCP | 25845 | 25432 | 413 | 98.40% | 861.5 | 1.094 ms | 2.451 ms | 1000.503 ms | timed out |
| 16/UDP | 304142 | 304020 | 122 | 99.96% | 10138.1 | 1.030 ms | 2.015 ms | 3.192 ms | timed out |
| 32/TCP | 29002 | 28183 | 819 | 97.18% | 966.7 | 1.090 ms | 2.944 ms | 1000.778 ms | timed out |
| 32/UDP | 296211 | 296013 | 198 | 99.93% | 9873.7 | 2.616 ms | 4.352 ms | 6.075 ms | timed out |
| 64/TCP | 45308 | 43648 | 1660 | 96.34% | 1510.3 | 1.170 ms | 259.774 ms | 1000.901 ms | timed out |
| 64/UDP | 269892 | 269105 | 787 | 99.71% | 8996.4 | 4.152 ms | 7.977 ms | 10.718 ms | timed out |
| 128/TCP | 68969 | 65568 | 3401 | 95.07% | 2299.0 | 1.382 ms | 387.978 ms | 1000.962 ms | timed out |
| 128/UDP | 221723 | 220276 | 1447 | 99.35% | 7390.8 | 10.863 ms | 23.785 ms | 30.823 ms | timed out |

结论：

1. UDP 默认复用 socket 后，并发能力明显恢复：8-32 并发可保持约 9k-10k rps，成功率 99.9%+，P99 在 2-6 ms。
2. TCP 测试是高频短连接，新建连接压力更大；随着并发升高，主要失败是 1000 ms connect/read timeout，P99 被 timeout 拉高。
3. TCP 和 UDP 同时压测时，UDP 在高并发下仍保持较高成功率；协议隔离测试进一步确认 UDP-only 8/32 并发均为 100% 成功。
4. 测试后采样显示 gateway 进程 CPU/RSS 不高：VM-0-12-ubuntu `edge-lb` 约 3.8% CPU、89 MB RSS；VM-0-16-ubuntu `edge-lb` 约 1.5% CPU、46 MB RSS。这个现象说明 timeout 不像是 edge-lb 用户态进程 CPU 打满导致。

### Rust 客户端协议隔离压测

为了排除 TCP/UDP 同时压测互相影响，分别执行 TCP-only 和 UDP-only 测试。

| 协议/并发 | 总请求数 | 成功 | 失败 | 成功率 | RPS | P50 | P95 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP/8 | 36615 | 36411 | 204 | 99.44% | 1220.5 | 0.782 ms | 1.457 ms | 2.137 ms |
| TCP/32 | 41329 | 40520 | 809 | 98.04% | 1377.6 | 0.777 ms | 1.547 ms | 1000.421 ms |
| UDP/8 | 354509 | 354509 | 0 | 100.00% | 11817.0 | 0.611 ms | 0.953 ms | 1.783 ms |
| UDP/32 | 366291 | 366291 | 0 | 100.00% | 12209.7 | 2.559 ms | 3.404 ms | 4.754 ms |

协议隔离后，UDP-only 在 8/32 并发下没有丢包，说明之前的 UDP timeout 主要来自压测客户端模型，而不是 edge-lb UDP 数据面。TCP-only 仍有少量 timeout，后续如果要继续提升短连接压测结果，应重点看 TCP SYN/SYN-ACK 链路、backend accept backlog、conntrack/flow 表容量和客户端本机端口回收。

### 系统参数优化后复测

运行期和持久化优化已应用到压测机、两台 gateway、两台 backend。

压测机：

- `net.ipv4.ip_local_port_range = 10000 65535`
- `net.ipv4.tcp_tw_reuse = 1`
- `net.ipv4.tcp_fin_timeout = 15`
- `net.ipv4.tcp_syn_retries = 3`
- `net.core.somaxconn = 65535`
- `net.core.netdev_max_backlog = 250000`
- `net.core.rmem_max = 134217728`
- `net.core.wmem_max = 134217728`
- `net.ipv4.udp_mem = 262144 524288 1048576`
- `nofile` 持久化到 `/etc/security/limits.d/99-edge-lb-bench.conf`，本次压测 shell 使用 `524288`

Gateway：

- `net.ipv4.ip_forward = 1`
- `net.core.somaxconn = 65535`
- `net.core.netdev_max_backlog = 250000`
- `net.core.rmem_max = 134217728`
- `net.core.wmem_max = 134217728`
- `net.ipv4.tcp_max_syn_backlog = 65535`
- `net.ipv4.tcp_fin_timeout = 15`

Backend：

- `net.core.somaxconn = 65535`
- `net.core.netdev_max_backlog = 250000`
- `net.core.rmem_max = 134217728`
- `net.core.wmem_max = 134217728`
- `net.ipv4.tcp_max_syn_backlog = 65535`
- `net.ipv4.tcp_fin_timeout = 15`
- `net.netfilter.nf_conntrack_max = 262144`

后续实现：gateway/backend 启动时已经自动收敛这些生产下限。已有更高配置不会被
降低，内核未暴露 conntrack sysctl 时会跳过，`ip_forward=1` 仍作为数据面必要
前置条件处理。

复测结果：

| 场景 | 总请求数 | 成功 | 失败 | 成功率 | RPS | P50 | P95 | P99 | 主要失败类型 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| both 8/TCP | 104366 | 104329 | 37 | 99.96% | 3478.9 | 1.606 ms | 3.030 ms | 4.282 ms | timed out |
| both 8/UDP | 172029 | 172029 | 0 | 100.00% | 5734.3 | 1.272 ms | 2.435 ms | 3.635 ms | - |
| TCP-only 32 | 177674 | 177079 | 595 | 99.67% | 5922.5 | 1.192 ms | 2.188 ms | 4.743 ms | timed out |
| UDP-only 32 | 361683 | 361683 | 0 | 100.00% | 12056.1 | 2.418 ms | 3.241 ms | 5.762 ms | - |

优化后，TCP 高频短连接的成功率和吞吐显著提升；UDP 继续保持 100% 成功，吞吐约 12k rps。当前 2C4G gateway + 2C2G 压测机环境下，后续再提高并发时应同步观察压测机 CPU、客户端端口回收、backend accept/backlog 和 gateway 网卡 drop 差值。

### TCP 长连接复用压测

新增 `ha-bench --tcp-reuse-conn` 后，每个 worker 复用一个 TCP 连接连续发送
`discover` 请求。该模式用于隔离短连接建连/回收开销，更接近支持长连接协议的业务。

测试命令形态：

```bash
sudo bash -lc 'ulimit -n 524288; /usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol tcp \
  --duration 30 \
  --concurrency <N> \
  --payload discover \
  --timeout-ms 1000 \
  --tcp-reuse-conn'
```

| 场景 | 总请求数 | 成功 | 失败 | 成功率 | RPS | 平均延迟 | P50 | P95 | P99 | 最大延迟 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP reuse 8 | 154131 | 154111 | 20 | 99.99% | 5137.7 | 1.564 ms | 1.129 ms | 2.078 ms | 2.934 ms | 1001.122 ms |
| TCP reuse 32 | 154353 | 153855 | 498 | 99.68% | 5145.1 | 6.273 ms | 1.203 ms | 2.470 ms | 202.825 ms | 1826.740 ms |
| TCP reuse 64 | 160633 | 159434 | 1199 | 99.25% | 5354.4 | 12.069 ms | 1.306 ms | 2.711 ms | 208.663 ms | 2002.035 ms |
| TCP reuse 128 | 165106 | 162382 | 2724 | 98.35% | 5503.5 | 23.546 ms | 1.437 ms | 3.698 ms | 1000.636 ms | 2004.614 ms |

后端分布保持基本均衡：

| 场景 | Backend 192.168.0.13 | Backend 192.168.0.14 |
| --- | ---: | ---: |
| TCP reuse 8 | 77126 | 76985 |
| TCP reuse 32 | 77014 | 76841 |
| TCP reuse 64 | 80126 | 79308 |
| TCP reuse 128 | 82008 | 80374 |

混合压测：

| 协议 | 总请求数 | 成功 | 失败 | 成功率 | RPS | P50 | P95 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP | 95969 | 95462 | 507 | 99.47% | 3199.0 | 1.883 ms | 3.922 ms | 206.959 ms |
| UDP | 158252 | 158252 | 0 | 100.00% | 5275.1 | 5.927 ms | 8.985 ms | 14.789 ms |

结论：TCP 长连接复用减少了建连开销，并发 8 时达到稳定的约 5.1k rps、
99.99% 成功率；继续提高并发后 RPS 增长有限，但 timeout 和 P99 明显上升。
当前环境的稳定长连接并发档更接近 8，极限吞吐约 5.5k rps，但不适合作为稳定
生产水位。

### TCP reuse c32 服务端侧观测

为判断 `c32` 下的 P99 和 timeout 是否主要来自压测机，追加一轮相同负载并同时在
两台 gateway、两台 backend 采集 `vmstat`、`ss -s` 和 `ip -s link`：

```bash
sudo bash -lc 'ulimit -n 524288; /usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol tcp \
  --duration 30 \
  --concurrency 32 \
  --payload discover \
  --timeout-ms 1000 \
  --tcp-reuse-conn \
  --out /tmp/edge-lb-ha-tcp-reuse-c32-observed.tsv'
```

压测结果与上一轮一致：

| 场景 | 总请求数 | 成功 | 失败 | 成功率 | RPS | P50 | P95 | P99 | 主要失败 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| TCP reuse c32 observed | 154541 | 154052 | 489 | 99.68% | 5151.4 | 1.256 ms | 2.473 ms | 203.180 ms | timed out |

服务端观测结论：

- 两台 gateway 未 CPU 打满，压测窗口内 `eth0` 和 `edge-hub` drop/error 未增长。
- backend-b 有余量，CPU idle 多数在 33%~58%，网卡 drop/error 未增长。
- backend-a 在压测窗口内接近 CPU 饱和，多数采样 idle 只有个位数，
  system CPU 可到 60%+；`edge-return` drop 计数未继续增长。
- 压测机前一轮 `vmstat` 仍有 60%+ idle，`TIME_WAIT` 很低，因此 `c32` 的 P99
  和 timeout 不能主要归因于压测机端口或 CPU 耗尽。

当前判断：`tcp-reuse c32` 的尾延迟瓶颈更可能在 backend 服务/宿主机回程处理侧，
而不是压测机发包能力；后续要继续提升稳定水位，应优先在 backend 上区分业务进程
CPU、softirq、edge-return 回程处理和应用 accept/read/write 行为。

### Rust 客户端固定 UDP 源端口 Hash 验证

执行命令：

```bash
/usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol udp \
  --duration 10 \
  --concurrency 1 \
  --payload discover \
  --timeout-ms 1000 \
  --udp-source-port 12345 \
  --out /tmp/edge-lb-ha-rust-udp-source-12345.tsv
```

| 协议 | 总请求数 | 成功 | 失败 | 成功率 | RPS | P50 | P95 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| UDP | 19387 | 19385 | 2 | 99.99% | 1938.7 | 0.396 ms | 0.459 ms | 0.629 ms |

所有成功请求均落到 `192.168.0.13`，符合基于五元组 hash 的粘性预期：同一个客户端 IP、源端口、VIP、目标端口和协议会稳定选择同一个 backend。

### Rust 客户端 A 切换到 B

初始状态：VM-0-12-ubuntu 为 MASTER，VM-0-16-ubuntu 为 BACKUP。

切换目标：VM-0-16-ubuntu。

执行命令：

```bash
/usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol both \
  --duration 60 \
  --concurrency 16 \
  --payload discover \
  --timeout-ms 1000 \
  --out /tmp/edge-lb-ha-rust-failover-a-to-b.tsv
```

| 协议 | 总请求数 | 成功 | 失败 | 成功率 | RPS | P50 | P95 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP | 20722 | 19871 | 851 | 95.89% | 345.4 | 0.739 ms | 289.084 ms | 1000.646 ms |
| UDP | 15310 | 14366 | 944 | 93.83% | 255.2 | 0.434 ms | 1013.200 ms | 1023.389 ms |

backend 分布：

| 协议 | Backend | 成功数 |
| --- | --- | ---: |
| TCP | 192.168.0.13 | 10071 |
| TCP | 192.168.0.14 | 9800 |
| UDP | 192.168.0.13 | 7507 |
| UDP | 192.168.0.14 | 6859 |

切换 API 调用后，状态最终收敛为 VM-0-16-ubuntu MASTER，VIP 绑定到 VM-0-16-ubuntu 的 loopback；测试结束后已手动切回 VM-0-12-ubuntu MASTER。

### 基线压测

执行命令：

```bash
/tmp/edge-lb-ha-pressure.sh \
  --vip 192.168.0.6 \
  --port 8080 \
  --protocol both \
  --duration 15 \
  --concurrency 8 \
  --payload discover \
  --out-dir /tmp/edge-lb-ha-baseline
```

| 协议 | 总请求数 | 成功 | 失败 | 成功率 | 平均命令耗时 |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP | 112 | 112 | 0 | 100.00% | 1026.0 ms |
| UDP | 80 | 80 | 0 | 100.00% | 1529.3 ms |

backend 分布：

| 协议 | Backend | 成功数 |
| --- | --- | ---: |
| TCP | 192.168.0.13 | 56 |
| TCP | 192.168.0.14 | 56 |
| UDP | 192.168.0.13 | 41 |
| UDP | 192.168.0.14 | 39 |

### A 切换到 B

初始状态：VM-0-12-ubuntu 为 MASTER，VM-0-16-ubuntu 为 BACKUP。

切换目标：VM-0-16-ubuntu。

| 协议 | 总请求数 | 成功 | 失败 | 成功率 | 平均命令耗时 |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP | 567 | 567 | 0 | 100.00% | 1017.4 ms |
| UDP | 360 | 360 | 0 | 100.00% | 1626.2 ms |

backend 分布：

| 协议 | Backend | 成功数 |
| --- | --- | ---: |
| TCP | 192.168.0.13 | 287 |
| TCP | 192.168.0.14 | 280 |
| UDP | 192.168.0.13 | 172 |
| UDP | 192.168.0.14 | 188 |

### B 回切到 A

初始状态：VM-0-16-ubuntu 为 MASTER，VM-0-12-ubuntu 为 BACKUP。

切换目标：VM-0-12-ubuntu。

| 协议 | 总请求数 | 成功 | 失败 | 成功率 | 平均命令耗时 |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP | 566 | 565 | 1 | 99.82% | 1012.4 ms |
| UDP | 367 | 367 | 0 | 100.00% | 1596.1 ms |

backend 分布：

| 协议 | Backend | 成功数 |
| --- | --- | ---: |
| TCP | 192.168.0.13 | 300 |
| TCP | 192.168.0.14 | 265 |
| UDP | 192.168.0.13 | 182 |
| UDP | 192.168.0.14 | 185 |

唯一一次 TCP 失败发生在切换窗口内：

```text
2026-09-07T10:55:12+08:00 tcp 0 1016 - nc: connect to 192.168.0.6 port 8080 (tcp) timed out
```

同一秒前后的 TCP 和 UDP 请求均成功，因此该失败更像是主备切换瞬间的短暂 miss，不是持续性数据面故障。

## 结论

1. 手工形态的 `nc` 基线验证中，HA VIP 的 TCP 和 UDP 转发成功率均为 100%。
2. `nc` 形态的 A -> B 主备切换过程中，TCP 和 UDP 成功率均为 100%；B -> A 回切过程中，UDP 成功率为 100%，TCP 出现 1 次切换窗口超时，整体成功率为 99.82%。
3. 修正后的 Rust 客户端显示：正常请求 RTT 在毫秒级，不存在每次请求 1 秒以上的固定延迟；`nc` 脚本中的 1 秒级耗时主要来自命令自身行为。
4. UDP 默认 socket 复用后，8/32 并发协议隔离压测均为 100% 成功，优化后 UDP-only 32 并发约 12k rps。
5. 系统参数优化后，TCP-only 32 并发提升到 99.67% 成功率、约 5.9k rps；剩余少量 timeout 后续可继续从 SYN/SYN-ACK、backend accept backlog、客户端端口回收等方向定位。
6. 两台 backend 都参与了转发，TCP/UDP 分布基本均衡。
7. 测试结束后 HA 状态恢复为 VM-0-12-ubuntu MASTER、VM-0-16-ubuntu BACKUP，VIP 正确绑定在 MASTER。

## 注意事项

- 报告中的耗时是命令级耗时，不是后端服务处理延迟。该耗时包含测试命令里的 `sleep 1` 和 `nc` 自身等待行为。
- 如果需要判断 edge-lb 自身转发延迟，应以 Rust 客户端 `ha-bench` 的 RTT 统计为准；`nc` 脚本主要用于复现手工验证命令和切换窗口可用性。
- 直接请求 backend 只能用于隔离 backend 服务或网络本身的稳定性，不能作为 HA 压测结论，因为它绕过了 VIP、gateway DNAT/SNAT、VXLAN 回程、主备切换和 xSync。
- 本次隔离验证中，`192.168.0.14:8080` 直连在 8 并发下也出现 1 秒 timeout，因此正式 HA 压测中的部分失败可能包含 backend 服务或 backend 网络路径自身抖动。
- `patch` 分支已调整本机 HA 角色提交顺序：本机 promote/demote hook 或 L2 VIP 动作成功后才写入 active 状态；peer handoff 失败时会回滚本机角色；本机 takeover 失败时会通知 peer 恢复原 active。双机切换仍应以 `/api/v1/ha/status` 和目标节点地址绑定检查为最终验收；远端确认丢失、旧操作晚到和真实故障注入仍需单独验证。
- 第一版压测脚本曾使用秒+纳秒的大整数做时间差计算，在压测机 Bash 算术中会出现边界问题并导致平均耗时异常。脚本已改为毫秒时间戳，并显式按十进制解析。
- 本轮测试前已修复 HA peer metadata 版本展示问题：`/api/v1/ha/status` 会从 live peer status 刷新展示用元数据，两台 gateway 的 peer version 均显示为 `0.1.6`。

## 原始数据

原始压测数据保留在压测机：

- `/tmp/edge-lb-ha-baseline/results.tsv`
- `/tmp/edge-lb-ha-failover-a-to-b/results.tsv`
- `/tmp/edge-lb-ha-failover-b-to-a/results.tsv`
- `/tmp/edge-lb-ha-rust-c8-reuse.tsv`
- `/tmp/edge-lb-ha-concurrency-reuse-20260907-114603/c16.tsv`
- `/tmp/edge-lb-ha-concurrency-reuse-20260907-114603/c32.tsv`
- `/tmp/edge-lb-ha-concurrency-reuse-20260907-114603/c64.tsv`
- `/tmp/edge-lb-ha-concurrency-reuse-20260907-114603/c128.tsv`
- `/tmp/edge-lb-ha-proto-isolate-20260907-120739/tcp-c8.tsv`
- `/tmp/edge-lb-ha-proto-isolate-20260907-120739/tcp-c32.tsv`
- `/tmp/edge-lb-ha-proto-isolate-20260907-120739/udp-c8.tsv`
- `/tmp/edge-lb-ha-proto-isolate-20260907-120739/udp-c32.tsv`
- `/tmp/edge-lb-ha-tcp-reuse-c32-observed.tsv`
- `/tmp/edge-lb-monitor-tcp-reuse-c32.txt`（四台 gateway/backend 各自本地）
