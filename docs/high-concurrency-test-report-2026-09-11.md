# edge-lb 高并发回归测试报告

测试日期：2026-09-11  
增补日期：2026-09-15（`consistent_hash` 回归与 flow persistence 部署后复测）
测试目标：验证 VIP `192.168.0.6:8080` 在高并发 TCP/UDP 访问下的转发稳定性、后端分布、健康检查与 eBPF 目标表状态。

## 结论

本报告按 listener 调度算法拆成两类：`hash` 为 2026-09-11 的历史高并发基线，`consistent_hash` 为 2026-09-15 的最新回归数据。

`consistent_hash` 最新回归使用最终部署后的 `edge-lb 0.1.8`、`concurrency=64`、`timeout=5000ms`。TCP `536058/536058` 成功，成功 CPS `8934.3`；默认 UDP socket 复用模式下 `1857518/1857572` 成功，请求吞吐 `30959.5 req/s`，出现 `54` 次 timeout。UDP 多源端口样本模式下去重源端口数 `55536`，`3837088/3837088` 成功，请求吞吐 `63951.5 req/s`，后端分布约 `51.0% / 49.0%`。active gateway `192.168.0.16` 在本轮后 `target_miss_total`、`return_miss_total`、`checksum_error_total`、`consistent_hash_bucket_miss_total`、`consistent_hash_bucket_unusable_total` 和 `consistent_hash_fallback_total` 均为 `0`。

`hash` 历史基线在 `concurrency=64` 下完成。TCP 在 3 秒和 5 秒超时阈值下均达到 `100.00%` 成功率；UDP 在高压下仍有少量超时，超时阈值从 3 秒放宽到 5 秒后 timeout 从 `232` 次下降到 `164` 次，成功率保持 `99.99%`。压测结束后，两台 gateway 的 target group 均保持 `ok`，`NATIVE_TARGETS` 均为 `8` 个元素，两台 backend 服务均正常监听 TCP/UDP `8080`。

公网 UDP 探测 `<gateway-public-entry>:8080` 已恢复响应，返回 backend `192.168.0.13`。

高并发 timeout 的表现随超时阈值放宽而明显缓解，尤其 TCP 在 3 秒和 5 秒阈值下均无失败；当前判断更倾向于 backend 服务处理能力或主机协议栈队列压力，而不是 edge-lb 固定转发路径异常。

## 测试环境

| 角色 | 主机 | 地址 | 运行状态 | OS / Kernel | CPU 配置 | 内存 | CPU 频率采样 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| gateway-a | VM-0-12-ubuntu | `192.168.0.12` | `edge-lb 0.1.8`, active | Ubuntu 26.04 LTS / Linux 7.0.0-14-generic | 2 vCPU, AMD EPYC 7K62, 1 thread/core | 3.6 GiB | avg/min/max `2595.1/2595.1/2595.1 MHz` |
| gateway-b | VM-0-16-ubuntu | `192.168.0.16` | `edge-lb 0.1.8`, active | Ubuntu 26.04 LTS / Linux 7.0.0-28-generic | 2 vCPU, AMD EPYC 7K62, 1 thread/core | 3.6 GiB | avg/min/max `2595.1/2595.1/2595.1 MHz` |
| backend-a | VM-0-14-ubuntu | `192.168.0.14` | `edge-lb 0.1.8`, active | Ubuntu 26.04 LTS / Linux 7.0.0-14-generic | 1 vCPU, AMD EPYC 7K62, 1 thread/core | 0.9 GiB | avg/min/max `2595.1/2595.1/2595.1 MHz` |
| backend-b | VM-0-13-ubuntu | `192.168.0.13` | `edge-lb 0.1.8`, active | Ubuntu 26.04 LTS / Linux 7.0.0-14-generic | 2 vCPU, General Processors, 2 threads/core | 1.9 GiB | avg/min/max `2595.1/2595.1/2595.1 MHz` |
| client | VM-0-10-ubuntu | `192.168.0.10` | `ha-bench` | Ubuntu 26.04 LTS / Linux 7.0.0-14-generic | 2 vCPU, General Processors, 2 threads/core | 1.9 GiB | avg/min/max `2595.1/2595.1/2595.1 MHz` |

后端测试服务：

| 项 | 值 |
| --- | --- |
| 部署目录 | `/mnt/netdiscover` |
| 部署方式 | `nerdctl compose` |
| 镜像 | `docker.io/1228022817/netdiscover:v0.1.6` |
| 镜像 digest 前缀 | `9d4c2caa243c` |
| 监听 | TCP `0.0.0.0:8080`, UDP `0.0.0.0:8080` |

## 测试命令

### hash

以下命令对应 listener `select=hash` 的历史基线。

```bash
ssh <client-host> \
  '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 \
  --protocol both --duration 30 --concurrency 16 \
  --payload discover --expect private_ipv4 --timeout-ms 1000 \
  --out /tmp/edge-lb-ha-vip-192.168.0.6-backend-server-image.tsv'
```

```bash
ssh <client-host> \
  '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 \
  --protocol both --duration 60 --concurrency 64 \
  --payload discover --expect private_ipv4 --timeout-ms 1000 \
  --out /tmp/edge-lb-ha-vip-192.168.0.6-high-concurrency-c64.tsv'
```

```bash
ssh <client-host> \
  '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 \
  --protocol both --duration 60 --concurrency 64 \
  --payload discover --expect private_ipv4 --timeout-ms 3000 \
  --out /tmp/edge-lb-ha-vip-192.168.0.6-high-concurrency-c64-timeout3000.tsv'
```

```bash
ssh <client-host> \
  '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 \
  --protocol both --duration 60 --concurrency 64 \
  --payload discover --expect private_ipv4 --timeout-ms 5000 \
  --out /tmp/edge-lb-ha-vip-192.168.0.6-high-concurrency-c64-timeout5000.tsv'
```

### consistent_hash

测试前确认两台 gateway listener 均为 `select=consistent_hash`：

```bash
ssh <gateway-host> \
  'curl -fsS -H "Authorization: Bearer <token>" \
  http://127.0.0.1:18080/api/v1/listener-configs'
```

```bash
ssh <client-host> \
  '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 \
  --protocol both --duration 60 --concurrency 64 \
  --payload discover --expect private_ipv4 --timeout-ms 5000 \
  --out /tmp/edge-lb-chash-c64-60s-rerun-20260915.tsv'
```

该模式用于验证一致性哈希在更多源端口样本下的后端分布。`ha-bench` 每个 UDP 请求新建 socket 并绑定 ephemeral source port，不用于替代默认 UDP 吞吐基线。

```bash
ssh <client-host> \
  '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 \
  --protocol udp --duration 60 --concurrency 64 \
  --payload discover --expect private_ipv4 --timeout-ms 5000 \
  --udp-new-socket-per-request \
  --out /home/ubuntu/edge-lb-chash-udp-new-socket-c64-60s-20260915.tsv'
```

### 公网 UDP 探测

```bash
(printf 'discover\n'; sleep 1) | nc -uv -w 2 <gateway-public-entry> 8080
```

## 测试结果

### hash

本报告中的 TCP 压测模式为 `tcp_conn_mode=new-per-request`，每个 TCP 请求都会新建一次连接，因此 TCP RPS 可以近似视为 CPS。

#### CPS 与吞吐

| 场景 | TCP 尝试 CPS | TCP 成功 CPS | TCP 失败 CPS | UDP 请求吞吐 | UDP 成功率 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `concurrency=16`, `timeout=1000ms` | 8734.2 | 8734.2 | 0.0 | 19502.2 req/s | 100.00% |
| `concurrency=64`, `timeout=1000ms` | 8908.9 | 8906.9 | 2.1 | 31204.1 req/s | 99.97% |
| `concurrency=64`, `timeout=3000ms` | 8928.1 | 8928.1 | 0.0 | 30856.4 req/s | 99.99% |
| `concurrency=64`, `timeout=5000ms` | 8839.3 | 8839.3 | 0.0 | 31658.8 req/s | 99.99% |

`hash` 基线已验证的最高稳定 TCP 成功 CPS 为 `8928.1`，对应 `concurrency=64`、`timeout=3000ms`、TCP 成功率 `100.00%`。在 `timeout=1000ms` 的更严格阈值下，TCP 尝试 CPS 为 `8908.9`，成功 CPS 为 `8906.9`，失败 CPS 约 `2.1`。

UDP 使用 `udp_socket_mode=reuse-per-worker` 时没有连接建立过程，不能按 CPS 表述；`hash` 基线下高并发默认 UDP 请求吞吐约 `30.9k` 到 `31.7k req/s`。

#### 低并发基线，concurrency=16，timeout=1000ms

| 协议 | total | ok | fail | 成功率 | RPS | p50 | p95 | p99 | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP | 262026 | 262026 | 0 | 100.00% | 8734.2 | 1.506ms | 3.528ms | 5.070ms | 23.278ms |
| UDP | 585065 | 585065 | 0 | 100.00% | 19502.2 | 0.485ms | 2.576ms | 4.360ms | 12.481ms |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| TCP | 132038 | 129988 |
| UDP | 395240 | 189825 |

#### 高并发，concurrency=64，timeout=1000ms

| 协议 | total | ok | fail | 成功率 | RPS | p50 | p95 | p99 | max | 错误 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| TCP | 534536 | 534412 | 124 | 99.98% | 8908.9 | 5.537ms | 14.675ms | 19.542ms | 1010.833ms | timed out |
| UDP | 1872248 | 1871635 | 613 | 99.97% | 31204.1 | 0.869ms | 6.801ms | 10.487ms | 1063.422ms | timed out |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| TCP | 269353 | 265059 |
| UDP | 1543151 | 328484 |

#### 高并发，concurrency=64，timeout=3000ms

| 协议 | total | ok | fail | 成功率 | RPS | p50 | p95 | p99 | max | 错误 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| TCP | 535684 | 535684 | 0 | 100.00% | 8928.1 | 5.489ms | 14.781ms | 18.796ms | 1078.452ms | 无 |
| UDP | 1851386 | 1851154 | 232 | 99.99% | 30856.4 | 0.887ms | 6.373ms | 9.471ms | 3061.538ms | timed out |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| TCP | 270272 | 265412 |
| UDP | 1481267 | 369887 |

#### 高并发，concurrency=64，timeout=5000ms

| 协议 | total | ok | fail | 成功率 | RPS | p50 | p95 | p99 | max | 错误 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| TCP | 530356 | 530356 | 0 | 100.00% | 8839.3 | 5.493ms | 14.974ms | 19.600ms | 1069.893ms | 无 |
| UDP | 1899530 | 1899366 | 164 | 99.99% | 31658.8 | 0.912ms | 6.251ms | 9.638ms | 5498.554ms | timed out |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| TCP | 267153 | 263203 |
| UDP | 1557697 | 341669 |

### consistent_hash

#### CPS 与吞吐

| 场景 | TCP 尝试 CPS | TCP 成功 CPS | TCP 失败 CPS | UDP 请求吞吐 | UDP 成功率 | source_ports |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `concurrency=64`, `timeout=5000ms`, `reuse-per-worker` | 8934.3 | 8934.3 | 0.0 | 30959.5 req/s | 100.00% | 64 |
| `concurrency=64`, `timeout=5000ms`, `udp-new-socket-per-request` | - | - | - | 63951.5 req/s | 100.00% | 55536 |

`consistent_hash` 默认 UDP socket 复用模式用于吞吐基线；`udp-new-socket-per-request` 用于增加源端口样本，验证调度分布，不与默认 UDP socket 复用模式直接比较吞吐。

#### 高并发，concurrency=64，timeout=5000ms，2026-09-15 首轮

测试前后两台 gateway API 均确认 listener 为 `select=consistent_hash`；active gateway 为 `192.168.0.16`。本轮使用 `edge-lb 0.1.8`，`ha-bench` 从 `192.168.0.10` 向 VIP `192.168.0.6:8080` 发起。

| 协议 | total | ok | fail | 成功率 | RPS | p50 | p95 | p99 | max | 错误 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| TCP | 511446 | 511446 | 0 | 100.00% | 8524.1 | 8.605ms | 14.804ms | 19.778ms | 47.859ms | 无 |
| UDP | 1882660 | 1882660 | 0 | 100.00% | 31377.7 | 0.884ms | 6.920ms | 10.178ms | 39.412ms | 无 |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| TCP | 249540 | 261906 |
| UDP | 1531898 | 350762 |

active gateway 指标增量：

| 指标 | 测试前 | 测试后 | 增量 |
| --- | ---: | ---: | ---: |
| `edge_lb_process_cpu_seconds_total` | 102.03 | 137.00 | 34.97 |
| `edge_lb_gateway_dscp_packets_matched_total` | 11124725 | 16075419 | 4950694 |
| `edge_lb_gateway_native_listener_hit_total` | 11124725 | 16075419 | 4950694 |
| `edge_lb_gateway_native_rewritten_total` | 19896902 | 28782217 | 8885315 |
| `edge_lb_gateway_native_target_miss_total` | 0 | 0 | 0 |
| `edge_lb_gateway_native_return_miss_total` | 0 | 0 | 0 |
| `edge_lb_gateway_native_checksum_error_total` | 0 | 0 | 0 |

`consistent_hash` 下默认 UDP 后端分布不均匀。该现象来自当前 `ha-bench` UDP 默认 `reuse-per-worker`，源端口数量约等于 worker 数；一致性桶按有限源端口集合映射，不能用这组样本判断真实多客户端、多源端口场景的均匀性。TCP 默认每请求新连接，源端口样本更丰富，分布接近均衡。

#### 最终部署后复测，concurrency=64，timeout=5000ms，2026-09-15

本轮在 flow persistence / HA restore 修正完成并滚动部署到两台 gateway 后执行。压测目标仍为 VIP `192.168.0.6:8080`，active gateway 为 `192.168.0.16`。

```bash
ssh <client-host> \
  'sudo bash -lc '"'"'ulimit -n 524288; /usr/local/bin/ha-bench \
  --target 192.168.0.6 --port 8080 --protocol both \
  --duration 60 --concurrency 64 --payload discover --timeout-ms 5000'"'"''
```

| 协议 | total | ok | fail | 成功率 | RPS | source_ports | p50 | p95 | p99 | max | 错误 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| TCP | 536058 | 536058 | 0 | 100.00% | 8934.3 | 27768 | 5.422ms | 14.834ms | 19.325ms | 1049.146ms | 无 |
| UDP | 1857572 | 1857518 | 54 | 100.00% | 30959.5 | 64 | 0.857ms | 8.027ms | 11.864ms | 5484.570ms | timed out x54 |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| TCP | 272561 | 263497 |
| UDP | 1537099 | 320419 |

active gateway 压测后指标：

| 指标 | 值 |
| --- | ---: |
| `edge_lb_process_cpu_seconds_total` | 193.83 |
| `edge_lb_gateway_dscp_packets_matched_total` | 8911157 |
| `edge_lb_gateway_native_listener_hit_total` | 8911157 |
| `edge_lb_gateway_native_rewritten_total` | 16754297 |
| `edge_lb_gateway_native_target_miss_total` | 0 |
| `edge_lb_gateway_native_return_miss_total` | 0 |
| `edge_lb_gateway_native_checksum_error_total` | 0 |
| `edge_lb_gateway_native_consistent_hash_bucket_hit_total` | 83390 |
| `edge_lb_gateway_native_consistent_hash_bucket_miss_total` | 0 |
| `edge_lb_gateway_native_consistent_hash_bucket_unusable_total` | 0 |
| `edge_lb_gateway_native_consistent_hash_fallback_total` | 0 |

#### UDP 多源端口样本，concurrency=64，timeout=5000ms，2026-09-15 首轮

本轮只测试 UDP，使用 `udp_socket_mode=new-per-request` 增加源端口样本。新版 `ha-bench` 在 summary 中统计去重源端口数量，本轮 `source_ports=55536`。

| 协议 | total | ok | fail | 成功率 | RPS | source_ports | p50 | p95 | p99 | max | 错误 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| UDP | 3590796 | 3590793 | 3 | 100.00% | 59846.6 | 55536 | 0.914ms | 1.858ms | 2.743ms | 5270.022ms | timed out x3 |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| UDP | 1747850 | 1842943 |

在源端口样本从约 `64` 个提升到 `55536` 个后，UDP 后端分布约为 `48.7% / 51.3%`，符合 `consistent_hash` 在两台健康后端上的预期均衡性。该模式同时增加本机 socket 创建/销毁压力，因此结论用于验证调度分布，不替代默认 UDP socket 复用模式的吞吐基线。

#### UDP 多源端口样本，最终部署后复测，2026-09-15

```bash
ssh <client-host> \
  'sudo bash -lc '"'"'ulimit -n 524288; /usr/local/bin/ha-bench \
  --target 192.168.0.6 --port 8080 --protocol udp \
  --duration 60 --concurrency 64 --payload discover --timeout-ms 5000 \
  --udp-new-socket-per-request'"'"''
```

| 协议 | total | ok | fail | 成功率 | RPS | source_ports | p50 | p95 | p99 | max | 错误 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| UDP | 3837088 | 3837088 | 0 | 100.00% | 63951.5 | 55536 | 0.923ms | 1.819ms | 2.813ms | 27.880ms | 无 |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| UDP | 1955883 | 1881205 |

本轮多源端口 UDP 分布约为 `51.0% / 49.0%`，`consistent_hash` bucket miss、unusable 和 fallback 计数均为 `0`。

### 公网 UDP 探测结果

```text
Connection to <gateway-public-entry> port 8080 [udp/http-alt] succeeded!
{"hostname":"netdiscover-serve","private_ipv4":"192.168.0.13","public_ipv4":"<redacted>","public_ipv6":"","client_ip":"<redacted>","client_port":21623}
```

## 压测后状态

### Gateway 健康状态

两台 gateway 的 target group `8080` 均为 `ok`，两个 target 均为 `ok`：

```json
{
  "items": [
    {
      "name": "8080",
      "health": "ok",
      "targets": [
        { "backend": "VM-0-13-ubuntu", "address": "192.168.0.13", "health": "ok", "weight": 1 },
        { "backend": "VM-0-14-ubuntu", "address": "192.168.0.14", "health": "ok", "weight": 1 }
      ]
    }
  ],
  "page": 1,
  "per_page": 20,
  "total": 1
}
```

两台 gateway 的 eBPF target map 状态：

```text
NATIVE_TARGETS: Found 8 elements
```

### Backend 运行状态

两台 backend 的 `netdiscover-serve` 容器均为 `running`，镜像均为：

```text
docker.io/1228022817/netdiscover:v0.1.6
```

两台 backend 均监听：

```text
tcp LISTEN 0.0.0.0:8080
udp UNCONN 0.0.0.0:8080
```

## 观察与判断

1. TCP 高并发路径稳定。`concurrency=64` 下放宽到 3 秒和 5 秒超时后均为 0 失败，p99 约 `18.8ms` 到 `19.6ms`，说明正常延迟主体稳定，1 秒超时失败来自极少量尾延迟。
2. UDP 高并发路径可用但在默认 socket 复用模式下仍可能有少量超时。历史 `hash` 基线中 `concurrency=64` 下 3 秒超时有 `232` 次 timeout，5 秒超时下降到 `164` 次 timeout；最终部署后的 `consistent_hash` 复测在 5 秒超时下有 `54` 次 timeout。多源端口 UDP 模式则 `3837088/3837088` 全成功。当前判断仍更倾向于 backend 服务处理能力、UDP socket buffer、softirq backlog 或主机协议栈队列压力，而不是固定转发路径不通。
3. 控制面和健康面未出现异常。压测后 target group、target health、backend 容器、监听状态和 eBPF map 都保持正常。
4. 默认 UDP socket 复用模式下后端分布不如 TCP 均匀，原因是源端口数量受 worker 数影响。`--udp-new-socket-per-request` 复测将去重源端口样本提升到 `55536` 后，`consistent_hash` UDP 分布从首轮约 `48.7% / 51.3%` 到最终部署后约 `51.0% / 49.0%`，更接近真实多客户端、多源端口场景。

## 后续建议

1. 增加 `concurrency=128`、`duration=300s` 的长稳测试，分别记录 1 秒、3 秒和 5 秒超时阈值结果。
2. 高并发 UDP 场景同时采集 `ss -su`、网卡丢包、softnet、nft counters 和 gateway eBPF stats，定位少量 timeout 的发生点。
3. 对 `--udp-new-socket-per-request` 增加 `concurrency=128`、`duration=300s` 长稳测试，并同步采集 source port 样本数、后端分布和 timeout 类型。
4. gateway 转发路径优化方案单独记录在 [forwarding-performance-options.md](forwarding-performance-options.md)，包括 veth、TC redirect、XDP 和 AF_XDP 的收益边界与验证顺序。
