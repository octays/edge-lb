# Patch Backend Redirect-only 四机验证报告

测试时间：2026-09-17 14:34-14:37 CST  
测试分支：`patch`  
基础提交：`274fae4`，含当前工作树未提交变更  
包内版本：`edge-lb 0.1.8`

## 结论

本轮已将同一个 release 二进制部署到两台 gateway 和两台 backend。四台机器
`/usr/local/bin/edge-lb` 的 SHA-256 均为：

```text
2289cffcaa4f055734706747b84c879a64003a22f2d68bfc736089366fe788eb
```

四台服务均为 `active`。VIP `192.168.0.6` 当前绑定在 gateway-a
`192.168.0.12`；gateway-b `192.168.0.16` 未绑定 VIP，未观察到双主。

backend 已切换到 Redirect-only 回程：

- backend-a `192.168.0.13`：`backend_return_ingress` 挂在 `eth0 ingress`，
  `backend_return_egress` 挂在 `eth0 egress`。
- backend-b `192.168.0.14`：`backend_return_ingress` 挂在 `eth0 ingress`，
  `backend_return_egress` 挂在 `eth0 egress`。
- 两台 backend 的 `BACKEND_RETURN_DSCP` map 均有 2 条 DSCP contract，contract
  指向 `edge-return` VXLAN ifindex 和对应 gateway overlay 邻居 MAC。
- 两台 backend 日志均显示 `return-path Redirect applied (eth0 ingress -> eth0 egress)`。

代码没有自动删除旧 nftables table、policy rule、route table 或
`/etc/iproute2/rt_tables` 条目；旧状态按
[Backend Redirect-only 迁移说明](backend-redirect-only-migration.md) 人工处理。

## 环境

公网地址不写入本文档。

| 角色 | 内网地址 | 说明 |
|---|---:|---|
| client | `192.168.0.10` | 发起 `ha-bench` 与 `nc` |
| gateway-a | `192.168.0.12` | 当前持有 VIP |
| gateway-b | `192.168.0.16` | 备用 gateway |
| backend-a | `192.168.0.13` | 目标组成员 |
| backend-b | `192.168.0.14` | 目标组成员 |

| 项 | 值 |
|---|---|
| VIP | `192.168.0.6` |
| 服务端口 | `8080` |
| listener | `tcp-udp-8080` |
| 调度算法 | `consistent_hash` |
| 后端目标 | `192.168.0.13:8080`、`192.168.0.14:8080` |

## 本地验证

| 检查项 | 结果 |
|---|---|
| `cargo fmt --all --check` | 通过 |
| `make check` | 通过 |
| `make test` | 通过 |
| `make release` | 通过 |

`make check`/`make release` 仍会提示旧 nft/policy-route 模块存在 dead-code warning。
这些模块当前只作为历史测试和只读诊断遗留；运行路径没有调用旧 nft/policy-route
apply 或 cleanup。

## 部署验证

部署后四台机器均返回同一 SHA，服务状态均为 `active`：

```bash
sudo install -m 0755 /tmp/edge-lb.patch /usr/local/bin/edge-lb
sudo systemctl restart edge-lb
systemctl is-active edge-lb
sha256sum /usr/local/bin/edge-lb
```

gateway TC 挂载：

```text
eth0 ingress:
  pref 1  dscp_mark
  pref 11 native_dnat_ingress
  pref 12 native_dnat_return

edge-hub ingress:
  pref 12 native_dnat_return
```

backend TC 挂载：

```text
eth0 ingress:
  pref 21 backend_return_ingress

eth0 egress:
  pref 22 backend_return_egress
```

VIP UDP smoke：

```bash
(printf 'discover\n'; sleep 0.2) | nc -uv -w 2 192.168.0.6 8080
```

结果：返回 `private_ipv4`，连续 5 次请求均成功，命中两台 backend。

两台 backend 在 daemon 运行期间执行 `edge-lb backend show` 均成功返回，不再因为
SQLite process lock 被运行中的 daemon 持有而失败。

## 高并发测试

所有测试从 `192.168.0.10` 发起，目标为 `192.168.0.6:8080`，payload 为
`discover`，超时为 `5000ms`。

### TCP + UDP 混合，默认 UDP socket 复用

```bash
sudo bash -lc 'ulimit -n 524288; /usr/local/bin/ha-bench \
  --target 192.168.0.6 --port 8080 --protocol both \
  --duration 30 --concurrency 64 --payload discover --timeout-ms 5000 \
  --out /home/ubuntu/edge-lb-redirect-only-2026-09-17-c64.tsv'
```

| 协议 | total | ok | fail | 成功率 | RPS/CPS | source_ports | avg ms | p50 ms | p95 ms | p99 ms | max ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| TCP | `376599` | `376599` | `0` | `100.00%` | `12553.3` | `27768` | `5.057` | `3.073` | `10.416` | `16.484` | `1072.809` |
| UDP | `412245` | `411944` | `301` | `99.93%` | `13741.5` | `64` | `5.002` | `0.785` | `3.347` | `5.639` | `5498.436` |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
|---|---:|---:|
| TCP | `194683` | `181916` |
| UDP | `316021` | `95923` |

说明：UDP 默认每个 worker 复用 socket，源端口样本只有 `64`，在
`consistent_hash` 下分布不均属于预期样本特征。`301` 次 UDP timeout 更接近后端服务
或主机 UDP 队列尾延迟，而不是固定转发路径不通。

### UDP 多源端口样本

```bash
sudo bash -lc 'ulimit -n 524288; /usr/local/bin/ha-bench \
  --target 192.168.0.6 --port 8080 --protocol udp \
  --duration 30 --concurrency 64 --payload discover --timeout-ms 5000 \
  --udp-new-socket-per-request \
  --out /home/ubuntu/edge-lb-redirect-only-2026-09-17-udp-new-socket.tsv'
```

| total | ok | fail | 成功率 | RPS | source_ports | avg ms | p50 ms | p95 ms | p99 ms | max ms |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `1849088` | `1849088` | `0` | `100.00%` | `61636.3` | `55536` | `0.961` | `0.833` | `1.807` | `3.148` | `108.747` |

后端分布：`192.168.0.13` 为 `955845`，`192.168.0.14` 为 `893243`。

### 资源采样压测

采样脚本：[sample-resource.sh](../deploy/sample-resource.sh)。采样读取 `/proc/stat`、
`/proc/meminfo`、`/proc/<edge-lb-pid>`，每秒一行，不采集高成本指标。

#### TCP + UDP 混合，concurrency=64，UDP 多源端口

命令：

```bash
sudo bash -lc 'ulimit -n 524288; /usr/local/bin/ha-bench \
  --target 192.168.0.6 --port 8080 --protocol both \
  --duration 60 --concurrency 64 --payload discover --timeout-ms 5000 \
  --udp-new-socket-per-request \
  --out /home/ubuntu/edge-lb-resource-pressure-both-c64.tsv'
```

结果：

| 协议 | total | ok | fail | 成功率 | RPS/CPS | p99 ms | max ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| TCP | `636269` | `636269` | `0` | `100.00%` | `10604.5` | `18.661` | `62.307` |
| UDP | `930701` | `930701` | `0` | `100.00%` | `15511.7` | `14.885` | `67.101` |

资源统计：

| 节点 | CPU avg | CPU p95 | CPU max | edge-lb CPU avg | edge-lb CPU p95 | mem used avg MB | edge-lb RSS MB |
|---|---:|---:|---:|---:|---:|---:|---:|
| client `192.168.0.10` | `2.20%` | `3.46%` | `6.86%` | `0.00%` | `0.00%` | `757.2` | `0.0` |
| gateway-a `192.168.0.12` | `2.29%` | `3.43%` | `6.93%` | `0.17%` | `0.50%` | `1652.3` | `30.6` |
| gateway-b `192.168.0.16` | `3.58%` | `4.68%` | `8.87%` | `1.46%` | `1.97%` | `1791.4` | `34.3` |
| backend-a `192.168.0.13` | `2.31%` | `3.68%` | `7.88%` | `0.01%` | `0.00%` | `728.6` | `32.4` |
| backend-b `192.168.0.14` | `4.61%` | `6.87%` | `23.96%` | `0.04%` | `0.00%` | `548.1` | `27.6` |

#### UDP-only，concurrency=128，UDP 多源端口

命令：

```bash
sudo bash -lc 'ulimit -n 524288; /usr/local/bin/ha-bench \
  --target 192.168.0.6 --port 8080 --protocol udp \
  --duration 60 --concurrency 128 --payload discover --timeout-ms 5000 \
  --udp-new-socket-per-request \
  --out /home/ubuntu/edge-lb-resource-pressure-udp-c128.tsv'
```

结果：

| total | ok | fail | 成功率 | RPS | source_ports | avg ms | p95 ms | p99 ms | max ms |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `3527792` | `3527792` | `0` | `100.00%` | `58796.5` | `55536` | `1.725` | `3.814` | `6.606` | `449.347` |

后端分布：`192.168.0.13` 为 `1823243`，`192.168.0.14` 为 `1704549`。

资源统计：

| 节点 | CPU avg | CPU p95 | CPU max | edge-lb CPU avg | edge-lb CPU p95 | edge-lb CPU max | mem used avg MB | edge-lb RSS max MB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| client `192.168.0.10` | `58.17%` | `99.55%` | `99.66%` | `0.00%` | `0.00%` | `0.00%` | `775.6` | `0.0` |
| gateway-a `192.168.0.12` | `10.04%` | `18.54%` | `29.56%` | `3.48%` | `8.93%` | `16.26%` | `1685.8` | `65.0` |
| gateway-b `192.168.0.16` | `45.64%` | `86.56%` | `100.00%` | `29.64%` | `70.54%` | `83.12%` | `1856.3` | `120.4` |
| backend-a `192.168.0.13` | `24.61%` | `38.76%` | `39.90%` | `0.02%` | `0.00%` | `0.51%` | `735.9` | `32.4` |
| backend-b `192.168.0.14` | `44.04%` | `69.47%` | `83.49%` | `0.04%` | `0.00%` | `0.99%` | `576.8` | `27.6` |

观察：

- 内存没有明显压力；edge-lb RSS 在混合压测约 `28-35MB`，UDP c128 高 flow churn 下
  active gateway 最高约 `120MB`，压测后未观察到持续增长。
- UDP c128 下 client CPU p95 接近满载，说明发包端已接近测试上限。
- UDP c128 下 active gateway 的 edge-lb 进程 CPU p95 较高。该模式每个请求新建 UDP
  socket，产生极高 flow churn，会放大 flow event drain、flow persistence 和 HA xSync
  的用户态成本；这不是普通长连接 SIP/RTP 模式的典型包路径成本。
- backend 侧 edge-lb 进程 CPU 接近 0，说明 backend Redirect 回程主要在 TC eBPF 内核态
  完成。backend 主机 CPU 较高来自 UDP 服务、协议栈和软中断压力。

## Backend Redirect 统计

## Active Gateway Phase 1/2 优化回归

本轮在 `patch` 分支继续部署 active gateway 压力优化后的 release 二进制，四台服务
节点 `/usr/local/bin/edge-lb` 的 SHA-256 均为：

```text
ca110e6c22c51659881f2f0fc80e35f16c57e68e848abd36a01a71be1a069563
```

额外修复：`edge-lb gateway show` 不再初始化 SQLite 运行时存储；daemon 持有
process lock 时，诊断命令会降级显示不可用的持久化配置段，而不是直接失败。

部署后状态：

| 节点 | 内网地址 | 服务状态 | 诊断结果 |
|---|---:|---|---|
| gateway-a | `192.168.0.12` | `active` | `gateway show` 成功 |
| gateway-b | `192.168.0.16` | `active` | `gateway show` 成功 |
| backend-a | `192.168.0.13` | `active` | `backend show` 成功 |
| backend-b | `192.168.0.14` | `active` | `backend show` 成功 |

VIP UDP smoke：

```bash
(printf 'discover\n'; sleep 1) | nc -uv -w 2 192.168.0.6 8080
```

结果：成功返回，backend 命中 `192.168.0.14`，client_ip 为 `192.168.0.10`。

### UDP-only，concurrency=128，Phase 1/2 优化后

命令：

```bash
sudo bash -lc 'ulimit -n 524288; /usr/local/bin/ha-bench \
  --target 192.168.0.6 --port 8080 --protocol udp \
  --duration 60 --concurrency 128 --payload discover --timeout-ms 5000 \
  --udp-new-socket-per-request \
  --out /home/ubuntu/edge-lb-phase12-udp-c128.tsv'
```

结果：

| total | ok | fail | 成功率 | RPS | source_ports | avg ms | p50 ms | p95 ms | p99 ms | max ms |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `3565126` | `3565126` | `0` | `100.00%` | `59418.8` | `55536` | `1.667` | `1.411` | `3.513` | `6.377` | `307.099` |

后端分布：`192.168.0.13` 为 `1841718`，`192.168.0.14` 为 `1723408`。

资源统计：

| 节点 | CPU avg | CPU p95 | CPU max | edge-lb CPU avg | edge-lb CPU p95 | edge-lb CPU max | edge-lb RSS max MB | mem used max MB | mem avail min MB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| client `192.168.0.10` | `2.22%` | `3.47%` | `6.34%` | `0.00%` | `0.00%` | `0.00%` | `0.0` | `760.3` | `1202.2` |
| gateway-a `192.168.0.12` | `2.29%` | `3.47%` | `4.90%` | `0.18%` | `0.50%` | `0.99%` | `63.4` | `1666.1` | `2052.7` |
| gateway-b `192.168.0.16` | `3.39%` | `4.43%` | `5.42%` | `1.39%` | `1.97%` | `1.97%` | `69.2` | `1823.9` | `1894.8` |
| backend-a `192.168.0.13` | `2.17%` | `3.41%` | `4.41%` | `0.01%` | `0.00%` | `0.49%` | `30.3` | `740.7` | `1221.9` |
| backend-b `192.168.0.14` | `4.45%` | `5.88%` | `8.82%` | `0.04%` | `0.00%` | `0.98%` | `28.1` | `587.0` | `369.4` |

对照上一轮 UDP c128 高 flow churn：

| 指标 | 优化前 | Phase 1/2 后 |
|---|---:|---:|
| UDP RPS | `58796.5` | `59418.8` |
| 成功率 | `100.00%` | `100.00%` |
| active gateway host CPU p95 | `86.56%` | `3.47%` |
| active gateway edge-lb CPU p95 | `70.54%` | `0.50%` |
| active gateway edge-lb RSS max | `120.4MB` | `63.4MB` |

观察：

- Phase 1/2 后，高 churn UDP c128 下 active gateway 用户态压力明显下降。
- 转发成功率保持 `100.00%`，后端分布维持接近 52/48。
- backend 侧 edge-lb 进程 CPU 继续接近 0，说明回程仍主要在 TC eBPF 内核态完成。
- 本轮资源采样窗口覆盖 70 秒，5 台机器采样时间一致。

## Backend Redirect 统计

`BACKEND_RETURN_STATS` 字段顺序为：

```text
learned, submitted, dscp_miss, flow_miss, expired, unsupported, mutation_error
```

压测后两台 backend 的 `learned` 与 `submitted` 持续增长，`expired`、
`unsupported`、`mutation_error` 均为 `0`。这说明请求侧 DSCP 学习和响应侧
`bpf_redirect()` 正在命中。`flow_miss` 的增长来自未匹配的非业务包或未学习响应，
当前不影响 VIP 请求成功率。

## 结论与后续

1. 当前部署已经不是 backend nftables 回程；backend 回程运行在 TC eBPF
   Redirect-only 路径。
2. 代码遵守迁移边界：不自动清理旧 nft/policy-route/rt_tables。
3. `consistent_hash` + UDP 多源端口样本在 Redirect-only 模式下达到
   `61636.3 RPS`、`100.00%` 成功率。
4. 默认 UDP socket 复用模式仍会因源端口样本少导致 backend 分布不均，并在高压下有
   少量 timeout；这与之前判断一致，优先从 backend 服务/主机 UDP 队列能力继续分析。
5. UDP c128 高 flow churn 已把 client 和 active gateway 压到明显高位；继续提升该模式
   的上限，应优先优化 flow event/xSync 批处理和测试机发包能力，而不是 backend
   Redirect eBPF 路径。
