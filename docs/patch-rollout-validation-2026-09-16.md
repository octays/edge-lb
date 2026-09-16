# Patch 四机滚动部署与验证记录

## 状态

已完成本地回归、Linux amd64 发布构建和四机滚动部署，四台运行中二进制摘要一致。
最终 gateway-a 为 MASTER、gateway-b 为 BACKUP，BFD up、xSync connected，两个目标健康。
部署后三轮 VIP 稳态测试共 22,449 次请求全部成功，备网关直连 TCP/UDP 也通过。

**部署完成不等于性能优化验收完成：** 两网关 `rp_filter=2` 触发安全回退，正向与回程
direct redirect 的 submitted 均为零；60 秒切流测试出现 4 次 UDP 超时，TCP 最大延迟
约 1 秒。本轮未证明加速收益或无损 HA，未合并 `master`、提交、推送或创建 tag。

## 构建

| 项目 | 结果 |
|---|---|
| 分支 | `patch` |
| 基础提交 | `529fda8`，包含尚未提交的工作区优化变更，不是该提交的干净构建 |
| 包内版本 | `0.1.8`，不能仅按版本号区分本次产物 |
| 产物 | `target/x86_64-unknown-linux-gnu/release/edge-lb` |
| SHA-256 | `443bb9dbf0080c5abed5116557874538867edf74cdf9b67cc37a987e5c264dbf` |
| 发布构建 | `make release` 通过，包含 UI 和当前 eBPF 对象；链接器报告弃用优化选项 `1` 的 warning |
| 本地回归 | 单线程 308 项单元测试、1 项 HA 集成测试通过 |
| 检查 | `make check`、`cargo fmt --all --check`、`git diff --check` 通过 |

测试命令：

```bash
make test DOCKER_PRIVILEGED="docker run --rm --privileged -e RUST_TEST_THREADS=1 -v $PWD:/src -v edge-lb-cargo:/usr/local/cargo/registry -w /src edge-lb-build:bookworm"
make check
cargo fmt --all --check
git diff --check
make release
shasum -a 256 target/x86_64-unknown-linux-gnu/release/edge-lb
```

## 重载边界

新增 `linux/redirect/kernel_network_tests/reload.rs`，复用私有 namespace/VXLAN 拓扑：

- 静默恢复用例：完成 TCP/UDP 收发，等待 200ms 排空测试中的 delayed ACK；导出两组
  双向 flow，卸载程序、删除夹具 pins、创建新对象，确认 flow map ID 改变且无旧状态。
- 回填原 flow 后，原 TCP 连接与 UDP socket 继续收发；新对象没有旧加速租约，旧对象的
  publication token 被拒绝。分别重新授权后，正向和回程的 submitted 增长。
- 将原 target slot 改为不同地址，已恢复会话仍访问原 endpoint，不随 slot 复用而迁移。
- 故障刻画用例：明确在 TC NAT 卸载后向仍是本机地址的 VIP 发送 TCP，连接被重置或关闭。
  这证明卸载窗口不保证连续服务，是已知限制的回归记录，不是期望产品行为。

最初未等待 delayed ACK 的恢复测试也出现 `ConnectionReset`。增加静默前置条件仅为
区分“状态回填正确性”和“切换窗口连续性”，**不是生产修复**，更不能给生产代码增加
固定 sleep 并声称无损。上述 flow 导出/回填直接操作测试 map，不覆盖磁盘 snapshot
编码、进程重启、生产自动准入、持续流量、双机 xSync 切换或服务器内核兼容性。

## 部署前四机核查

| 角色 | 主机 | 内网地址 | 服务状态 | HA 状态/健康 |
|---|---|---|---|---|
| gateway-a | VM-0-12-ubuntu | `192.168.0.12` | active/running | BACKUP；BFD up，xSync connected |
| gateway-b | VM-0-16-ubuntu | `192.168.0.16` | active/running | MASTER；BFD up，xSync connected |
| backend-a | VM-0-14-ubuntu | `192.168.0.14` | active/running | 两节点目标组中为 ok |
| backend-b | VM-0-13-ubuntu | `192.168.0.13` | active/running | 两节点目标组中为 ok |

四台均使用 `edge-lb.service`，ExecStart 为
`/usr/local/bin/edge-lb --config /etc/edge-lb/config.toml`。两台 Gateway 的 metrics
在内网 `:19090` 可读，现有 native/DSCP 已挂载，checksum error 为零；flow persistence
已启用，snapshot error 为零。目标组 `8080` 的两目标均 healthy，VIP 为 `192.168.0.6`。

部署前磁盘二进制 SHA-256：

| 角色 | SHA-256 |
|---|---|
| 两台 Gateway | `b472d5443a6f82e66a9987c9b635dbdeb00f9007087bbb0bb22a6545bd70286c` |
| 两台 Backend | `ee936602d977dcf63efb0e7b9bb5fa736722406a1340927fca0a70be1ceb1862` |

实际核查通过 SSH 执行 `hostname`、`systemctl show`、`sha256sum`，从 Gateway 内网地址
读取 `/metrics`，并访问既有 `/api/v1/ha/status` 和 `/api/v1/target-groups`。
API 凭据仅在服务器本地从 TOML 解析并用于请求，不输出或写入文档。
在线执行 `gateway show` 因 daemon 持有 SQLite process lock 被拒绝，未绕过锁；
改用运行中 daemon 的 API/metrics，不中断服务来运行诊断。

## 旧版本基线

从既有测试机 `192.168.0.10` 发起，持续 10 秒、并发 4、每 worker 间隔 10ms、
timeout 5000ms。TCP 每请求新连接，UDP 每请求新 socket，用于连通性而非压力极限：

```bash
ssh <test-host> '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 --protocol both --duration 10 --concurrency 4 --payload discover --expect private_ipv4 --timeout-ms 5000 --interval-ms 10 --udp-new-socket-per-request --out /tmp/edge-lb-patch-preflight-20260916.tsv'
```

| 协议 | 请求/成功 | 失败 | RPS | 源端口样本 | 平均 ms | p95 ms | p99 ms | 最大 ms |
|---|---|---|---|---|---|---|---|---|
| TCP | 3678/3678 | 0 | 367.8 | 3517 | 0.799 | 1.029 | 1.421 | 6.498 |
| UDP | 3821/3821 | 0 | 382.1 | 3687 | 0.386 | 0.498 | 0.707 | 10.259 |

TCP 两后端分别成功 1875/1803 次，UDP 分别 1972/1849 次，顺序为 `.13`/`.14`。
这些数据属于**升级前旧二进制**，不证明新版本 redirect 命中或性能收益。

## 实际滚动部署

用户确认继续后，按先 BACKUP、切流、原 MASTER、逐台 Backend 的顺序执行。
四台均先备份旧二进制、TOML 配置和 SQLite 在线备份，数据库 `quick_check` 通过。
备份目录为 `/var/lib/edge-lb-rollbacks/patch-20260916-443bb9db`，权限为 `0700`。
Backend 没有 sqlite3 命令，因此使用 Python 标准库 SQLite backup API；未安装额外工具。
候选文件为 `/tmp/edge-lb-443bb9db`，校验后同目录原子替换可执行文件，再重启 agent。

| 顺序 | 主机 | 新服务启动时间（UTC+8） | 最终角色/状态 | PID | NRestarts |
|---|---|---|---|---|---|
| 1 | gateway-a `.12` | 2026-09-16 15:18:28 | MASTER / active/running | 1461897 | 0 |
| 2 | gateway-b `.16` | 2026-09-16 15:24:27 | BACKUP / active/running | 1454175 | 0 |
| 3 | backend-a `.14` | 2026-09-16 15:26:31 | active/running，目标 ok | 563324 | 0 |
| 4 | backend-b `.13` | 2026-09-16 15:27:05 | active/running，目标 ok | 1132872 | 0 |

四台 `/proc/<PID>/exe` 的 SHA-256 均与构建表中的 `443bb9db...264dbf` 完全一致，
不是仅比较磁盘文件或 `0.1.8` 版本字符串。只重启 `edge-lb.service`，未操作
`/mnt/netdiscover` 的 nerdctl compose 测试服务、角色配置或主机安全策略。

`.12` 升级后直连测试 TCP 3665/3665、UDP 3819/3819 成功，然后通过既有
`POST /api/v1/ha/failover`，请求体 `{"gateway":"192.168.0.12"}` 发起切流。
日志显示 15:23:54 开始写入 active 选择，15:23:57 `.12` 完成 VIP 绑定和 GARP。
双方短暂出现 proxy snapshot HTTP 409，15:23:59 记录 replication recovered；最终
配置同步 `pending=false`、`last_error=null`，双方内容摘要一致。

`.16` 作为 BACKUP 重启期间 BFD 短暂 down，随后恢复，最终双侧 xSync connected。
两台 Backend 重启后均连接双网关，应用 `inet edge_lb_return` 和两条 gateway 回程路径。
监听 `tcp-udp-8080` 仍为 `consistent_hash`，两个目标 `.13`/`.14` 都参与实际响应。

实际执行的诊断/部署命令形式如下（主机名占位，避免暴露公网地址）：

```bash
ssh <role-host> 'sudo sh /tmp/edge-lb-rollout.sh backup'
scp target/x86_64-unknown-linux-gnu/release/edge-lb <role-host>:/tmp/edge-lb-443bb9db
ssh <role-host> 'sudo sh /tmp/edge-lb-rollout.sh activate'
ssh <gateway-b> 'sudo python3 /tmp/edge-lb-rollout-failover.py 192.168.0.12'
ssh <role-host> 'systemctl show edge-lb.service -p ActiveState -p SubState -p MainPID -p NRestarts'
ssh <role-host> 'sudo sha256sum /proc/<PID>/exe'
ssh <role-host> 'sudo journalctl -u edge-lb.service --no-pager -n 30'
ssh <gateway-a> 'sudo python3 /tmp/edge-lb-rollout-audit.py /api/v1/ha/status'
ssh <gateway-a> 'sudo python3 /tmp/edge-lb-rollout-audit.py /api/v1/target-groups'
ssh <gateway-a> 'sudo python3 /tmp/edge-lb-rollout-audit.py /api/v1/nodes/backends'
ssh <gateway-a> 'sudo python3 /tmp/edge-lb-rollout-audit.py /api/v1/listener-configs'
ssh <gateway-a> 'sudo python3 /tmp/edge-lb-rollout-audit.py /api/v1/ha/proxy-config-sync'
ssh <gateway-a> 'curl -fsS http://192.168.0.12:19090/metrics'
ssh <gateway-b> 'curl -fsS http://192.168.0.16:19090/metrics'
```

临时 rollout 脚本执行校验、备份、原子替换和 systemd 重启；audit/failover 脚本仅在
服务器本地读取 API token 并调用既有 API。这些是人工部署工具，不是生产网络代码的
外部命令依赖。回滚入口为 `sudo sh /tmp/edge-lb-rollout.sh rollback`，恢复该节点的
旧二进制并重启；本次未执行回滚。不要同时回滚双网关，也不要直接覆盖运行中的数据库。

## 切流测试与异常

```bash
ssh <test-host> '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 --protocol both --duration 60 --concurrency 4 --payload discover --expect private_ipv4 --timeout-ms 5000 --interval-ms 10 --udp-new-socket-per-request --out /tmp/edge-lb-patch-switchover-20260916.tsv'
```

此窗口覆盖 HA 切流和随后原 MASTER 的重启，尚未升级两个 Backend。

| 协议 | 总数 | 成功 | 失败 | RPS（工具输出） | 源端口样本 | 平均 ms | p95 ms | p99 ms | 最大 ms |
|---|---|---|---|---|---|---|---|---|---|
| TCP | 21605 | 21605 | 0 | 360.1 | 15771 | 1.025 | 1.072 | 1.507 | 1042.918 |
| UDP | 20921 | 20917 | 4 | 348.7 | 17425 | 1.385 | 0.515 | 0.813 | 5203.232 |

4 次错误均为 UDP `timed out`。发现后暂停后端升级，检查 HA/同步和连续两轮稳态探测，
TCP 分别 3664/3655 次、UDP 分别 3820/3815 次全部成功后，才继续逐台升级 Backend。
这是恢复后的稳态证据，**不能抵消切流期间失败，也没有证明旧长连接跨切流保持不变**。

本轮现有测试机 ha-bench 的终端摘要正常，但指定的 `/tmp` TSV 文件读回为 0 字节；
尝试 `/dev/shm` 后也未取得可归档文件。当时原因未查明（后续已定位 `/tmp` 配额错误，见下节），不能把 `raw_results=...` 输出
当成成功保存原始记录。本报告表格来自实际终端摘要，无法将 4 次超时精确关联到具体
切流/重启事件，也不据此断言优化代码引入了回归或旧版本同样会丢包。

## 部署后三轮稳态测试

从 `.10` 测试机连续执行以下命令三次，无切流或重启；每协议 4 worker、持续 10 秒，
每 worker 请求间隔 10ms，超时 5000ms。TCP 新连接、UDP 新 socket：

```bash
ssh <test-host> '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 --protocol both --duration 10 --concurrency 4 --payload discover --expect private_ipv4 --timeout-ms 5000 --interval-ms 10 --udp-new-socket-per-request'
```

| 轮次 | 协议 | 成功/总数 | 失败 | RPS | 源端口样本 | 平均 ms | p95 ms | p99 ms | 最大 ms |
|---|---|---|---|---|---|---|---|---|---|
| 1 | TCP | 3665/3665 | 0 | 366.5 | 3609 | 0.846 | 1.093 | 1.341 | 10.014 |
| 1 | UDP | 3820/3820 | 0 | 382.0 | 3703 | 0.393 | 0.534 | 0.735 | 3.293 |
| 2 | TCP | 3660/3660 | 0 | 366.0 | 3660 | 0.859 | 1.148 | 1.780 | 13.888 |
| 2 | UDP | 3811/3811 | 0 | 381.1 | 3692 | 0.409 | 0.568 | 1.352 | 9.342 |
| 3 | TCP | 3668/3668 | 0 | 366.8 | 3451 | 0.831 | 1.086 | 1.368 | 5.396 |
| 3 | UDP | 3825/3825 | 0 | 382.5 | 3682 | 0.394 | 0.520 | 0.794 | 8.962 |

合计 TCP 10,993 次、UDP 11,456 次，全部成功。每轮两后端都返回有效 `private_ipv4`。
四并发且每请求间隔 10ms 限制了负载，这些 RPS **不是最大 CPS/吞吐能力**；
旧版本基线也未使用相同 MASTER，因此不能用两张表的小幅延迟差异推断性能增益。

最终将上述命令的 `--target` 改为 `192.168.0.16` 验证升级后的备网关，TCP 3676/3676、
UDP 3824/3824 全部成功，平均延迟分别 0.819/0.387ms，p99 为 1.326/0.756ms。

## 快路径准入与验收边界

两台 Gateway 执行以下只读检查，三项结果均为 `2`，没有修改值：

```bash
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.eth0.rp_filter net.ipv4.conf.edge-hub.rp_filter
```

日志均出现 `rp_filter requires kernel path; redirect cache invalidated`。
当前安全准入要求相关 rp_filter 为 0，因此不发布 redirect 租约。下表是升级后运行期间
累计快照，两个采样点不同时，不用作单次压测增量：

| 指标 | gateway-a | gateway-b |
|---|---|---|
| native / DSCP attached | 1 / 1 | 1 / 1 |
| 正向 / 回程 redirect stats available | 1 / 1 | 1 / 1 |
| 正向 / 回程 redirect submitted | 0 / 0 | 0 / 0 |
| 正向 fallback `route_miss` | 325129 | 249 |
| 回程 fallback `policy` | 233800 | 201 |
| checksum / 正向 mutation / 回程 mutation error | 0 / 0 / 0 | 0 / 0 / 0 |
| native target miss / return miss | 0 / 0 | 0 / 1 |
| snapshot / restore error | 0 / 0 | 0 / 0 |

备机出现累计 1 次 return miss，当前证据不足以归因；不能笼统描述为所有错误计数为零。
`.12` 晋升时记录恢复 767 对 flow，另有 2 对因配置校验跳过；这是磁盘恢复路径实际执行
的证据，不等于所有存量会话连续性已经验证。

本轮确认新二进制、指标和保守回退能在四机运行，Backend 原生 nft 回程能完成真实业务。
P3 Backend fast path 尚未实现；P4 的生产自动准入、加速收益、持续旧连接与无损 HA
仍未完成。下一步先完善原始采样证据并定位切流超时，再在保留安全语义的前提下评估
rp_filter 准入方案。改变安全策略或架构必须先同步用户并取得同意，不通过关闭安全检查
制造 redirect 命中数据。

## 后续诊断：采样修复与 UDP 归属

### 采样根因及修复

继续核查发现测试机 `/tmp` 写入返回 `Disk quota exceeded (os error 122)`。
当时 `df -h` 显示 `/tmp` 总计 982M、可用 191M，inode 使用率仅 1%；总空闲空间
不能证明当前用户仍有写入配额。SCP 到 `/tmp` 同样失败且留下截断文件，尝试执行时
返回 `Exec format error`，没有成功启动；随后改传 `/home/ubuntu`，先校验 SHA-256
后才运行。没有删除用户文件或调整配额。

旧 ha-bench 对逐行写入和最终 flush 使用 `.ok()` 忽略错误。通过 `--out /dev/full`
复现：它仍发送 10 次请求、打印 `raw_results=/dev/full`，并以退出码 0 结束。
修复后的 `raw_output` 模块在发请求前写入并 flush 表头，运行期间锁存首个写入错误，
结束时检查 flush 和记录行数；失败返回非零且不打印成功结果路径。worker panic 也
不再被作为完整测试。保持原有 TSV 列语义，成功摘要新增 `raw_rows`。

本地 `cargo test -p ha-bench` 15 项通过，其中新增 7 项覆盖正常输出、表头失败、
中途失败锁存、最终 flush/write 失败和缺行；`cargo clippy -p ha-bench --all-targets -- -D warnings`
通过。Linux 构建使用 `make ha-bench`。修复版在测试机的 `/dev/full` 上立即退出 1，
在 `/tmp` 上立即报配额错误，不发送测试流量。

测试机已安装修复版 `/usr/local/bin/ha-bench`；旧版备份为
`/home/ubuntu/ha-bench-before-raw-output-fix`。新版摘要：

```text
8e1cf4980d88868a38df3db8cfee84f2401de3a3312f580a86fe9990d1bee1f3
```

本批没有重启四台 edge-lb、改变 HA 角色、清空 map、改写 return-path contract，
也没有修改 rp_filter。四机仍使用前述 `443bb9db...264dbf` 产物。

### 有原始记录的稳态验证

实际使用候选路径执行以下测试，通过后将同一摘要的文件安装到 `/usr/local/bin`：

```bash
ssh <test-host> '/home/ubuntu/ha-bench-raw-output-fix --target 192.168.0.6 --port 8080 --protocol both --duration 10 --concurrency 4 --payload discover --expect private_ipv4 --timeout-ms 5000 --interval-ms 10 --udp-new-socket-per-request --out /home/ubuntu/edge-lb-raw-verified-20260916.tsv'
ssh <test-host> 'wc -l /home/ubuntu/edge-lb-raw-verified-20260916.tsv'
scp <test-host>:/home/ubuntu/edge-lb-raw-verified-20260916.tsv /private/tmp/edge-lb-raw-verified-20260916.tsv
```

| 协议 | 成功/总数 | 失败 | RPS | 源端口样本 | 平均 ms | p95 ms | p99 ms | 最大 ms |
|---|---|---|---|---|---|---|---|---|
| TCP | 3665/3665 | 0 | 366.5 | 3613 | 0.828 | 1.074 | 1.429 | 9.059 |
| UDP | 3822/3822 | 0 | 382.2 | 3704 | 0.388 | 0.520 | 0.742 | 6.649 |

摘要 `raw_rows=7487`，远程文件 7488 行（含表头）。下载后用 CSV/TSV 解析器复核
协议计数、成功标记及不同源端口数量，与摘要完全一致；本地和远端 SHA-256 相同：

```text
befa56e7387852a78b21e934ae1cd1c2970473d3d31038107725a0b0e0089c08
```

这是新增稳态样本，不能补回之前丢失的切流原始数据；先前四次 UDP 超时仍保留为
未精确归因的失败记录。本批未重做线上切流，不将该结果记为 HA 或性能提升验收。

### 已证实的缺陷与待证假设

1. **已证实：Backend UDP 双归属。** 原生 namespace/VXLAN 测试复现同客户端 IP/端口
   先经 B、再经 A 访问同一 8080 服务，A 的回复仍去 B。两套学习 set 都命中，后面的
   OUTPUT 规则覆盖前面的源地址和 mark。补充测试见
   `edge-lb/src/linux/nft/kernel_tests/mod.rs`。这不是只加服务端口就能解决的问题。
2. **待证：HA 就绪时序。** `api/handlers/ha.rs::peer_activate` 写入 active 选择后
   直接 reconcile VIP；`provider/native/ha.rs::switch_active_gateway` 接受对端 2xx
   后继续降级本地，没有等待 datapath generation/flow 状态的就绪确认。另一方面，
   `provider/native/model.rs::effective_vip_ips` 已为备机安装 shared VIP 的监听，不能
   简化为“备机没有 VIP map、等待 3 秒才有转发”。是否存在相关竞态需采样证明。
3. **未证实：上次四次超时的单一根因。** 尚无请求级证据把超时对应到 GARP 收敛、
   双归属误投、旧网关重启或其他环节，不能把隔离测试复现等同于线上故障定位完成。

后续先在隔离测试中覆盖相同 UDP socket 经网关切换的回程、请求延迟/乱序和旧学习
超时；线上受控切流需确认后执行，并分别记录“只切流”和“只重启备机”，不能再混在
一个窗口里推断原因。新的采样写到有配额的目录，保留请求开始/完成时间、源端口、
HA 日志及双方回程计数。涉及就绪确认协议或回程关联语义的实现，先提交方案取得同意。

本批最终验证：单线程全量 309 项 edge-lb 单元测试和 1 项 HA 集成测试通过，
ha-bench 15 项测试通过；`make check`、`cargo fmt --all --check`、`git diff --check`
及 ha-bench 的 clippy 检查均通过。未提交、推送或合并分支。

## 第十五批后续

已在隔离测试中验证规则顺序、30 秒学习过期及显式源地址覆盖问题，并按既定契约
修复 HA 切换触发完整数据面 reconcile 的两个入口。全量 313 项单元测试及 1 项 HA
集成测试通过；本批未部署或切流，四机摘要不变，原四次超时未完成线上归因。
详细证据和 UDP 待确认范围见 [UDP 回程归属诊断](udp-return-ownership-diagnosis.md)。
