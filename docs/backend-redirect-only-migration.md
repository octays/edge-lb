# Backend Redirect-only 迁移说明

本文记录从旧 backend nftables/policy-route 回程切换到 Redirect-only 回程时的人工
迁移边界。运行时代码只管理当前版本创建的 Redirect TC 程序和 pinned map，不负责清理
旧版本留下的 nftables table、policy rule、route table 或 `/etc/iproute2/rt_tables`
条目。

## 原则

- backend 最终语义只有 Redirect-only，不提供 `return_engine` 配置，也不保留
  nftables/Redirect 双模式。
- 新版本 daemon 不主动删除旧 nftables/policy-route 状态，避免把历史迁移动作混入
  正常收敛路径。
- 旧资源必须作为一次性迁移操作处理；迁移前确认没有旧版本 edge-lb 进程仍在运行。
- 迁移操作只针对本机旧 edge-lb return-path 资源，不处理外部业务防火墙、系统路由或
  其他应用创建的规则。

## 检查项

在 backend 节点升级后，先确认新版本已挂载 Redirect 程序：

```bash
edge-lb backend show
tc filter show dev <underlay_dev> ingress
tc filter show dev <underlay_dev> egress
bpftool map dump pinned /sys/fs/bpf/edge-lb/backend-redirect/BACKEND_RETURN_DSCP
```

旧版本可能仍留下以下状态。它们不是新版本 runtime 的管理对象：

```bash
nft list table inet edge_lb_return
ip rule show
ip route show table <backend_route_table>
grep -E 'edge_lb|<backend_route_table>' /etc/iproute2/rt_tables
```

## 人工迁移窗口

建议在维护窗口执行旧状态清理：

1. 停止旧版本 edge-lb，确认新版本包和配置已就绪。
2. 启动新版本 backend，确认 Redirect 程序、VXLAN peer 和 DSCP contract 正常。
3. 确认业务回程已经通过 Redirect 验证。
4. 仅在确认旧 nftables/policy-route 不再需要后，人工删除旧资源。

仓库提供了手工迁移脚本，默认 dry-run，必须显式传入 `--apply` 才会执行删除：

```bash
# backend 节点：清理旧 TC 回程 filter 和旧 nftables return-path table
deploy/cleanup-legacy-datapath.sh --role backend
deploy/cleanup-legacy-datapath.sh --role backend --apply

# gateway 节点：清理 edge-lb-owned TC filter
deploy/cleanup-legacy-datapath.sh --role gateway
deploy/cleanup-legacy-datapath.sh --role gateway --apply
```

脚本默认要求 `edge-lb.service` 已停止，避免误删正在运行版本的 TC 程序。若维护窗口中
确认需要在服务运行时操作，才使用 `--force-active`。

也可以按现场配置手工执行。示例命令必须替换表名、rule priority 和 route table：

```bash
nft delete table inet edge_lb_return
ip rule delete pref <backend_rule_priority>
ip route flush table <backend_route_table>
```

注意：上面的 policy route 示例不在脚本自动范围内。脚本只处理旧 TC 和 backend
nftables table；policy rule、route table 和 `/etc/iproute2/rt_tables` 仍需人工确认后
单独处理。

`/etc/iproute2/rt_tables` 是系统共享文件，不建议由 edge-lb 自动改写。若确需删除旧
表名，请人工编辑并保留其他业务条目。

## 验证

迁移完成后再次检查：

```bash
edge-lb backend show
tc filter show dev <underlay_dev> ingress
tc filter show dev <underlay_dev> egress
nft list table inet edge_lb_return
ip rule show
```

期望结果：

- Redirect ingress/egress TC 程序存在。
- DSCP contract 指向 `edge-return` VXLAN 设备的 ifindex 和 gateway overlay 邻居 MAC。
- 旧 `inet edge_lb_return` 表不存在，或已确认是有意保留的历史状态。
- 旧 fwmark policy rule 不再参与回程路径，或已确认是有意保留的历史状态。
- UDP/TCP 回程仍返回请求所属 gateway，业务源 IP 不被改写。
