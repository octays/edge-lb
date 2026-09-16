# Edge LB

**English** | [简体中文](README.zh-CN.md)

A layer-4 load-balancing agent for cloud VPCs. edge-lb uses its built-in native
DNAT/SNAT datapath while preserving the **real client IP** seen by backends.

## The problem it solves

A cloud VPC only forwards traffic whose destination MAC/IP belongs to the
VM. When a gateway performs default DNAT and preserves the client source IP,
the backend's replies are destined to the public client and cannot be routed
back through the gateway inside the VPC. Asymmetric routing breaks the
connection, while SNAT-based modes lose the real client IP.

Edge LB's design:

```mermaid
flowchart TD
    client["Client"]
    vip["Gateway public VIP:port"]
    dnat["edge-lb native default<br/>DNAT + DSCP mark"]
    backend["Backend host:port"]
    app["App<br/>host/container DNAT"]
    reply["Reply direction of marked conn<br/>nft fwmark + policy route"]
    vxlan["VXLAN return tunnel<br/>VNI 100 / UDP 4789"]
    revnat["Gateway native reverse NAT"]

    client --> vip --> dnat --> backend --> app
    app --> reply --> vxlan --> revnat --> client
```

DNAT uses the configured business IP, never an implicit overlay replacement.
Replies to connections classified by a subscribed DSCP use the VXLAN return path.
DSCP is not authentication: direct traffic carrying the same codepoint is also
classified, so reserve these codepoints at the network boundary.
See [address semantics and coordinated upgrade requirements](docs/dnat-service-address-fix.md).

## Quick start

On x86_64 Linux (or use the Docker-based targets in the `Makefile` from
any host):

```bash
make ebpf release      # eBPF object + x86_64 release binary
make ui                # optional: management UI (bun + rolldown-vite)
BIN=target/x86_64-unknown-linux-gnu/release/edge-lb

# The role is written to /etc/edge-lb/config.toml:
sudo $BIN install backend

# Optional bootstrap overrides are written together with the role:
# --node-name, --underlay-ip, --public-ip, --underlay-dev,
# --vni, --vxlan-port and --dscp. Use --force to replace an existing config.

edge-lb verify         # both paths + eBPF counters
```

Packaging lives in `scripts/package.sh`, `scripts/deb.sh`, and
`deploy/container.Dockerfile`.

## Debian package installation

Install the role-specific Debian package, write the systemd service
configuration, then start the daemon:

```bash
sudo dpkg -i edge-lb-gateway_<version>_<arch>.deb
sudo edge-lb install service --role gateway
sudo systemctl enable edge-lb
sudo systemctl start edge-lb
sudo journalctl -u edge-lb.service -f
```

For backend nodes, use the backend package and role:

```bash
sudo dpkg -i edge-lb-backend_<version>_<arch>.deb
sudo edge-lb install service --role backend
sudo systemctl enable edge-lb
sudo systemctl start edge-lb
sudo journalctl -u edge-lb.service -f
```

## Commands

```bash
edge-lb --config /etc/edge-lb/config.toml # run the configured node_role
edge-lb ui serve                         # management API/UI (default
                                         # 127.0.0.1:18080; also started by the
                                         # gateway daemon)
edge-lb verify                           # VIP path + direct path + eBPF stats
edge-lb config validate|init             # validate / write annotated,
                                         # role-aware config templates
edge-lb install [gateway|backend]        # install systemd service
edge-lb uninstall service                # remove systemd service
```

Every default is overridable on the CLI (`--help` for the full list).

## Configuration

`/etc/edge-lb/config.toml`, organized by role. The deploy templates are split
by role and keep local identity at the top level, with gateway-only control/API
settings under `[gateway.*]`, and backend-only subscription/return-path
settings under `[backend.*]`:

```toml
node_role = "gateway"        # gateway | backend
[discovery]                  # auto discovery for local IPs and route device
[gateway.ha]                 # gateway failover
[gateway.xds]                # xDS-like control plane listener
[gateway.network]            # overlay/VXLAN/DSCP source of truth
[gateway.api]                # management UI/API
[gateway.metrics]            # gateway-only Prometheus metrics
[backend.xds]                # backend subscribes to gateway xDS
[backend.return_path]        # backend nft/route return-path settings
```

Architecture: **[docs/architecture.md](docs/architecture.md)** (Chinese).
Full configuration guide: **[docs/config.md](docs/config.md)** (Chinese);
deploy templates are split by role: `deploy/config.gateway.example.toml` and
`deploy/config.backend.example.toml`. Listener configuration is managed through
the gateway UI/API and persisted under `state_dir`, not in TOML.

## Management UI / API

`edge-lb ui serve` (or the gateway daemon, which starts it automatically):
node status, listener configuration, target groups, automatic target groups,
notifications, manual failover, apply, and cleanup. Destructive actions always
show a summary of what will change before running.

Standalone `ui serve` also delivers pending HA configuration snapshots for the
gateway role, but does not start BFD or the datapath. It must own its `state_dir`
exclusively; do not run it alongside a gateway daemon using the same database.

```text
GET     /api/v1/status
GET     /api/v1/nodes/gateways
GET     /api/v1/nodes/backends          (runtime xDS registrations)
GET/POST/PUT/DELETE /api/v1/listener-configs[/{name}]
GET/POST/PUT/DELETE /api/v1/target-groups[/{name}]
GET/POST/PUT/DELETE /api/v1/automations[/{name}]
GET/POST /api/v1/notifications
GET/DELETE /api/v1/notifications/{id}
POST    /api/v1/notifications/{id}/test
GET/PUT /api/v1/ha/config
GET     /api/v1/ha/status
POST    /api/v1/ha/failover
POST    /api/v1/operations/{apply|cleanup}
```

The server binds `127.0.0.1:18080` by default. Listening on a
non-loopback address requires `gateway.api.auth_token` (Bearer). API calls
must also match `gateway.api.trusted_source_cidrs`; an empty list derives the
local underlay subnet automatically.

Gateway metrics are optional and use an independent port:

```toml
[gateway.metrics]
enabled = true
listen = "0.0.0.0:19090"
trusted_source_cidrs = ["192.168.0.0/24"]
```

The metrics endpoint serves `GET /metrics`, is not part of `/api/v1`, and uses
CIDR allowlist only. See **[docs/metrics.md](docs/metrics.md)** for the full
metric list.

## Performance snapshot

The 2026-09-11 high-concurrency lab run used VIP `192.168.0.6:8080` and omits
public addresses from the documentation. Full details are in
**[docs/high-concurrency-test-report-2026-09-11.md](docs/high-concurrency-test-report-2026-09-11.md)**.

| Role | Host | Lab address | Runtime | CPU / memory | CPU frequency sample |
| --- | --- | --- | --- | --- | --- |
| gateway-a | VM-0-12-ubuntu | `192.168.0.12` | `edge-lb 0.1.8`, active | 2 vCPU AMD EPYC 7K62, 3.6 GiB | 2595.1 MHz |
| gateway-b | VM-0-16-ubuntu | `192.168.0.16` | `edge-lb 0.1.8`, active | 2 vCPU AMD EPYC 7K62, 3.6 GiB | 2595.1 MHz |
| backend-a | VM-0-14-ubuntu | `192.168.0.14` | `edge-lb 0.1.8`, active | 1 vCPU AMD EPYC 7K62, 0.9 GiB | 2595.1 MHz |
| backend-b | VM-0-13-ubuntu | `192.168.0.13` | `edge-lb 0.1.8`, active | 2 vCPU General Processors, 1.9 GiB | 2595.1 MHz |
| client | VM-0-10-ubuntu | `192.168.0.10` | `ha-bench` | 2 vCPU General Processors, 1.9 GiB | 2595.1 MHz |

| Scenario | TCP success CPS | TCP success rate | UDP throughput | UDP success rate |
| --- | ---: | ---: | ---: | ---: |
| `concurrency=16`, `timeout=1000ms` | 8734.2 | 100.00% | 19502.2 req/s | 100.00% |
| `concurrency=64`, `timeout=1000ms` | 8906.9 | 99.98% | 31204.1 req/s | 99.97% |
| `concurrency=64`, `timeout=3000ms` | 8928.1 | 100.00% | 30856.4 req/s | 99.99% |
| `concurrency=64`, `timeout=5000ms` | 8839.3 | 100.00% | 31658.8 req/s | 99.99% |
| `consistent_hash`, `concurrency=64`, `timeout=5000ms` | 8934.3 | 100.00% | 30959.5 req/s | 100.00% |
| `consistent_hash` UDP source-port sample, `concurrency=64`, `timeout=5000ms` | - | - | 63951.5 req/s | 100.00% |

The TCP test mode was `new-per-request`, so TCP RPS is equivalent to CPS for
this run. UDP used reused worker sockets by default, so it is reported as
request throughput rather than CPS. Timeout counts dropped as the client timeout
grew. The final 2026-09-15 `consistent_hash` rerun reached 0 TCP failures and
54 UDP timeout failures at `concurrency=64` with 5s timeout. The UDP
source-port sample mode reached 0 failures. Its active gateway reported no
target misses, return misses, checksum errors, bucket misses, unusable buckets,
or consistent-hash fallback.

`consistent_hash` UDP distribution rerun:

| UDP mode | Total | OK | Fail | RPS | Source ports | Backend distribution |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `reuse-per-worker` | 1857572 | 1857518 | 54 | 30959.5 | 64 | `82.8% / 17.2%` |
| `new-per-request` | 3837088 | 3837088 | 0 | 63951.5 | 55536 | `51.0% / 49.0%` |

## Repository layout

```text
edge-lb/          user-space agent (CLI / daemon / HTTP API / systemd install)
edge-lb-ebpf/     DSCP marker and native datapath eBPF (Rust + Aya)
edge-lb-common/   shared types
ui/               Vue 3 + TypeScript + rolldown-vite panel (built with bun)
deploy/           systemd units, deploy/install scripts, example configs
docs/             current architecture, configuration, API and verification docs
```

## Building

- The user-space crate depends on aya, which only compiles on Linux:
  `make check / clippy / test` wrap everything in a Docker container
  (works on Apple Silicon).
- The eBPF object needs `nightly-2025-12-01` and `bpf-linker` v0.11.0:
  install the prebuilt `bpf-linker` release, then run `make ebpf`.
- The frontend uses bun: `make ui`.
- Tarballs: `make package`; role-specific Debian packages:
  `make deb` creates `edge-lb-gateway_<version>_<arch>.deb` and
  `edge-lb-backend_<version>_<arch>.deb`; local container image:
  `make container-image`. Multi-platform image push:
  `make container-image-push`.

## Caveats

- Failover is Active/Standby: switching guarantees recovery of **new**
  connections; existing connections break. Moving the public entry point
  (EIP binding) is outside the agent's scope.
- The native datapath currently targets IPv4 TCP/UDP default DNAT first.
  Other NAT/proxy modes are intentionally outside the first working version.
