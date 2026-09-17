# HA Pressure Test Report

Report version: v1

Test date: 2026-09-07

## Scope

This report records the HA pressure test results for the native edge-lb
active-backup deployment. The test sends TCP and UDP traffic from the load
generator to the HA private VIP.

The original manual validation commands were:

```bash
(printf 'discover\n'; sleep 1) | nc -v -w 1 192.168.0.6 8080
(printf 'discover\n'; sleep 1) | nc -uv -w 1 192.168.0.6 8080
```

The shell scripts treat a request as successful only when the response body
matches the backend discovery JSON. This avoids counting UDP `nc` connection
messages as datapath success.

The Rust client `ha-bench` is the preferred tool for latency and concurrency
testing. It measures socket round-trip time directly. TCP sends the payload and
then shuts down the write half of the socket, matching `nc -N`. UDP reuses one
socket per worker by default, matching normal long-lived UDP service behavior.

## Environment

| Role | Host label | Node |
| --- | --- | --- |
| Gateway | gateway-a | VM-0-12-ubuntu |
| Gateway | gateway-b | VM-0-16-ubuntu |
| Backend | backend-a | VM-0-14-ubuntu |
| Backend | backend-b | VM-0-13-ubuntu |
| Load generator | load-generator | ubuntu |

Runtime state after the test:

| Item | Result |
| --- | --- |
| edge-lb version | 0.1.6 on all four edge-lb nodes |
| HA state after test | VM-0-12-ubuntu MASTER, VM-0-16-ubuntu BACKUP |
| BFD | up |
| xSync | connected |
| VIP binding | 192.168.0.6/32 bound on MASTER loopback |
| Listener | tcp+udp/8080 |
| Target group | tcp-udp-8080 |
| Healthy backends | 192.168.0.13, 192.168.0.14 |

## Test Tools

Tools added:

- `scripts/edge-lb-ha-pressure.sh`: runs TCP/UDP pressure against a VIP and
  writes raw TSV plus summary data.
- `scripts/edge-lb-ha-failover-pressure.sh`: triggers HA failover during a
  pressure run and summarizes before, during, and after phases.
- `ha-bench`: Rust pressure client that records true socket RTT, source port
  samples, and backend distribution.

Build the Rust client:

```bash
make ha-bench
scp target/x86_64-unknown-linux-gnu/release/ha-bench ubuntu@<load-generator>:/tmp/ha-bench
```

Run a TCP+UDP VIP pressure test:

```bash
/usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol both \
  --duration 30 \
  --concurrency 8 \
  --payload discover \
  --timeout-ms 1000 \
  --out /tmp/edge-lb-ha-rust-bench.tsv
```

Run a paced test closer to manual `nc -N` checks:

```bash
/usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol both \
  --duration 30 \
  --concurrency 8 \
  --payload discover \
  --timeout-ms 1000 \
  --interval-ms 10
```

Check hash stickiness with a fixed UDP source port:

```bash
/usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol udp \
  --duration 10 \
  --concurrency 1 \
  --payload discover \
  --udp-source-port 12345
```

`--udp-source-port` requires `--concurrency 1`, because the same local UDP port
cannot be bound by multiple workers. Without `--udp-source-port`, each UDP
worker reuses one ephemeral UDP socket by default. Use
`--udp-new-socket-per-request` when explicitly testing flow creation, cleanup
pressure, or hash distribution across many UDP source ports. The summary prints
the number of unique source ports as `source_ports`, and raw TSV output includes
a `source_port` column.

## Results

### Rust Client Baseline

Command:

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

| Protocol | Total | OK | Fail | Success Rate | RPS | Avg RTT | P50 | P95 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP | 30581 | 30386 | 195 | 99.36% | 1019.4 | 7.994 ms | 1.176 ms | 2.562 ms | 4.735 ms |
| UDP | 273385 | 273358 | 27 | 99.99% | 9112.8 | 0.879 ms | 0.802 ms | 1.501 ms | 2.270 ms |

Backend distribution:

| Protocol | Backend | OK |
| --- | --- | ---: |
| TCP | 192.168.0.13 | 15307 |
| TCP | 192.168.0.14 | 15079 |
| UDP | 192.168.0.13 | 146679 |
| UDP | 192.168.0.14 | 126679 |

Failure types:

| Protocol | Error | Count |
| --- | --- | ---: |
| TCP | timed out | 195 |
| UDP | timed out | 27 |

Normal requests complete in the millisecond range. TCP P99 was not pulled into
the one-second timeout bucket; UDP P99 was about 2.27 ms. This confirms that
the one-second latency seen in the shell validation script came from the command
shape, not from normal edge-lb forwarding latency.

`ha-bench` defaults to reusing UDP sockets, which matches typical UDP services
that keep one socket open. Use `--udp-new-socket-per-request` only when the goal
is to stress flow creation and expiration.

### Rust Client Concurrency Sweep

Gateway size: 2C4G.

Target: `192.168.0.6:8080`.

Per-run duration: 30 seconds.

Payload: `discover\n`.

Timeout: 1000 ms.

| Concurrency/Protocol | Total | OK | Fail | Success Rate | RPS | P50 | P95 | P99 | Main Error |
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

Findings:

1. With UDP socket reuse, UDP capacity is healthy. At 8-32 concurrency, it holds
   around 9k-10k rps with 99.9%+ success rate and P99 in the 2-6 ms range.
2. TCP is a high-rate short-connection test. As concurrency increases, failures
   are mainly 1000 ms timeout cases, which pull P99 into the timeout bucket.
3. Gateway process load was low after the test: VM-0-12-ubuntu `edge-lb` was
   about 3.8% CPU and 89 MB RSS; VM-0-16-ubuntu was about 1.5% CPU and 46 MB
   RSS. The timeout pattern does not look like edge-lb user-space CPU
   saturation.

### Rust Client Protocol Isolation

TCP-only and UDP-only runs were executed to rule out cross-protocol pressure.

| Protocol/Concurrency | Total | OK | Fail | Success Rate | RPS | P50 | P95 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP/8 | 36615 | 36411 | 204 | 99.44% | 1220.5 | 0.782 ms | 1.457 ms | 2.137 ms |
| TCP/32 | 41329 | 40520 | 809 | 98.04% | 1377.6 | 0.777 ms | 1.547 ms | 1000.421 ms |
| UDP/8 | 354509 | 354509 | 0 | 100.00% | 11817.0 | 0.611 ms | 0.953 ms | 1.783 ms |
| UDP/32 | 366291 | 366291 | 0 | 100.00% | 12209.7 | 2.559 ms | 3.404 ms | 4.754 ms |

UDP-only had no packet loss at 8 and 32 concurrency. TCP-only still had a small
timeout rate, so future TCP tuning should focus on SYN/SYN-ACK behavior,
backend accept backlog, flow/conntrack capacity, and client-side connection
recycling.

### Retest After System Tuning

Runtime and persistent tuning was applied to the load generator, both gateways,
and both backend nodes.

Load generator:

- `net.ipv4.ip_local_port_range = 10000 65535`
- `net.ipv4.tcp_tw_reuse = 1`
- `net.ipv4.tcp_fin_timeout = 15`
- `net.ipv4.tcp_syn_retries = 3`
- `net.core.somaxconn = 65535`
- `net.core.netdev_max_backlog = 250000`
- `net.core.rmem_max = 134217728`
- `net.core.wmem_max = 134217728`
- `net.ipv4.udp_mem = 262144 524288 1048576`
- `nofile` persisted in `/etc/security/limits.d/99-edge-lb-bench.conf`; the
  retest shell used `524288`

Gateways:

- `net.ipv4.ip_forward = 1`
- `net.core.somaxconn = 65535`
- `net.core.netdev_max_backlog = 250000`
- `net.core.rmem_max = 134217728`
- `net.core.wmem_max = 134217728`
- `net.ipv4.tcp_max_syn_backlog = 65535`
- `net.ipv4.tcp_fin_timeout = 15`

Backends:

- `net.core.somaxconn = 65535`
- `net.core.netdev_max_backlog = 250000`
- `net.core.rmem_max = 134217728`
- `net.core.wmem_max = 134217728`
- `net.ipv4.tcp_max_syn_backlog = 65535`
- `net.ipv4.tcp_fin_timeout = 15`
- `net.netfilter.nf_conntrack_max = 262144`

Follow-up implementation: gateway and backend startup now applies these
production floors automatically where the kernel exposes the sysctl. Existing
higher values are preserved, unavailable conntrack sysctls are skipped, and
`ip_forward=1` remains a required datapath prerequisite.

Retest results:

| Scenario | Total | OK | Fail | Success Rate | RPS | P50 | P95 | P99 | Main Error |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| both 8/TCP | 104366 | 104329 | 37 | 99.96% | 3478.9 | 1.606 ms | 3.030 ms | 4.282 ms | timed out |
| both 8/UDP | 172029 | 172029 | 0 | 100.00% | 5734.3 | 1.272 ms | 2.435 ms | 3.635 ms | - |
| TCP-only 32 | 177674 | 177079 | 595 | 99.67% | 5922.5 | 1.192 ms | 2.188 ms | 4.743 ms | timed out |
| UDP-only 32 | 361683 | 361683 | 0 | 100.00% | 12056.1 | 2.418 ms | 3.241 ms | 5.762 ms | - |

After tuning, TCP short-connection success rate and throughput improved
substantially. UDP remained lossless in the 32-way isolated run at about 12k
rps. Further concurrency tests should capture load-generator CPU, client port
reuse, backend accept/backlog, and gateway NIC drop deltas at the same time.

### TCP Persistent Connection Pressure

After adding `ha-bench --tcp-reuse-conn`, each worker reuses one TCP connection
and sends sequential `discover` requests on it. This isolates short-connection
setup/teardown overhead and is closer to long-lived application protocols.

Command shape:

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

| Scenario | Total | OK | Fail | Success Rate | RPS | Avg | P50 | P95 | P99 | Max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP reuse 8 | 154131 | 154111 | 20 | 99.99% | 5137.7 | 1.564 ms | 1.129 ms | 2.078 ms | 2.934 ms | 1001.122 ms |
| TCP reuse 32 | 154353 | 153855 | 498 | 99.68% | 5145.1 | 6.273 ms | 1.203 ms | 2.470 ms | 202.825 ms | 1826.740 ms |
| TCP reuse 64 | 160633 | 159434 | 1199 | 99.25% | 5354.4 | 12.069 ms | 1.306 ms | 2.711 ms | 208.663 ms | 2002.035 ms |
| TCP reuse 128 | 165106 | 162382 | 2724 | 98.35% | 5503.5 | 23.546 ms | 1.437 ms | 3.698 ms | 1000.636 ms | 2004.614 ms |

Backend distribution remained roughly balanced:

| Scenario | Backend 192.168.0.13 | Backend 192.168.0.14 |
| --- | ---: | ---: |
| TCP reuse 8 | 77126 | 76985 |
| TCP reuse 32 | 77014 | 76841 |
| TCP reuse 64 | 80126 | 79308 |
| TCP reuse 128 | 82008 | 80374 |

Mixed pressure:

| Protocol | Total | OK | Fail | Success Rate | RPS | P50 | P95 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP | 95969 | 95462 | 507 | 99.47% | 3199.0 | 1.883 ms | 3.922 ms | 206.959 ms |
| UDP | 158252 | 158252 | 0 | 100.00% | 5275.1 | 5.927 ms | 8.985 ms | 14.789 ms |

Conclusion: TCP connection reuse reduces connection setup overhead. At 8-way
concurrency it reached about 5.1k rps with 99.99% success. Increasing
concurrency above that brought only limited RPS growth while timeout count and
P99 latency rose sharply. In this environment, the stable persistent-TCP
operating point is closer to concurrency 8; the observed ceiling is about 5.5k
rps, but that is not a stable production target.

### TCP Reuse C32 Server-Side Observation

To check whether the c32 P99 and timeouts were mainly caused by the load
generator, the same load was repeated while both gateways and both backends
captured `vmstat`, `ss -s`, and `ip -s link`:

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

The pressure result matched the previous c32 run:

| Scenario | Total | OK | Fail | Success Rate | RPS | P50 | P95 | P99 | Main Error |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| TCP reuse c32 observed | 154541 | 154052 | 489 | 99.68% | 5151.4 | 1.256 ms | 2.473 ms | 203.180 ms | timed out |

Server-side observations:

- Both gateways had CPU headroom, and `eth0`/`edge-hub` drop/error counters did
  not increase during the pressure window.
- Backend backend-b still had headroom, with CPU idle mostly around
  33% to 58%, and no link drop/error growth.
- Backend backend-a was close to CPU saturation during the pressure
  window. Most samples had single-digit idle, and system CPU reached 60%+.
  Historical `edge-return` drops did not continue increasing.
- The load generator's previous `vmstat` run still showed 60%+ idle and very
  low `TIME_WAIT`, so the c32 P99/timeouts should not be primarily attributed
  to load-generator CPU or client port exhaustion.

Current interpretation: the `tcp-reuse c32` tail latency bottleneck is more
likely on the backend service/host return-path side than on the load generator.
Further tuning should first separate backend application CPU, softirq,
edge-return processing, and application accept/read/write behavior.

### Fixed UDP Source Port Hash Check

Command:

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

| Protocol | Total | OK | Fail | Success Rate | RPS | P50 | P95 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| UDP | 19387 | 19385 | 2 | 99.99% | 1938.7 | 0.396 ms | 0.459 ms | 0.629 ms |

All successful requests landed on `192.168.0.13`, which matches five-tuple hash
stickiness: same client IP, source port, VIP, destination port, and protocol
select the same backend.

### Rust Client Failover A to B

Initial state: VM-0-12-ubuntu MASTER, VM-0-16-ubuntu BACKUP.

Failover target: VM-0-16-ubuntu.

Command:

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

| Protocol | Total | OK | Fail | Success Rate | RPS | P50 | P95 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP | 20722 | 19871 | 851 | 95.89% | 345.4 | 0.739 ms | 289.084 ms | 1000.646 ms |
| UDP | 15310 | 14366 | 944 | 93.83% | 255.2 | 0.434 ms | 1013.200 ms | 1023.389 ms |

Backend distribution:

| Protocol | Backend | OK |
| --- | --- | ---: |
| TCP | 192.168.0.13 | 10071 |
| TCP | 192.168.0.14 | 9800 |
| UDP | 192.168.0.13 | 7507 |
| UDP | 192.168.0.14 | 6859 |

After the failover API call, the state converged to VM-0-16-ubuntu MASTER and
the VIP was bound on VM-0-16-ubuntu loopback. The environment was switched back
to VM-0-12-ubuntu MASTER after the test.

### Shell Baseline

Command:

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

| Protocol | Total | OK | Fail | Success Rate | Avg Command Latency |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP | 112 | 112 | 0 | 100.00% | 1026.0 ms |
| UDP | 80 | 80 | 0 | 100.00% | 1529.3 ms |

The shell latency is command-level latency. It includes the intentional
`sleep 1` and `nc` behavior, so it should not be interpreted as datapath RTT.

### Shell Failover A to B

Initial state: VM-0-12-ubuntu MASTER, VM-0-16-ubuntu BACKUP.

Failover target: VM-0-16-ubuntu.

| Protocol | Total | OK | Fail | Success Rate | Avg Command Latency |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP | 567 | 567 | 0 | 100.00% | 1017.4 ms |
| UDP | 360 | 360 | 0 | 100.00% | 1626.2 ms |

### Shell Failover B to A

Initial state: VM-0-16-ubuntu MASTER, VM-0-12-ubuntu BACKUP.

Failover target: VM-0-12-ubuntu.

| Protocol | Total | OK | Fail | Success Rate | Avg Command Latency |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP | 566 | 565 | 1 | 99.82% | 1012.4 ms |
| UDP | 367 | 367 | 0 | 100.00% | 1596.1 ms |

The single TCP failure happened during the switchover window:

```text
2026-09-07T10:55:12+08:00 tcp 0 1016 - nc: connect to 192.168.0.6 port 8080 (tcp) timed out
```

Adjacent requests in the same second succeeded for both TCP and UDP, so this
was a short switchover-window miss rather than a persistent datapath failure.

## Conclusions

1. Manual-shape `nc` baseline validation showed 100% TCP and UDP forwarding
   success through the HA VIP.
2. Shell failover validation showed 100% TCP/UDP success for A to B. During B
   to A, UDP remained 100%; TCP had one switchover-window timeout, for 99.82%
   overall success.
3. Corrected Rust-client results show normal request RTT in the millisecond
   range. There is no fixed one-second forwarding latency.
4. With UDP socket reuse, UDP-only 8/32 concurrency reached 100% success; after
   system tuning, UDP-only 32 concurrency was about 12k rps.
5. After system tuning, TCP-only 32 concurrency improved to 99.67% success and
   about 5.9k rps. Remaining timeouts should be investigated through
   SYN/SYN-ACK, backend accept backlog, and client-side port recycling.
6. Both backend nodes participated in forwarding and the distribution was
   generally balanced.
7. After the test, HA state was restored to VM-0-12-ubuntu MASTER and
   VM-0-16-ubuntu BACKUP, with the VIP correctly bound on MASTER.

## Notes

- Direct backend tests are useful only for isolation. HA conclusions must be
  based on requests to the VIP, because direct backend tests bypass VIP,
  gateway DNAT/SNAT, VXLAN return path, failover, and xSync.
- A direct isolation run showed that `192.168.0.14:8080` can also timeout under
  8-way concurrency. Some HA pressure failures may therefore include backend
  service or backend network-path jitter.
- The `patch` branch now commits local HA role state only after the local
  promote/demote hook or L2 VIP action succeeds, and restores the local role if
  peer handoff fails after local demotion. If local takeover fails after peer
  demotion, it notifies the peer to restore the previous active gateway. Final
  two-node failover validation should still check `/api/v1/ha/status` and the
  node address list; lost peer confirmations, late operations, and real fault
  injection remain separate validation items.
- The first shell script used a seconds+nanoseconds integer timestamp. On the
  load generator this caused Bash arithmetic edge cases and misleading average
  latency. The script now computes millisecond timestamps with explicit base-10
  parsing.
- HA peer metadata version was fixed before this run. `/api/v1/ha/status` now
  refreshes display metadata from the live peer status, and both gateways show
  peer version `0.1.6`.

## Raw Data

Raw result files remain on the load generator:

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
- `/tmp/edge-lb-monitor-tcp-reuse-c32.txt` on each gateway/backend node
