# ha-bench

`ha-bench` is a small TCP/UDP pressure client for edge-lb HA validation. It
measures socket round-trip time directly and treats a request as successful only
when the response body contains the expected text.

Build a Linux amd64 binary from macOS:

```bash
make ha-bench
```

Install on a load generator:

```bash
scp target/x86_64-unknown-linux-gnu/release/ha-bench ubuntu@<load-generator>:/tmp/ha-bench
ssh ubuntu@<load-generator> 'sudo install -m 0755 /tmp/ha-bench /usr/local/bin/ha-bench'
```

Run a TCP+UDP VIP pressure test:

```bash
/usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol both \
  --duration 30 \
  --concurrency 16 \
  --payload discover \
  --timeout-ms 1000 \
  --out /tmp/edge-lb-ha-rust.tsv
```

Run a paced test closer to manual `nc -N` validation:

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

Run a persistent TCP test. Each worker keeps one TCP connection open and sends
requests sequentially over that connection:

```bash
/usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol tcp \
  --duration 30 \
  --concurrency 16 \
  --payload discover \
  --timeout-ms 1000 \
  --tcp-reuse-conn
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

Check UDP distribution with many source port samples:

```bash
/usr/local/bin/ha-bench \
  --target 192.168.0.6 \
  --port 8080 \
  --protocol udp \
  --duration 60 \
  --concurrency 64 \
  --payload discover \
  --timeout-ms 5000 \
  --udp-new-socket-per-request
```

TCP opens a new connection per request by default, sends the payload, and then
shuts down the write half of the socket, matching `nc -N`. Use
`--tcp-reuse-conn` when the backend protocol supports multiple request/response
rounds on one connection. If the peer closes a reused connection, `ha-bench`
reconnects and retries that request once. `--udp-source-port` requires
`--concurrency 1`; one UDP source port cannot be bound by multiple workers at
the same time.

UDP reuses one socket per worker by default. That mode is useful for testing
fixed five-tuple throughput and typical long-lived UDP clients. Use
`--udp-new-socket-per-request` when validating load-balancing distribution for
algorithms such as `consistent_hash`; each request binds a fresh ephemeral
source port, so the source port sample count grows with request count instead
of worker count. Direct backend tests are useful only for isolation. HA
conclusions should be based on requests to the VIP.

## Raw Result Integrity

`--out` writes TSV columns `timestamp_ms`, `protocol`, `source_port`, `ok`,
`latency_us`, `backend`, and `error`. `timestamp_ms` is the request start time
(Unix milliseconds); `ok` is 0 or 1. A timeout's completion is later than its
timestamp by approximately `latency_us`.

The header is flushed before workers send traffic. A header write/flush error
exits with status 1 immediately. Later write errors are retained while workers
finish; final write/flush errors or a mismatch between recorded rows and total
requests also exit with status 1, without printing a successful `raw_results`
summary. Worker panics invalidate the run as well. Buffered output is not a
crash-durable audit log and is not flushed on every request.

After a successful output check, the summary includes `raw_rows` (excluding the
header). Verify the downloaded TSV row count against this value before using
it for HA event correlation. Exit status 0 alone does not mean all network
requests succeeded: inspect each protocol's `fail` count too.

Use a destination with available user quota as well as free space. In the
2026-09-16 test environment, `/tmp` had free space but writes failed with
`Disk quota exceeded`; `/home/ubuntu` successfully stored the samples. The old
client ignored write errors and printed `raw_results` even for `/dev/full`.
An empty old TSV cannot be recovered from its summary.
