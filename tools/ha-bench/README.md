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
