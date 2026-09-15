# Edge LB Package

Install on a Linux systemd host:

```bash
sudo ./install.sh backend
sudo ./install.sh gateway

# Direct binary installation accepts a positional role plus node/IP/network
# bootstrap args.
```

Install Debian packages:

```bash
sudo apt install ./edge-lb-gateway_<version>_amd64.deb
sudo systemctl enable --now edge-lb@gateway

sudo apt install ./edge-lb-backend_<version>_amd64.deb
sudo systemctl enable --now edge-lb@backend
```

After installation:

```bash
sudo edge-lb config validate
sudo systemctl status edge-lb@gateway
sudo systemctl status edge-lb@backend
```

Edit `/etc/edge-lb/config.toml` before exposing the API outside localhost.
When `gateway.api.listen` is not loopback, set `gateway.api.auth_token`.
Gateway Prometheus metrics are disabled by default; enable `[gateway.metrics]`
only on gateway nodes and restrict `trusted_source_cidrs` to the monitoring
network.

The DSCP and native DNAT eBPF object is embedded into `edge-lb` during package
builds. Packages do not install or require a separate eBPF object file. Runtime
loads the embedded object by default.

The package contains role-specific Chinese annotated templates:
`config.gateway.example.toml` and `config.backend.example.toml`. The installer
copies the selected role template to `/etc/edge-lb/config.toml`. When
`node_name` is omitted, the agent uses the system hostname.
Listener configuration and target groups are managed by the gateway UI/API and
persisted by the native datapath. Backend targets are part of a target group.

Build packages from the repository root:

```bash
make package          # tar.gz bundles
make deb              # gateway/backend amd64/arm64 Debian packages
make container-image  # local ghcr.io/octays/edge-lb:v<version> image
make container-image-push
```

GitHub Actions builds amd64/arm64 Debian packages on pull requests and pushes.
Non-PR runs also publish a multi-arch container image to GHCR. Tags named
`v*` publish the role-specific Debian packages as direct Release assets:
`edge-lb-gateway_<version>_<arch>.deb` and
`edge-lb-backend_<version>_<arch>.deb`. Branch builds use
`0.1.0-<short-sha>`.

Container deployments should run with host networking and privileged access.
Prepare a role-specific config first:

```bash
sudo install -d -m 0755 /etc/edge-lb /var/lib/edge-lb /var/log/edge-lb

# Gateway host
sudo install -m 0644 deploy/config.gateway.example.toml /etc/edge-lb/config.toml
sudo sysctl -w net.ipv4.ip_forward=1
EDGE_LB_IMAGE=ghcr.io/octays/edge-lb:0.1.7 \
  docker compose -f deploy/compose.example.yml --profile gateway up -d

# Backend host
sudo install -m 0644 deploy/config.backend.example.toml /etc/edge-lb/config.toml
EDGE_LB_IMAGE=ghcr.io/octays/edge-lb:0.1.7 \
  docker compose -f deploy/compose.example.yml --profile backend up -d
```

`EDGE_LB_PUBLIC_IP`, `EDGE_LB_UNDERLAY_IP`, and `EDGE_LB_UNDERLAY_DEV` may be
provided as environment variables to override auto discovery. See
`deploy/compose.example.yml`.
