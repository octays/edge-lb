# Edge LB API v1

The management API has one public namespace: `/api/v1`. Unversioned `/api/...`
paths are rejected with HTTP 404 and are not alternate aliases.

Prometheus metrics are not part of `/api/v1`. When `[gateway.metrics]` is
enabled, the gateway daemon exposes `GET /metrics` on a separate port protected
only by CIDR allowlist.

## Resources

- `GET /api/v1/status`
- `GET|POST /api/v1/listener-configs`, `PUT|DELETE /api/v1/listener-configs/{name}`
- `GET|POST /api/v1/target-groups`, `PUT|DELETE /api/v1/target-groups/{name}`
- `GET|POST /api/v1/automations`, `PUT|DELETE /api/v1/automations/{name}`
- `GET|POST /api/v1/notifications`, `GET|DELETE /api/v1/notifications/{id}`,
  `POST /api/v1/notifications/{id}/test`
- `GET /api/v1/nodes/gateways`, `GET /api/v1/nodes/backends`
- `POST /api/v1/operations/{apply|cleanup}`

Import and export are subresources of their owning collection, for example
`/api/v1/listener-configs/export` and `/api/v1/target-groups/import`.

List endpoints that back tables return a pagination object by default:
`{ "items": [], "total": 0, "page": 1, "per_page": 20 }`. They accept
`page`, `per_page`, and `q` query parameters.
Import is idempotent by resource name: existing listener configs or target
groups with the same name are updated in place, and missing names are created.
Duplicate names inside one import payload are rejected before committing the
transaction.

HA configuration and operations live under `/api/v1/ha`: `config`, `status`,
`pair`, and `failover`. Peer-only configuration replica paths are also under
this namespace and require the paired peer bearer token.
Native flow-state xSync uses the `FlowSync` gRPC service on the control-plane
port, not an HTTP API endpoint.

`POST /api/v1/ha/peer/activate` is a peer-only operation used by coordinated
manual failover. The receiving gateway accepts the request only when the target
is itself, then binds the configured L2 VIP and announces it before replying.

Whole-file config replacement, metrics, legacy `operations/failover`, and
HTTP verify endpoints are not part of the public v1 surface. Use the resource
APIs, `/api/v1/ha/failover`, the CLI `edge-lb verify`, and node status instead.

The API returns edge-lb-native listener and target-group models. A target group
owns backend targets, weights, and optional health-check configuration. Runtime
health is included in the target-group view. There is no public standalone
backend-target resource: datapath entries are derived from target groups and
listeners.
