# mcp-authz

Authorization API for the [SnappCloud bot](../snappcloud-bot). One instance runs
**per cluster** and answers, for its own cluster via OpenShift RBAC, **which
namespaces a user may access**. The bot calls every region's instance and
aggregates — so this service holds no cluster credentials beyond its own
in-cluster identity, and knows nothing about Mattermost, Dify, or MCP servers.

```
snappcloud-bot ──HTTP (bearer)──▶ mcp-authz (this cluster)
                                     │
                                     └─ SubjectAccessReview: "can user X get pods in ns N?"
```

## Why this design

- **Reuses OpenShift RBAC.** A `SubjectAccessReview` per namespace ("can user X
  `get pods` in N?") means a user sees in the bot exactly the namespaces they see
  with `oc`. No second source of truth.
- **One per cluster, no kubeconfigs.** Each instance uses its own in-cluster
  ServiceAccount. The bot aggregates across regions, so no instance needs remote
  credentials.
- **Fail-closed.** Backend errors and missing identity deny by default.
- **Pluggable backend.** `authz.NamespaceLister` is the seam: `kube`
  (SubjectAccessReview) today, `static` (in-config map) for dev.

## API

All endpoints require `Authorization: Bearer <token>` when `server.authTokenEnv`
is set.

```
GET  /v1/namespaces?user=<email>[&groups=a,b]
  -> {"user":"<email>","namespaces":["team-a","team-b"]}

POST /v1/authorize
  {"user":"<email>","namespaces":["team-a"]}
  -> {"allowed":true}        # all-or-nothing across the requested namespaces

GET  /healthz  /readyz
```

Identity arrives as a parameter from the trusted caller (the bot); the bearer
token gates who may call.

## Configuration

See [`config.example.yaml`](config.example.yaml). Sections: `server`
(bearer-token env var) and `authorizer` (backend, RBAC action, `qps`/`burst`,
namespace selector). Tokens are read from the environment, never from YAML.

## Develop

```bash
make build   # binary -> bin/mcp-authz
make test    # unit + API tests
make run     # run with config.example.yaml
make docker  # multi-arch image via build/package/docker-bake.json
```

## Deploy

Helm chart: `core/helm/apps/mcp-authz`. Deployed on **every region** (the bot
needs each cluster's API). Ships Deployment, Service, ConfigMap, the
ClusterRole/Binding (`create` on `subjectaccessreviews`, `get`/`list` on
`namespaces`), a Secret for `AUTH_TOKEN`, a private HTTPProxy
(`mcp-authz.apps.private.<region_hostname>`), and a NetworkPolicy restricting
ingress to the Contour router.

The `AUTH_TOKEN` must be the **same value** in every region and in the bot's
`MCP_AUTHZ_TOKEN`.
