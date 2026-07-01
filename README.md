# mcp-authz

Authorization API for the [SnappCloud bot](../snappcloud-bot). One instance runs
**per cluster** and answers, for its own cluster via OpenShift RBAC, **which
namespaces a user may access**. The bot calls every region's instance and
aggregates — so this service holds no cluster credentials beyond its own
in-cluster identity, and knows nothing about Mattermost, Dify, or MCP servers.

```
snappcloud-bot ──HTTP (bearer)──▶ mcp-authz (this cluster)
                                     │  resolve the user's OpenShift groups
                                     └─ SubjectAccessReview: "can user X (+groups) get pods in ns N?"
```

## Why this design

- **Reuses OpenShift RBAC.** A `SubjectAccessReview` per namespace ("can user X
  `get pods` in N?") means a user sees in the bot exactly the namespaces they see
  with `oc`. No second source of truth.
- **Group-aware.** A SAR does *not* auto-resolve a user's groups, but OpenShift
  RBAC is mostly group-based. So mcp-authz reads the `user.openshift.io` Group
  objects (cached), and every SAR includes the user's real groups plus the
  implicit `system:authenticated` / `system:authenticated:oauth` — matching
  `oc auth can-i --as=<user>`. Without this, group-bound access is missed.
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

POST /v1/resolve             # map resources -> namespace(s) (kube backend only)
  {"refs":[{"kind":"ip","value":"10.0.0.5"},{"kind":"pod","value":"web-0"}]}
  -> {"namespaces":{"10.0.0.5":["team-a"],"web-0":["team-a","team-b"]}}

GET  /healthz  /readyz
```

`/v1/resolve` lets the bot gate MCP tool output that names only a pod/service/IP
(not a namespace): it maps the resource to its namespace(s) in-cluster, and the
bot checks those against the user's scope. Kinds: `pod`, `service`, `ip`,
`namespace`.

Identity arrives as a parameter from the trusted caller (the bot); the bearer
token gates who may call. Groups are resolved server-side, so the `groups` param
is optional (merged with the resolved set).

## Configuration

See [`config.example.yaml`](config.example.yaml). Sections: `server`
(bearer-token env var) and `authorizer` (backend, RBAC `action`, `qps`/`burst`,
`namespaceSelector`). Tune `qps`/`burst` (defaults `100`/`200`) up on clusters
with many namespaces, or set `namespaceSelector` to skip ones users never touch
— the sweep is one SAR per namespace. Tokens are read from the environment,
never from YAML.

## Develop

```bash
make build   # binary -> bin/mcp-authz
make test    # unit + API tests
make run     # run with config.example.yaml
make docker  # multi-arch image via build/package/docker-bake.json
```

## Deploy

Helm chart: `core/helm/apps/mcp-authz`. Deployed on **every region** (the bot
needs each cluster's API). Ships Deployment, Service, ConfigMap, a Secret for
`AUTH_TOKEN`, a private HTTPProxy (`mcp-authz.apps.private.<region_hostname>`), a
NetworkPolicy restricting ingress to the Contour router, and a ClusterRole/Binding
granting:

- `create` on `subjectaccessreviews` (authorization.k8s.io),
- `get`/`list` on `namespaces`, `pods`, `services` (core) — the last two for `/v1/resolve`,
- `get`/`list` on `groups` (user.openshift.io) — for group resolution.

The `AUTH_TOKEN` must be the **same value** in every region and in the bot's
`MCP_AUTHZ_TOKEN`.
