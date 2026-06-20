# mcp-authz

Authorization gateway for MCP servers on OpenShift/OKD4.

The MCP servers in this fleet (e.g. [cilium-hubble-mcp](../cilium-hubble-mcp),
[contour-envoy-mcp](../envoy-mcp-server)) let a chatbot/LLM query cluster
workloads and network traffic. Authentication already identifies the caller.
`mcp-authz` adds **authorization**: it ensures a user only ever queries
namespaces they have access to — e.g. `saman.hoseini@snapp.cab` can inspect
flows in `team-a`/`team-b` but is rejected for `kube-system`.

## How it works

```
chatbot/LLM ──MCP──▶ mcp-authz ──MCP──▶ cilium-hubble-mcp / contour-envoy-mcp
                        │
                        ├─ identity:  read user/groups from trusted auth-proxy headers
                        ├─ extract:   find which namespaces this tool call touches
                        └─ decide:    SubjectAccessReview against OpenShift RBAC
```

For every MCP `tools/call`, the gateway:

1. Reads the caller identity from headers an upstream auth proxy injected.
2. Extracts the namespace(s) the call references — from a `namespace` arg and
   from the `namespace/name` prefix of pod/service selectors.
3. Asks the authorizer whether the user may access **every** referenced
   namespace (all-or-nothing).
4. Forwards to the real MCP server if allowed, otherwise returns a JSON-RPC
   error (`code -32001`) so the LLM is told it is unauthorized — the query never
   reaches the MCP server.

Non-`tools/call` traffic (`initialize`, `tools/list`, notifications) passes
through untouched.

## Why this design

- **Reuses OpenShift RBAC.** The default `kube` backend runs a
  `SubjectAccessReview` ("can user X `get pods` in namespace N?"). No second
  source of truth — a user sees in an MCP exactly what they see with `oc`.
- **Abstract / multi-MCP.** The decision engine knows nothing about Hubble or
  Envoy. Protecting a new MCP server is a **config change**: declare its
  upstream and which tool arguments carry a namespace. See
  [`config.example.yaml`](config.example.yaml).
- **Pluggable backend.** `authz.Authorizer` is a one-method interface.
  Backends today: `kube` (SubjectAccessReview), `static` (in-config map),
  `allow` (dev only). A SpiceDB/Zanzibar backend can be added without touching
  the proxy or API.
- **Fail-closed.** Backend errors, missing identity, unknown tools, and
  unscoped (cluster-wide) calls all deny by default.

## Modes

`-mode` selects the surface:

| Mode    | Purpose |
|---------|---------|
| `proxy` | Inline enforcement in front of MCP servers (the hot path). |
| `api`   | Decision API for a chatbot to pre-check before calling an MCP. |
| `both`  | Both (default). |

### Decision API

```
POST /v1/authorize
  {"user":"saman.hoseini@snapp.cab","mcp":"cilium-hubble-mcp","namespaces":["team-a"]}
  -> {"allowed":true, "decisions":[...]}

GET /v1/namespaces?user=saman.hoseini@snapp.cab&mcp=cilium-hubble-mcp
  -> {"user":"...","namespaces":["team-a","team-b"]}
```

## Configuration

See [`config.example.yaml`](config.example.yaml). Key sections: `identity`
(which headers carry the user/groups), `authorizer` (backend + RBAC action +
cache), and `mcps` (per-server upstream and per-tool namespace extraction
rules). A tool may be marked `public: true` to skip authorization (e.g.
`server_status`, `get_namespaces`).

## Develop

```bash
make build      # binary -> bin/mcp-authz
make test       # unit + proxy integration tests
make run        # run with config.example.yaml
make docker     # build container image
```

## Deploy

Helm chart lives at `core/helm/apps/mcp-authz` (same layout as the other
SnappCloud app charts). It ships the Deployment, Service, ConfigMap, and the
ClusterRole/Binding granting `create` on `subjectaccessreviews` plus
`get`/`list` on `namespaces`.

Point each chatbot MCP client at the gateway instead of the MCP server:

```
http://mcp-authz-svc:8080/<mcp-name>/mcp
```

> Security: the gateway trusts identity headers. It must be reachable **only**
> through the authenticating proxy, never directly, or callers could spoof
> identity.
