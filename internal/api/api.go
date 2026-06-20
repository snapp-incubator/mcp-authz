// Package api exposes a small JSON decision API so a chatbot/orchestrator can
// ask, before it ever calls an MCP server, "is this user allowed?" and "which
// namespaces can this user see?". It is the standalone counterpart to the
// inline proxy and shares the same engine, so answers are identical.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
	"github.com/snapp-incubator/mcp-authz/internal/config"
	"github.com/snapp-incubator/mcp-authz/internal/engine"
	"github.com/snapp-incubator/mcp-authz/internal/identity"
)

// Handler serves the decision API under /v1/.
type Handler struct {
	engine *engine.Engine
	mcps   map[string]config.MCP
	ident  *identity.Extractor
	log    *slog.Logger
}

// New builds the decision API handler. ident lets the API read the caller's
// identity from the same trusted auth-proxy headers the enforcing proxy uses,
// so a chatbot can forward the user in a header instead of the request body.
func New(eng *engine.Engine, mcps map[string]config.MCP, ident *identity.Extractor, log *slog.Logger) *Handler {
	return &Handler{engine: eng, mcps: mcps, ident: ident, log: log}
}

// Routes registers the API endpoints on a mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/authorize", h.authorize)
	mux.HandleFunc("GET /v1/namespaces", h.namespaces)
}

type authorizeRequest struct {
	User       string   `json:"user"`
	Groups     []string `json:"groups"`
	MCP        string   `json:"mcp"`
	Namespaces []string `json:"namespaces"`
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	var req authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}

	// Identity from the body takes precedence; otherwise fall back to the
	// trusted auth-proxy headers so a caller can forward the user in a header.
	sub := authz.Subject{User: req.User, Groups: req.Groups}
	if sub.User == "" {
		if s, ok := h.ident.Extract(r); ok {
			sub = s
		}
	}
	if sub.User == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user is required (request body or identity header)"})
		return
	}

	m, ok := h.lookupMCP(req.MCP)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown mcp"})
		return
	}

	verdict, err := h.engine.EvaluateNamespaces(r.Context(), sub, m, req.Namespaces)
	if err != nil {
		h.log.Error("authorize api backend error", "user", req.User, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authorization backend unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, verdict)
}

type namespacesResponse struct {
	User       string   `json:"user"`
	Namespaces []string `json:"namespaces"`
}

func (h *Handler) namespaces(w http.ResponseWriter, r *http.Request) {
	// Identity from query params takes precedence; otherwise fall back to the
	// trusted auth-proxy headers.
	sub := authz.Subject{User: r.URL.Query().Get("user")}
	if g := r.URL.Query().Get("groups"); g != "" {
		sub.Groups = splitCSV(g)
	}
	if sub.User == "" {
		if s, ok := h.ident.Extract(r); ok {
			sub = s
		}
	}
	if sub.User == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user is required (query param or identity header)"})
		return
	}

	m, ok := h.lookupMCP(r.URL.Query().Get("mcp"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown mcp"})
		return
	}

	lister, ok := h.engine.Authorizer().(authz.NamespaceLister)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "namespace listing not supported by backend"})
		return
	}

	act := authz.Action{}
	if m.Action != nil {
		act = *m.Action
	}
	nss, err := lister.ListAllowed(r.Context(), sub, act)
	if err != nil {
		h.log.Error("namespaces api backend error", "user", sub.User, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authorization backend unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, namespacesResponse{User: sub.User, Namespaces: nss})
}

// lookupMCP returns the named MCP, or — when name is empty and exactly one MCP
// is configured — that single MCP. This keeps the API ergonomic in the common
// single-MCP-per-deployment case while staying explicit for multi-MCP setups.
func (h *Handler) lookupMCP(name string) (config.MCP, bool) {
	if name == "" {
		if len(h.mcps) == 1 {
			for _, m := range h.mcps {
				return m, true
			}
		}
		// Empty name with multiple MCPs: use a zero MCP (default action) so
		// pure namespace checks still work without per-MCP overrides.
		return config.MCP{}, true
	}
	m, ok := h.mcps[name]
	return m, ok
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
