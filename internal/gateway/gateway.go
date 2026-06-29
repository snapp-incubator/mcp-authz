package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/snapp-incubator/mcp-authz/internal/mcpwire"
	"github.com/snapp-incubator/mcp-authz/internal/scopetoken"
)

const jsonRPCUnauthorized = -32001

// Handler enforces authorization in front of one MCP server.
type Handler struct {
	cfg    *Config
	secret string
	proxy  *httputil.ReverseProxy
	log    *slog.Logger
}

// New builds the gateway handler.
func New(cfg *Config, secret string, log *slog.Logger) (*Handler, error) {
	u, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", cfg.Upstream, err)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	h := &Handler{cfg: cfg, secret: secret, proxy: rp, log: log}
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		h.log.Error("upstream error", "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	req, isCall, perr := mcpwire.Parse(body)
	if perr != nil || !isCall {
		// Malformed or non-tools/call (initialize, tools/list, …): pass through.
		h.proxy.ServeHTTP(w, r)
		return
	}

	rule, ok := h.cfg.ToolRule(req.Params.Name)
	if !ok {
		h.deny(w, req.ID, fmt.Sprintf("no rule for tool %q", req.Params.Name))
		return
	}
	if rule.Public {
		h.proxy.ServeHTTP(w, r)
		return
	}

	allowed, ok := h.allowedNamespaces(r)
	if !ok {
		if h.cfg.RequireToken() {
			h.deny(w, req.ID, "missing or invalid scope token")
			return
		}
		// Token not required: treat as no namespaces allowed -> deny scoped calls.
		allowed = nil
	}

	ext := mcpwire.ExtractNamespaces(req.Params.Arguments, rule)
	if ext.Unscoped {
		if mcpwire.RequireNamespace(rule) {
			h.deny(w, req.ID, "request is not scoped to a namespace; specify a namespace you are authorized for")
			return
		}
		h.proxy.ServeHTTP(w, r)
		return
	}

	allow := map[string]bool{}
	for _, ns := range allowed {
		allow[ns] = true
	}
	for _, ns := range ext.Namespaces {
		if !allow[ns] {
			h.log.Info("denied", "tool", req.Params.Name, "namespace", ns, "cluster", h.cfg.Cluster)
			h.deny(w, req.ID, fmt.Sprintf("not authorized for namespace %q on %s", ns, h.cfg.Cluster))
			return
		}
	}
	h.proxy.ServeHTTP(w, r)
}

// allowedNamespaces verifies the scope token and returns this cluster's allowed
// namespaces. ok is false when no/invalid token.
func (h *Handler) allowedNamespaces(r *http.Request) ([]string, bool) {
	tok := r.Header.Get(h.cfg.TokenHeader)
	if tok == "" {
		return nil, false
	}
	claims, err := scopetoken.Verify(tok, h.secret)
	if err != nil {
		h.log.Warn("scope token rejected", "err", err)
		return nil, false
	}
	return claims.Scope[h.cfg.Cluster], true
}

func (h *Handler) deny(w http.ResponseWriter, id json.RawMessage, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": jsonRPCUnauthorized, "message": "unauthorized: " + msg},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // 200 so MCP clients surface the message to the model
	_ = json.NewEncoder(w).Encode(resp)
}
