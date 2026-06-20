// Package proxy is the policy enforcement point. It is a reverse proxy that
// sits in front of one or more MCP servers: it reads the caller's identity,
// inspects each MCP tools/call, asks the engine for a decision, and either
// forwards the request to the real MCP server or returns a JSON-RPC error so
// the chatbot/LLM is told it is not authorized — without the query ever
// reaching the MCP server.
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/snapp-incubator/mcp-authz/internal/config"
	"github.com/snapp-incubator/mcp-authz/internal/engine"
	"github.com/snapp-incubator/mcp-authz/internal/identity"
	"github.com/snapp-incubator/mcp-authz/internal/mcp"
)

// jsonRPCUnauthorized is a custom JSON-RPC error code for authz denials.
const jsonRPCUnauthorized = -32001

type backend struct {
	name  string
	cfg   config.MCP
	proxy *httputil.ReverseProxy
}

// Handler enforces authorization in front of the configured MCP servers.
type Handler struct {
	engine   *engine.Engine
	ident    *identity.Extractor
	requireID bool
	log      *slog.Logger

	backends map[string]*backend
	single   *backend // set when exactly one MCP is configured
}

// New builds the enforcing proxy handler.
func New(cfgs map[string]config.MCP, eng *engine.Engine, ident *identity.Extractor, requireID bool, log *slog.Logger) (*Handler, error) {
	h := &Handler{
		engine:    eng,
		ident:     ident,
		requireID: requireID,
		log:       log,
		backends:  map[string]*backend{},
	}
	for name, c := range cfgs {
		u, err := url.Parse(c.Upstream)
		if err != nil {
			return nil, fmt.Errorf("mcp %q upstream %q: %w", name, c.Upstream, err)
		}
		rp := httputil.NewSingleHostReverseProxy(u)
		rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			h.log.Error("upstream error", "mcp", name, "err", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		}
		b := &backend{name: name, cfg: c, proxy: rp}
		h.backends[name] = b
		h.single = b
	}
	if len(h.backends) != 1 {
		h.single = nil
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, ok := h.route(r)
	if !ok {
		http.Error(w, "no MCP backend for path", http.StatusNotFound)
		return
	}

	// Buffer the body so we can both inspect and forward it.
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20)) // 4 MiB cap
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	req, isToolCall, perr := mcp.Parse(body)
	if perr != nil {
		// Malformed JSON-RPC: let the upstream MCP server reject it properly.
		h.log.Warn("parse mcp body", "mcp", b.name, "err", perr)
		b.proxy.ServeHTTP(w, r)
		return
	}
	if !isToolCall {
		// initialize, tools/list, notifications, etc. — nothing to authorize.
		b.proxy.ServeHTTP(w, r)
		return
	}

	sub, present := h.ident.Extract(r)
	if !present && h.requireID {
		h.log.Warn("missing identity", "mcp", b.name, "tool", req.Params.Name)
		http.Error(w, "missing identity headers", http.StatusUnauthorized)
		return
	}

	verdict, derr := h.engine.EvaluateToolCall(r.Context(), sub, b.cfg, req)
	if derr != nil {
		// Backend error: fail closed.
		h.log.Error("authorization error", "mcp", b.name, "user", sub.User, "tool", req.Params.Name, "err", derr)
		h.writeRPCError(w, req.ID, "authorization temporarily unavailable")
		return
	}

	if !verdict.Allowed {
		h.log.Info("denied",
			"mcp", b.name, "user", sub.User, "tool", verdict.Tool,
			"namespaces", verdict.Namespaces, "reason", verdict.Reason)
		h.writeRPCError(w, req.ID, "unauthorized: "+verdict.Reason)
		return
	}

	h.log.Info("allowed",
		"mcp", b.name, "user", sub.User, "tool", verdict.Tool,
		"namespaces", verdict.Namespaces, "public", verdict.Public)
	b.proxy.ServeHTTP(w, r)
}

// route picks the backend and, in multi-MCP mode, strips the /<name> prefix so
// the upstream sees its own path (e.g. /mcp).
func (h *Handler) route(r *http.Request) (*backend, bool) {
	if h.single != nil {
		return h.single, true
	}
	// Path form: /<name>/<rest>
	trimmed := strings.TrimPrefix(r.URL.Path, "/")
	name, rest, _ := strings.Cut(trimmed, "/")
	b, ok := h.backends[name]
	if !ok {
		return nil, false
	}
	r.URL.Path = "/" + rest
	return b, true
}

// writeRPCError returns a JSON-RPC error envelope with HTTP 200 so MCP clients
// surface the message to the model instead of treating it as a transport fault.
func (h *Handler) writeRPCError(w http.ResponseWriter, id json.RawMessage, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    jsonRPCUnauthorized,
			"message": msg,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.log.Error("encode rpc error", "err", err)
	}
}
