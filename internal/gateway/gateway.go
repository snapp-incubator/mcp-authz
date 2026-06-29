package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/snapp-incubator/mcp-authz/internal/mcpwire"
	"github.com/snapp-incubator/mcp-authz/internal/scopetoken"
)

const jsonRPCUnauthorized = -32001

type ctxKey int

const methodKey ctxKey = 0

// Handler enforces authorization in front of one MCP server. The scope token
// rides the tool ARGUMENTS (Dify cannot put per-conversation data in MCP
// headers): the gateway injects a _scope_token parameter into every tool schema
// (tools/list), reads + verifies it on each tools/call, strips it before
// forwarding, and rejects unauthorized namespaces. A header is still accepted as
// a fallback for clients that can set one.
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
	h := &Handler{cfg: cfg, secret: secret, proxy: httputil.NewSingleHostReverseProxy(u), log: log}
	h.proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		h.log.Error("upstream error", "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	// Inject the _scope_token parameter into tools/list responses so the agent
	// knows to provide it.
	h.proxy.ModifyResponse = h.injectScopeParam
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	call, isCall := mcpwire.ParseCall(body)
	if !isCall {
		// initialize, tools/list, notifications, … — forward unchanged. (The
		// tools/list response is rewritten by ModifyResponse, which reads the
		// method off the request context.)
		r = r.WithContext(context.WithValue(r.Context(), methodKey, mcpwire.Method(body)))
		h.restore(r, body)
		h.proxy.ServeHTTP(w, r)
		return
	}

	rule, ok := h.cfg.ToolRule(call.Name())
	if !ok {
		h.deny(w, body, fmt.Sprintf("no rule for tool %q", call.Name()))
		return
	}
	if rule.Public {
		// Still strip the synthetic arg if present so the MCP server stays clean.
		cleaned, _ := call.Body()
		_ = call.ScopeToken()
		h.restore(r, pick(cleaned, body))
		h.proxy.ServeHTTP(w, r)
		return
	}

	// Read + strip the scope token (argument first, then header fallback).
	tok := call.ScopeToken()
	if tok == "" {
		tok = r.Header.Get(h.cfg.TokenHeader)
	}
	allowed, authed := h.verify(tok)
	if !authed && h.cfg.RequireToken() {
		h.deny(w, body, "missing or invalid scope token")
		return
	}

	cleaned, err := call.Body()
	if err != nil {
		h.deny(w, body, "could not process request")
		return
	}

	ext := mcpwire.ExtractNamespaces(call.Args(), rule)
	if ext.Unscoped {
		if mcpwire.RequireNamespace(rule) {
			h.deny(w, body, "request is not scoped to a namespace; specify a namespace you are authorized for")
			return
		}
		h.restore(r, cleaned)
		h.proxy.ServeHTTP(w, r)
		return
	}

	allow := map[string]bool{}
	for _, ns := range allowed {
		allow[ns] = true
	}
	for _, ns := range ext.Namespaces {
		if !allow[ns] {
			h.log.Info("denied", "tool", call.Name(), "namespace", ns, "cluster", h.cfg.Cluster)
			h.deny(w, body, fmt.Sprintf("not authorized for namespace %q on %s", ns, h.cfg.Cluster))
			return
		}
	}
	h.restore(r, cleaned)
	h.proxy.ServeHTTP(w, r)
}

// verify returns this cluster's allowed namespaces from the token; authed=false
// when the token is missing/invalid.
func (h *Handler) verify(tok string) ([]string, bool) {
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

// restore puts a (possibly rewritten) body back on the request for forwarding.
func (h *Handler) restore(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
}

// injectScopeParam rewrites a tools/list response to advertise _scope_token.
func (h *Handler) injectScopeParam(resp *http.Response) error {
	if resp.Request == nil {
		return nil
	}
	if m, _ := resp.Request.Context().Value(methodKey).(string); m != mcpwire.MethodToolsList {
		return nil
	}
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	out := transform(raw)
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}

// transform injects _scope_token into a tools/list result, handling both plain
// JSON and SSE (data: {...}) framing used by streamable-http.
func transform(body []byte) []byte {
	if t := strings.TrimSpace(string(body)); t != "" && t[0] == '{' {
		return transformJSON(body)
	}
	// SSE: rewrite each data: line that carries a JSON-RPC object.
	lines := strings.Split(string(body), "\n")
	for i, ln := range lines {
		if data, ok := strings.CutPrefix(ln, "data:"); ok {
			d := strings.TrimSpace(data)
			if d != "" && d[0] == '{' {
				lines[i] = "data: " + string(transformJSON([]byte(d)))
			}
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func transformJSON(b []byte) []byte {
	var obj map[string]any
	if json.Unmarshal(b, &obj) != nil {
		return b
	}
	out, err := json.Marshal(mcpwire.InjectScopeParam(obj))
	if err != nil {
		return b
	}
	return out
}

func (h *Handler) deny(w http.ResponseWriter, body []byte, msg string) {
	var id any
	var env struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(body, &env) == nil && len(env.ID) > 0 {
		_ = json.Unmarshal(env.ID, &id)
	}
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": jsonRPCUnauthorized, "message": "unauthorized: " + msg},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func pick(a, b []byte) []byte {
	if len(a) > 0 {
		return a
	}
	return b
}
