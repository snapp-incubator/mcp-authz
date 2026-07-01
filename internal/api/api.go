// Package api is the authorization HTTP API. It answers, for the cluster this
// instance runs on, which namespaces a user may access. The bot calls one of
// these per region and aggregates. Identity arrives as a query/body parameter
// from the trusted caller (the bot), gated by a bearer token.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
)

// Handler serves the authorization API.
type Handler struct {
	lister   authz.NamespaceLister
	resolver authz.NamespaceResolver // optional (nil disables /v1/resolve)
	action   authz.Action
	token    string // bearer token the caller must present ("" disables auth)
	log      *slog.Logger
}

// New builds the API handler. resolver may be nil (no /v1/resolve).
func New(lister authz.NamespaceLister, resolver authz.NamespaceResolver, action authz.Action, token string, log *slog.Logger) *Handler {
	return &Handler{lister: lister, resolver: resolver, action: action, token: token, log: log}
}

// Routes registers the endpoints on a mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/namespaces", h.auth(h.namespaces))
	mux.HandleFunc("POST /v1/authorize", h.auth(h.authorize))
	if h.resolver != nil {
		mux.HandleFunc("POST /v1/resolve", h.auth(h.resolve))
	}
}

// auth wraps a handler with bearer-token verification.
func (h *Handler) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got != h.token {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

type namespacesResponse struct {
	User       string   `json:"user"`
	Namespaces []string `json:"namespaces"`
}

// namespaces returns the namespaces the user may access on this cluster.
func (h *Handler) namespaces(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.URL.Query().Get("user"))
	if user == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user query param is required"})
		return
	}
	groups := splitCSV(r.URL.Query().Get("groups"))

	sub := authz.Subject{User: user, Groups: groups}
	nss, err := h.lister.ListAllowed(r.Context(), sub, h.action)
	if err != nil {
		h.log.Error("list namespaces", "user", user, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authorization backend unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, namespacesResponse{User: user, Namespaces: nss})
}

type authorizeRequest struct {
	User       string   `json:"user"`
	Groups     []string `json:"groups"`
	Namespaces []string `json:"namespaces"`
}

type authorizeResponse struct {
	Allowed bool `json:"allowed"`
}

// authorize answers whether the user may access every requested namespace on
// this cluster (all-or-nothing).
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	var req authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if strings.TrimSpace(req.User) == "" || len(req.Namespaces) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user and namespaces are required"})
		return
	}
	// Enumerate once, then check membership — reuses the lister rather than N SARs.
	sub := authz.Subject{User: req.User, Groups: req.Groups}
	allowed, err := h.lister.ListAllowed(r.Context(), sub, h.action)
	if err != nil {
		h.log.Error("authorize", "user", req.User, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authorization backend unavailable"})
		return
	}
	set := make(map[string]bool, len(allowed))
	for _, ns := range allowed {
		set[ns] = true
	}
	for _, ns := range req.Namespaces {
		if !set[ns] {
			writeJSON(w, http.StatusOK, authorizeResponse{Allowed: false})
			return
		}
	}
	writeJSON(w, http.StatusOK, authorizeResponse{Allowed: true})
}

type resolveRequest struct {
	Refs []authz.ResourceRef `json:"refs"`
}

type resolveResponse struct {
	// Namespaces maps each ref value to the namespace(s) it resolves to.
	Namespaces map[string][]string `json:"namespaces"`
}

// resolve maps resource refs (pod/service/ip/namespace) to their namespaces.
// The caller (bot) gates the returned namespaces against the user's scope.
func (h *Handler) resolve(w http.ResponseWriter, r *http.Request) {
	var req resolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if len(req.Refs) == 0 {
		writeJSON(w, http.StatusOK, resolveResponse{Namespaces: map[string][]string{}})
		return
	}
	nss, err := h.resolver.ResolveNamespaces(r.Context(), req.Refs)
	if err != nil {
		h.log.Error("resolve", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "resolve backend unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, resolveResponse{Namespaces: nss})
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
