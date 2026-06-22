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
	lister authz.NamespaceLister
	action authz.Action
	token  string // bearer token the caller must present ("" disables auth)
	log    *slog.Logger
}

// New builds the API handler.
func New(lister authz.NamespaceLister, action authz.Action, token string, log *slog.Logger) *Handler {
	return &Handler{lister: lister, action: action, token: token, log: log}
}

// Routes registers the endpoints on a mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/namespaces", h.auth(h.namespaces))
	mux.HandleFunc("POST /v1/authorize", h.auth(h.authorize))
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
