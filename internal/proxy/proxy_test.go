package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
	"github.com/snapp-incubator/mcp-authz/internal/config"
	"github.com/snapp-incubator/mcp-authz/internal/engine"
	"github.com/snapp-incubator/mcp-authz/internal/identity"
)

func newTestHandler(t *testing.T, upstreamURL string, reached *bool) *Handler {
	t.Helper()
	st := authz.NewStatic(authz.StaticConfig{
		Users: map[string][]string{"saman.hoseini@snapp.cab": {"team-a"}},
	})
	eng := engine.New(st, authz.Action{Verb: "get", Resource: "pods"})
	ident := identity.New(config.Identity{
		UserHeaders:     []string{"X-Forwarded-Email"},
		GroupsHeader:    "X-Forwarded-Groups",
		GroupsDelimiter: ",",
	})
	mcps := map[string]config.MCP{
		"hubble": {
			Upstream: upstreamURL,
			Tools: map[string]config.Tool{
				"*": {NamespaceArgs: []config.NamespaceArg{{Key: "namespace", Format: config.FormatPlain}}},
			},
		},
	}
	h, err := New(mcps, eng, ident, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestProxy_AllowedForwards(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream.URL, &reached)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_flows","arguments":{"namespace":"team-a"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Forwarded-Email", "saman.hoseini@snapp.cab")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !reached {
		t.Fatalf("authorized request should reach upstream")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestProxy_DeniedDoesNotForward(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream.URL, &reached)
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_flows","arguments":{"namespace":"kube-system"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Forwarded-Email", "saman.hoseini@snapp.cab")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if reached {
		t.Fatalf("denied request must NOT reach upstream")
	}
	var resp struct {
		ID    json.Number `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if resp.Error.Code != jsonRPCUnauthorized {
		t.Fatalf("error code = %d, want %d", resp.Error.Code, jsonRPCUnauthorized)
	}
	if resp.ID.String() != "7" {
		t.Fatalf("echoed id = %s, want 7", resp.ID.String())
	}
	if !strings.Contains(resp.Error.Message, "unauthorized") {
		t.Fatalf("message = %q", resp.Error.Message)
	}
}

func TestProxy_MissingIdentity401(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer upstream.Close()

	h := newTestHandler(t, upstream.URL, &reached)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_flows","arguments":{"namespace":"team-a"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if reached {
		t.Fatalf("must not forward without identity")
	}
}

func TestProxy_NonToolCallPassthrough(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream.URL, &reached)
	// tools/list has no identity and must pass through untouched.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !reached {
		t.Fatalf("tools/list must pass through to upstream")
	}
}
