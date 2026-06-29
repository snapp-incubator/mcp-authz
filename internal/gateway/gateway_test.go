package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snapp-incubator/mcp-authz/internal/mcpwire"
	"github.com/snapp-incubator/mcp-authz/internal/scopetoken"
)

const secret = "test-secret"

func boolp(b bool) *bool { return &b }

func newGW(t *testing.T, upstream string) *Handler {
	t.Helper()
	cfg := &Config{
		Cluster: "okd4-ts-2", Upstream: upstream, TokenHeader: "X-Scope-Token",
		Required: boolp(true),
		Tools: map[string]mcpwire.Tool{
			"*":             {NamespaceArgs: []mcpwire.NamespaceArg{{Key: "namespace", Format: "plain"}, {Key: "pod", Format: "slash"}}},
			"server_status": {Public: true},
		},
	}
	h, err := New(cfg, secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func token(t *testing.T, scope scopetoken.Scope) string {
	tok, err := scopetoken.Sign(scopetoken.Claims{User: "u", Scope: scope, Exp: time.Now().Add(time.Hour).Unix()}, secret)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// call builds a tools/call with the scope token in the arguments (the B design).
func call(name string, args map[string]any, tok string) string {
	if args == nil {
		args = map[string]any{}
	}
	if tok != "" {
		args["_scope_token"] = tok
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args}})
	return string(b)
}

// stubUpstream echoes whether _scope_token reached it (it must NOT) and marks forwarding.
func stubUpstream(t *testing.T, sawScopeArg *bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "_scope_token") {
			*sawScopeArg = true
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"UPSTREAM_OK"}`)
	}))
}

func do(t *testing.T, h *Handler, body string) (bool, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	resp := w.Body.String()
	forwarded := strings.Contains(resp, "UPSTREAM_OK")
	var env struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal([]byte(resp), &env)
	return forwarded, env.Error.Message
}

func TestAuthorizedNamespaceForwardedAndArgStripped(t *testing.T) {
	saw := false
	up := stubUpstream(t, &saw)
	defer up.Close()
	h := newGW(t, up.URL)
	fwd, errMsg := do(t, h, call("get_flows", map[string]any{"namespace": "argocd"},
		token(t, scopetoken.Scope{"okd4-ts-2": {"argocd"}})))
	if !fwd {
		t.Fatalf("authorized call not forwarded; err=%q", errMsg)
	}
	if saw {
		t.Fatal("_scope_token leaked to the upstream MCP server")
	}
}

func TestUnauthorizedNamespaceBlocked(t *testing.T) {
	saw := false
	up := stubUpstream(t, &saw)
	defer up.Close()
	h := newGW(t, up.URL)
	fwd, errMsg := do(t, h, call("get_flows", map[string]any{"namespace": "kube-system"},
		token(t, scopetoken.Scope{"okd4-ts-2": {"argocd"}})))
	if fwd {
		t.Fatal("unauthorized namespace forwarded")
	}
	if !strings.Contains(errMsg, "not authorized for namespace") {
		t.Fatalf("expected deny, got %q", errMsg)
	}
}

func TestWrongClusterScopeBlocked(t *testing.T) {
	saw := false
	up := stubUpstream(t, &saw)
	defer up.Close()
	h := newGW(t, up.URL)
	fwd, _ := do(t, h, call("get_flows", map[string]any{"namespace": "argocd"},
		token(t, scopetoken.Scope{"okd4-ts-3": {"argocd"}})))
	if fwd {
		t.Fatal("ts-3 scope must not authorize a ts-2 call")
	}
}

func TestMissingTokenBlocked(t *testing.T) {
	saw := false
	up := stubUpstream(t, &saw)
	defer up.Close()
	h := newGW(t, up.URL)
	fwd, errMsg := do(t, h, call("get_flows", map[string]any{"namespace": "argocd"}, ""))
	if fwd {
		t.Fatal("call with no token forwarded")
	}
	if !strings.Contains(errMsg, "scope token") {
		t.Fatalf("expected token error, got %q", errMsg)
	}
}

func TestPublicToolForwardedWithoutToken(t *testing.T) {
	saw := false
	up := stubUpstream(t, &saw)
	defer up.Close()
	h := newGW(t, up.URL)
	fwd, _ := do(t, h, call("server_status", nil, ""))
	if !fwd {
		t.Fatal("public tool should forward without a token")
	}
}

func TestToolsListInjectsScopeParam(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_flows","inputSchema":{"type":"object","properties":{"namespace":{"type":"string"}},"required":["namespace"]}}]}}`)
	}))
	defer up.Close()
	h := newGW(t, up.URL)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	out := w.Body.String()
	if !strings.Contains(out, "_scope_token") {
		t.Fatalf("tools/list response did not advertise _scope_token: %s", out)
	}
}
