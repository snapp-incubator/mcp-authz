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

func call(name string, args map[string]any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args}})
	return string(b)
}

// do sends a tools/call and returns (forwardedToUpstream, jsonRPCError).
func do(t *testing.T, h *Handler, body, tok string) (bool, string) {
	t.Helper()
	forwarded := false
	// upstream marker handler is set per test via the proxy target; here we detect
	// forwarding by the response body from a stub upstream.
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	if tok != "" {
		r.Header.Set("X-Scope-Token", tok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	resp := w.Body.String()
	if strings.Contains(resp, "UPSTREAM_OK") {
		forwarded = true
	}
	var env struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal([]byte(resp), &env)
	return forwarded, env.Error.Message
}

func stubUpstream() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"UPSTREAM_OK"}`)
	}))
}

func TestAuthorizedNamespaceForwarded(t *testing.T) {
	up := stubUpstream()
	defer up.Close()
	h := newGW(t, up.URL)
	fwd, errMsg := do(t, h, call("get_flows", map[string]any{"namespace": "argocd"}),
		token(t, scopetoken.Scope{"okd4-ts-2": {"argocd", "team-a"}}))
	if !fwd {
		t.Fatalf("authorized call was not forwarded; err=%q", errMsg)
	}
}

func TestUnauthorizedNamespaceBlocked(t *testing.T) {
	up := stubUpstream()
	defer up.Close()
	h := newGW(t, up.URL)
	fwd, errMsg := do(t, h, call("get_flows", map[string]any{"namespace": "kube-system"}),
		token(t, scopetoken.Scope{"okd4-ts-2": {"argocd"}}))
	if fwd {
		t.Fatal("unauthorized namespace was forwarded")
	}
	if !strings.Contains(errMsg, "not authorized for namespace") {
		t.Fatalf("expected deny message, got %q", errMsg)
	}
}

func TestWrongClusterScopeBlocked(t *testing.T) {
	up := stubUpstream()
	defer up.Close()
	h := newGW(t, up.URL) // cluster okd4-ts-2
	// token authorizes argocd on ts-3, nothing on ts-2 -> blocked here.
	fwd, _ := do(t, h, call("get_flows", map[string]any{"namespace": "argocd"}),
		token(t, scopetoken.Scope{"okd4-ts-3": {"argocd"}}))
	if fwd {
		t.Fatal("ts-3 scope must not authorize a ts-2 call")
	}
}

func TestMissingTokenBlocked(t *testing.T) {
	up := stubUpstream()
	defer up.Close()
	h := newGW(t, up.URL)
	fwd, errMsg := do(t, h, call("get_flows", map[string]any{"namespace": "argocd"}), "")
	if fwd {
		t.Fatal("call with no token was forwarded")
	}
	if !strings.Contains(errMsg, "scope token") {
		t.Fatalf("expected token error, got %q", errMsg)
	}
}

func TestPublicToolForwardedWithoutToken(t *testing.T) {
	up := stubUpstream()
	defer up.Close()
	h := newGW(t, up.URL)
	fwd, _ := do(t, h, call("server_status", nil), "")
	if !fwd {
		t.Fatal("public tool should be forwarded without a token")
	}
}

func TestSlashNamespaceExtraction(t *testing.T) {
	up := stubUpstream()
	defer up.Close()
	h := newGW(t, up.URL)
	// pod = "kube-system/coredns" -> namespace kube-system, not authorized.
	fwd, _ := do(t, h, call("get_flows", map[string]any{"pod": "kube-system/coredns"}),
		token(t, scopetoken.Scope{"okd4-ts-2": {"argocd"}}))
	if fwd {
		t.Fatal("slash-form unauthorized namespace was forwarded")
	}
}
