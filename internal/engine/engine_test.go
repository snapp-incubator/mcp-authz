package engine

import (
	"context"
	"testing"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
	"github.com/snapp-incubator/mcp-authz/internal/config"
	"github.com/snapp-incubator/mcp-authz/internal/mcp"
)

func testMCP() config.MCP {
	return config.MCP{
		Upstream: "http://upstream:8080",
		Tools: map[string]config.Tool{
			"*": {
				NamespaceArgs: []config.NamespaceArg{
					{Key: "namespace", Format: config.FormatPlain},
					{Key: "source_pod", Format: config.FormatSlash},
				},
			},
			"server_status": {Public: true},
		},
	}
}

func newEngine() *Engine {
	st := authz.NewStatic(authz.StaticConfig{
		Users: map[string][]string{"saman.hoseini@snapp.cab": {"team-a", "team-b"}},
	})
	return New(st, authz.Action{Verb: "get", Resource: "pods"})
}

func toolCall(name string, args map[string]any) *mcp.Request {
	return &mcp.Request{Method: mcp.MethodToolsCall, Params: mcp.ToolCallParams{Name: name, Arguments: args}}
}

func TestEvaluate_AllowedNamespace(t *testing.T) {
	eng := newEngine()
	sub := authz.Subject{User: "saman.hoseini@snapp.cab"}
	v, err := eng.EvaluateToolCall(context.Background(), sub, testMCP(), toolCall("get_flows", map[string]any{"namespace": "team-a"}))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Allowed {
		t.Fatalf("expected allowed, got deny: %s", v.Reason)
	}
}

func TestEvaluate_DeniedNamespace(t *testing.T) {
	eng := newEngine()
	sub := authz.Subject{User: "saman.hoseini@snapp.cab"}
	v, err := eng.EvaluateToolCall(context.Background(), sub, testMCP(), toolCall("get_flows", map[string]any{"namespace": "kube-system"}))
	if err != nil {
		t.Fatal(err)
	}
	if v.Allowed {
		t.Fatalf("expected deny for kube-system")
	}
}

func TestEvaluate_OneAllowedOneDenied_DeniesWhole(t *testing.T) {
	eng := newEngine()
	sub := authz.Subject{User: "saman.hoseini@snapp.cab"}
	v, err := eng.EvaluateToolCall(context.Background(), sub, testMCP(),
		toolCall("get_flows", map[string]any{"namespace": "team-a", "source_pod": "kube-system/x"}))
	if err != nil {
		t.Fatal(err)
	}
	if v.Allowed {
		t.Fatalf("mixed access must deny the whole call")
	}
}

func TestEvaluate_UnscopedDenied(t *testing.T) {
	eng := newEngine()
	sub := authz.Subject{User: "saman.hoseini@snapp.cab"}
	v, err := eng.EvaluateToolCall(context.Background(), sub, testMCP(), toolCall("get_flows", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if v.Allowed {
		t.Fatalf("unscoped call must be denied by default")
	}
}

func TestEvaluate_PublicTool(t *testing.T) {
	eng := newEngine()
	sub := authz.Subject{User: "nobody@snapp.cab"}
	v, err := eng.EvaluateToolCall(context.Background(), sub, testMCP(), toolCall("server_status", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Allowed || !v.Public {
		t.Fatalf("public tool must be allowed without auth")
	}
}

func TestEvaluate_UnknownUserDenied(t *testing.T) {
	eng := newEngine()
	sub := authz.Subject{User: "intruder@evil.com"}
	v, err := eng.EvaluateToolCall(context.Background(), sub, testMCP(), toolCall("get_flows", map[string]any{"namespace": "team-a"}))
	if err != nil {
		t.Fatal(err)
	}
	if v.Allowed {
		t.Fatalf("unknown user must be denied")
	}
}
