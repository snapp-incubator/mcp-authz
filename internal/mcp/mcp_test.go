package mcp

import (
	"reflect"
	"sort"
	"testing"

	"github.com/snapp-incubator/mcp-authz/internal/config"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantOK   bool
		wantTool string
		wantErr  bool
	}{
		{name: "tools/call", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_flows","arguments":{"namespace":"team-a"}}}`, wantOK: true, wantTool: "get_flows"},
		{name: "initialize", body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, wantOK: false},
		{name: "tools/list", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, wantOK: false},
		{name: "batch", body: `[{"jsonrpc":"2.0","id":1,"method":"tools/call"}]`, wantOK: false},
		{name: "empty", body: ``, wantOK: false},
		{name: "garbage", body: `{not json`, wantErr: true},
		{name: "no tool name", body: `{"jsonrpc":"2.0","method":"tools/call","params":{}}`, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, ok, err := Parse([]byte(tt.body))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && req.Params.Name != tt.wantTool {
				t.Fatalf("tool = %q, want %q", req.Params.Name, tt.wantTool)
			}
		})
	}
}

func TestExtractNamespaces(t *testing.T) {
	rule := config.Tool{
		NamespaceArgs: []config.NamespaceArg{
			{Key: "namespace", Format: config.FormatPlain},
			{Key: "source_pod", Format: config.FormatSlash},
			{Key: "destination_pod", Format: config.FormatSlash},
			{Key: "service", Format: config.FormatSlash},
		},
	}

	tests := []struct {
		name         string
		args         map[string]any
		wantNS       []string
		wantUnscoped bool
	}{
		{
			name:   "plain namespace",
			args:   map[string]any{"namespace": "team-a"},
			wantNS: []string{"team-a"},
		},
		{
			name:   "slash pod",
			args:   map[string]any{"source_pod": "team-b/web-123"},
			wantNS: []string{"team-b"},
		},
		{
			name:   "multiple distinct",
			args:   map[string]any{"namespace": "team-a", "destination_pod": "team-c/api-0"},
			wantNS: []string{"team-a", "team-c"},
		},
		{
			name:   "dedup",
			args:   map[string]any{"namespace": "team-a", "source_pod": "team-a/x", "destination_pod": "team-a/y"},
			wantNS: []string{"team-a"},
		},
		{
			name:         "slash without namespace is unscoped",
			args:         map[string]any{"source_pod": "justaname"},
			wantUnscoped: true,
		},
		{
			name:         "empty args unscoped",
			args:         map[string]any{},
			wantUnscoped: true,
		},
		{
			name:   "non-string ignored",
			args:   map[string]any{"namespace": 123, "destination_pod": "team-d/p"},
			wantNS: []string{"team-d"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := ExtractNamespaces(tt.args, rule)
			if ext.Unscoped != tt.wantUnscoped {
				t.Fatalf("unscoped = %v, want %v", ext.Unscoped, tt.wantUnscoped)
			}
			got := append([]string(nil), ext.Namespaces...)
			sort.Strings(got)
			want := append([]string(nil), tt.wantNS...)
			sort.Strings(want)
			if len(got) == 0 && len(want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("namespaces = %v, want %v", got, want)
			}
		})
	}
}
