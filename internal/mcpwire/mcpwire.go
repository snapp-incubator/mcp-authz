// Package mcpwire understands just enough of the MCP JSON-RPC wire format for
// the gateway: classify a request (tools/call vs tools/list vs other), read the
// scope token and namespaces from a tools/call, and inject the token parameter
// into a tools/list response schema.
package mcpwire

import (
	"encoding/json"
	"strings"
)

const (
	MethodToolsCall = "tools/call"
	MethodToolsList = "tools/list"
	// ScopeArg is the synthetic tool argument that carries the scope token. The
	// gateway injects it into every tool schema and strips it before forwarding.
	ScopeArg = "_scope_token"
)

// Call is a parsed tools/call with mutable arguments.
type Call struct {
	full map[string]any
	name string
	args map[string]any
}

// ParseCall returns the parsed tools/call, or ok=false when body is not a single
// tools/call object (initialize, notifications, batch, tools/list, …).
func ParseCall(body []byte) (*Call, bool) {
	var full map[string]any
	if t := strings.TrimSpace(string(body)); t == "" || t[0] != '{' {
		return nil, false
	}
	if json.Unmarshal(body, &full) != nil {
		return nil, false
	}
	if m, _ := full["method"].(string); m != MethodToolsCall {
		return nil, false
	}
	params, _ := full["params"].(map[string]any)
	name, _ := params["name"].(string)
	if name == "" {
		return nil, false
	}
	args, _ := params["arguments"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}
	return &Call{full: full, name: name, args: args}, true
}

// Name is the tool name.
func (c *Call) Name() string { return c.name }

// Args are the (mutable) tool arguments.
func (c *Call) Args() map[string]any { return c.args }

// ScopeToken returns the scope token from the arguments and removes it, so the
// upstream MCP server never sees the synthetic argument.
func (c *Call) ScopeToken() string {
	tok, _ := c.args[ScopeArg].(string)
	delete(c.args, ScopeArg)
	return tok
}

// Body re-serializes the call (with _scope_token stripped) for forwarding.
func (c *Call) Body() ([]byte, error) {
	if params, ok := c.full["params"].(map[string]any); ok {
		params["arguments"] = c.args
	}
	return json.Marshal(c.full)
}

// Method returns the JSON-RPC method of a body, or "" if not a single object.
func Method(body []byte) string {
	var m struct {
		Method string `json:"method"`
	}
	if t := strings.TrimSpace(string(body)); t == "" || t[0] != '{' {
		return ""
	}
	_ = json.Unmarshal(body, &m)
	return m.Method
}

// NamespaceArg points at one tool argument and how to read a namespace from it.
type NamespaceArg struct {
	Key    string `yaml:"key"`
	Format string `yaml:"format"` // "plain" | "slash" (namespace/name)
}

// Tool declares how to find namespaces for a tool and whether unscoped is allowed.
type Tool struct {
	NamespaceArgs    []NamespaceArg `yaml:"namespaceArgs"`
	RequireNamespace *bool          `yaml:"requireNamespace"`
	Public           bool           `yaml:"public"`
}

// Extraction is the result of inspecting a tool call.
type Extraction struct {
	Namespaces []string
	Unscoped   bool
}

// ExtractNamespaces pulls namespaces from a tool call's arguments per the rule.
func ExtractNamespaces(args map[string]any, rule Tool) Extraction {
	seen := map[string]bool{}
	var out []string
	add := func(ns string) {
		ns = strings.TrimSpace(ns)
		if ns == "" || seen[ns] {
			return
		}
		seen[ns] = true
		out = append(out, ns)
	}
	for _, na := range rule.NamespaceArgs {
		val, ok := args[na.Key].(string)
		if !ok || val == "" {
			continue
		}
		if na.Format == "slash" {
			if i := strings.Index(val, "/"); i > 0 {
				add(val[:i])
			}
			continue
		}
		add(val)
	}
	return Extraction{Namespaces: out, Unscoped: len(out) == 0}
}

// RequireNamespace reports the effective requireNamespace (default true).
func RequireNamespace(rule Tool) bool {
	return rule.RequireNamespace == nil || *rule.RequireNamespace
}

// InjectScopeParam adds the _scope_token parameter to every tool schema in a
// tools/list JSON-RPC response object, so the agent provides it on each call.
// It mutates and returns the object; non-tools/list objects are returned as-is.
func InjectScopeParam(obj map[string]any) map[string]any {
	result, _ := obj["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	for _, ti := range tools {
		tool, ok := ti.(map[string]any)
		if !ok {
			continue
		}
		schema, _ := tool["inputSchema"].(map[string]any)
		if schema == nil {
			schema = map[string]any{"type": "object"}
			tool["inputSchema"] = schema
		}
		props, _ := schema["properties"].(map[string]any)
		if props == nil {
			props = map[string]any{}
			schema["properties"] = props
		}
		props[ScopeArg] = map[string]any{
			"type":        "string",
			"description": "REQUIRED authorization token. Set it to the exact value of the scope_token workflow input.",
		}
		req, _ := schema["required"].([]any)
		has := false
		for _, r := range req {
			if s, _ := r.(string); s == ScopeArg {
				has = true
			}
		}
		if !has {
			schema["required"] = append(req, ScopeArg)
		}
	}
	return obj
}
