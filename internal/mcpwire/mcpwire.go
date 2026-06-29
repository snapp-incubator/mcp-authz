// Package mcpwire understands just enough of the MCP JSON-RPC wire format to
// decide whether a request is a namespace-scoped tools/call and, if so, which
// namespaces it touches. Anything it does not recognise is reported as "not a
// tools/call" and passed through unchecked by the gateway.
package mcpwire

import (
	"encoding/json"
	"strings"
)

const methodToolsCall = "tools/call"

// Request is a partial view of an MCP JSON-RPC request.
type Request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"params"`
}

// Parse decodes a body. ok is false (nil error) when it is not a single
// tools/call object (initialize, tools/list, notifications, batch) — the gateway
// forwards those unchecked.
func Parse(body []byte) (*Request, bool, error) {
	t := strings.TrimSpace(string(body))
	if t == "" || t[0] != '{' {
		return nil, false, nil
	}
	var r Request
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, false, err
	}
	if r.Method != methodToolsCall || r.Params.Name == "" {
		return nil, false, nil
	}
	return &r, true, nil
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
		raw, ok := args[na.Key]
		if !ok {
			continue
		}
		val, ok := raw.(string)
		if !ok || val == "" {
			continue
		}
		if na.Format == "slash" {
			if i := strings.Index(val, "/"); i > 0 {
				add(val[:i])
			}
			continue
		}
		add(val) // plain
	}
	return Extraction{Namespaces: out, Unscoped: len(out) == 0}
}

// RequireNamespace reports the effective requireNamespace (default true).
func RequireNamespace(rule Tool) bool {
	return rule.RequireNamespace == nil || *rule.RequireNamespace
}
