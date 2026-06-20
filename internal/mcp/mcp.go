// Package mcp understands just enough of the MCP JSON-RPC wire format to decide
// whether a request needs authorization and, if so, which namespaces it
// touches. It is intentionally tolerant: anything it does not recognise as a
// namespace-scoped tool call is reported as "not a tools/call" and passed
// through untouched by the proxy.
package mcp

import (
	"encoding/json"
	"strings"

	"github.com/snapp-incubator/mcp-authz/internal/config"
)

// MethodToolsCall is the JSON-RPC method the MCP spec uses to invoke a tool.
const MethodToolsCall = "tools/call"

// Request is a partial view of an MCP JSON-RPC request. Only the fields needed
// for authorization are decoded; the original bytes are forwarded verbatim.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  ToolCallParams  `json:"params"`
}

// ToolCallParams holds the tool name and its arguments.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]any         `json:"arguments"`
	// Meta is ignored but kept so re-marshalling is lossless if ever needed.
	Meta json.RawMessage `json:"_meta,omitempty"`
}

// Parse decodes a request body. ok is false (with nil error) when the body is
// not a single JSON-RPC tools/call object — e.g. initialize, tools/list,
// notifications, or a batch — meaning the proxy should forward it unchecked.
func Parse(body []byte) (*Request, bool, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed[0] != '{' {
		// Empty, or a JSON-RPC batch ('['): not a single tool call.
		return nil, false, nil
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, false, err
	}
	if req.Method != MethodToolsCall || req.Params.Name == "" {
		return nil, false, nil
	}
	return &req, true, nil
}

// ToolRule resolves the extraction rule for a tool name, falling back to the
// "*" default. The second return is false when neither exists (no rule).
func ToolRule(m config.MCP, tool string) (config.Tool, bool) {
	if t, ok := m.Tools[tool]; ok {
		return t, true
	}
	if t, ok := m.Tools["*"]; ok {
		return t, true
	}
	return config.Tool{}, false
}

// Extraction is the result of inspecting a tool call against its rule.
type Extraction struct {
	// Namespaces is the de-duplicated set referenced by the call.
	Namespaces []string
	// Unscoped is true when the call referenced no namespace at all (e.g. a
	// cluster-wide query). The caller decides whether that is allowed.
	Unscoped bool
}

// ExtractNamespaces pulls namespaces from a tool call's arguments per the rule.
func ExtractNamespaces(args map[string]any, rule config.Tool) Extraction {
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
		switch na.Format {
		case config.FormatSlash:
			if ns, ok := namespaceFromSlash(val); ok {
				add(ns)
			}
			// No slash => name only, namespace unknown; contributes nothing.
		default: // FormatPlain and ""
			add(val)
		}
	}

	return Extraction{Namespaces: out, Unscoped: len(out) == 0}
}

// namespaceFromSlash returns the namespace from a "namespace/name" value.
// Hubble pod/service selectors use this shape and support prefix matching on
// the name, but the namespace segment is always concrete.
func namespaceFromSlash(v string) (string, bool) {
	i := strings.Index(v, "/")
	if i <= 0 {
		return "", false
	}
	return v[:i], true
}

// RequireNamespace reports the effective requireNamespace setting (default true).
func RequireNamespace(rule config.Tool) bool {
	if rule.RequireNamespace == nil {
		return true
	}
	return *rule.RequireNamespace
}
