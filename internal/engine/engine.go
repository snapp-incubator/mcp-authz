// Package engine is the policy decision point: given an authenticated subject
// and a parsed MCP tool call, it decides allow or deny. It is the one place
// that combines namespace extraction with the authorization backend, and it is
// shared by both the enforcing proxy and the standalone decision API so the two
// can never drift apart.
package engine

import (
	"context"
	"fmt"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
	"github.com/snapp-incubator/mcp-authz/internal/config"
	"github.com/snapp-incubator/mcp-authz/internal/mcp"
)

// Engine evaluates authorization decisions.
type Engine struct {
	authorizer    authz.Authorizer
	defaultAction authz.Action
}

// New builds an Engine over an authorizer and a default RBAC action.
func New(a authz.Authorizer, defaultAction authz.Action) *Engine {
	return &Engine{authorizer: a, defaultAction: defaultAction}
}

// Authorizer exposes the underlying backend (used by the decision API for
// namespace listing).
func (e *Engine) Authorizer() authz.Authorizer { return e.authorizer }

// Verdict is the outcome of evaluating a tool call.
type Verdict struct {
	Allowed    bool             `json:"allowed"`
	Reason     string           `json:"reason"`
	Tool       string           `json:"tool,omitempty"`
	Namespaces []string         `json:"namespaces,omitempty"`
	Decisions  []authz.Decision `json:"decisions,omitempty"`
	// Public marks calls that bypassed authorization by policy.
	Public bool `json:"public,omitempty"`
}

// EvaluateToolCall decides whether sub may run the given tool call against the
// MCP server m. It is fail-closed: extraction or backend errors yield deny.
func (e *Engine) EvaluateToolCall(ctx context.Context, sub authz.Subject, m config.MCP, req *mcp.Request) (Verdict, error) {
	tool := req.Params.Name
	rule, ok := mcp.ToolRule(m, tool)
	if !ok {
		// No rule and no "*" default: deny unknown tools rather than leak.
		return Verdict{Allowed: false, Tool: tool, Reason: fmt.Sprintf("no authorization rule for tool %q", tool)}, nil
	}
	if rule.Public {
		return Verdict{Allowed: true, Tool: tool, Public: true, Reason: "tool is marked public"}, nil
	}

	ext := mcp.ExtractNamespaces(req.Params.Arguments, rule)
	if ext.Unscoped {
		if mcp.RequireNamespace(rule) {
			return Verdict{
				Allowed: false,
				Tool:    tool,
				Reason:  "request is not scoped to a namespace; specify a namespace you have access to",
			}, nil
		}
		// Unscoped allowed by policy (rare; e.g. truly cluster-wide read tool).
		return Verdict{Allowed: true, Tool: tool, Reason: "unscoped call permitted by policy"}, nil
	}

	allowed, decisions, err := authz.AuthorizeAll(ctx, e.authorizer, sub, e.action(m), ext.Namespaces)
	if err != nil {
		return Verdict{Allowed: false, Tool: tool, Namespaces: ext.Namespaces, Reason: "authorization backend error"}, err
	}

	v := Verdict{Allowed: allowed, Tool: tool, Namespaces: ext.Namespaces, Decisions: decisions}
	if allowed {
		v.Reason = "subject authorized for all referenced namespaces"
	} else {
		v.Reason = denyReason(decisions)
	}
	return v, nil
}

// EvaluateNamespaces decides access to an explicit set of namespaces, for the
// decision API (no MCP request involved).
func (e *Engine) EvaluateNamespaces(ctx context.Context, sub authz.Subject, m config.MCP, namespaces []string) (Verdict, error) {
	if len(namespaces) == 0 {
		return Verdict{Allowed: false, Reason: "no namespaces provided"}, nil
	}
	allowed, decisions, err := authz.AuthorizeAll(ctx, e.authorizer, sub, e.action(m), namespaces)
	if err != nil {
		return Verdict{Allowed: false, Namespaces: namespaces, Reason: "authorization backend error"}, err
	}
	v := Verdict{Allowed: allowed, Namespaces: namespaces, Decisions: decisions}
	if allowed {
		v.Reason = "subject authorized for all namespaces"
	} else {
		v.Reason = denyReason(decisions)
	}
	return v, nil
}

func (e *Engine) action(m config.MCP) authz.Action {
	if m.Action != nil {
		return *m.Action
	}
	return e.defaultAction
}

func denyReason(decisions []authz.Decision) string {
	for _, d := range decisions {
		if !d.Allowed {
			return fmt.Sprintf("not authorized for namespace %q: %s", d.Namespace, d.Reason)
		}
	}
	return "not authorized"
}
