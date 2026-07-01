// Package authz defines the abstract authorization model used by mcp-authz.
//
// The package is deliberately backend-agnostic: an Authorizer answers a single
// question — "may this Subject touch this namespace for this Action?" — and
// nothing about MCP, HTTP, or Kubernetes leaks into the interface. This is what
// lets the same decision engine sit in front of any number of MCP servers
// (hubble, envoy, future ones) and be backed by OpenShift RBAC today and, say,
// SpiceDB tomorrow without touching call sites.
package authz

import (
	"context"
	"errors"
	"fmt"
)

// ErrListUnsupported is returned when a backend cannot enumerate namespaces.
var ErrListUnsupported = errors.New("namespace listing not supported by this backend")

// Subject is the authenticated identity a request is made on behalf of.
// User is the canonical identifier (an email/username in SnappCloud). Groups
// are optional and let RBAC-style backends match group bindings too.
type Subject struct {
	User   string
	Groups []string
}

func (s Subject) String() string {
	if len(s.Groups) == 0 {
		return s.User
	}
	return fmt.Sprintf("%s%v", s.User, s.Groups)
}

// Action describes what the subject wants to do, expressed in Kubernetes RBAC
// terms so the kube backend can map it straight onto a SubjectAccessReview and
// other backends can interpret it however they like. Zero value means the
// backend's configured default (typically "get pods").
type Action struct {
	Verb     string // e.g. "get", "list", "watch"
	Group    string // API group, "" for core
	Resource string // e.g. "pods", "services"
}

// Decision is the outcome of a single namespace check.
type Decision struct {
	Namespace string `json:"namespace"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason,omitempty"`
}

// Authorizer decides whether a Subject may perform an Action in a namespace.
// Implementations must be safe for concurrent use.
type Authorizer interface {
	// Authorize evaluates a single namespace. A non-nil error means the
	// decision could not be made (backend unavailable); callers must treat
	// that as "deny" — never "allow" — to stay fail-closed.
	Authorize(ctx context.Context, sub Subject, act Action, namespace string) (Decision, error)
	// Name identifies the backend for logs and the decision API.
	Name() string
}

// NamespaceLister is an optional capability: enumerate every namespace a
// subject may access. Used by the decision API so a chatbot can scope its
// queries up front instead of probing namespace by namespace. Backends that
// cannot cheaply enumerate (e.g. pure SAR without listing) may not implement it.
type NamespaceLister interface {
	ListAllowed(ctx context.Context, sub Subject, act Action) ([]string, error)
}

// ResourceRef names a cluster resource whose namespace the caller wants
// resolved. Kind is pod | service | ip | namespace; Value is the name or IP.
type ResourceRef struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// NamespaceResolver maps resources to the namespace(s) they live in. MCP tool
// output references pods/IPs/services, not namespaces, so the bot resolves those
// here (in-cluster) before gating them against the user's scope. A resource may
// resolve to several namespaces (same pod name in different namespaces).
type NamespaceResolver interface {
	ResolveNamespaces(ctx context.Context, refs []ResourceRef) (map[string][]string, error)
}

// AuthorizeAll evaluates every namespace and returns the per-namespace
// decisions plus an overall verdict. The overall verdict is allow only if
// every namespace is allowed (all-or-nothing): a query that reaches into a
// namespace the user cannot see must be rejected as a whole. An empty
// namespace set returns allowed=false with ErrNoNamespace semantics left to
// the caller (the caller decides whether unscoped means deny).
func AuthorizeAll(ctx context.Context, a Authorizer, sub Subject, act Action, namespaces []string) (bool, []Decision, error) {
	decisions := make([]Decision, 0, len(namespaces))
	allowed := true
	for _, ns := range namespaces {
		d, err := a.Authorize(ctx, sub, act, ns)
		if err != nil {
			// Fail closed: surface the error and mark denied.
			return false, decisions, err
		}
		if !d.Allowed {
			allowed = false
		}
		decisions = append(decisions, d)
	}
	return allowed, decisions, nil
}
