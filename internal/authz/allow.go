package authz

import "context"

// AllowAll authorizes everything. Intended only for local development and
// testing — never enable it in a cluster. Selected via provider "allow".
type AllowAll struct{}

func (AllowAll) Name() string { return "allow" }

func (AllowAll) Authorize(_ context.Context, _ Subject, _ Action, ns string) (Decision, error) {
	return Decision{Namespace: ns, Allowed: true, Reason: "allow-all backend (dev only)"}, nil
}
