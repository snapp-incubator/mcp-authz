package authz

import (
	"context"
	"fmt"
	"strings"
)

// StaticConfig maps subjects to the namespaces they may access. It is the
// fallback backend for clusters without OpenShift RBAC wiring (or for tests).
// A namespace value of "*" grants every namespace. Matching is case-insensitive
// on the user/group key.
type StaticConfig struct {
	// Users maps a username to its allowed namespaces.
	Users map[string][]string `yaml:"users" json:"users"`
	// Groups maps a group name to its allowed namespaces.
	Groups map[string][]string `yaml:"groups" json:"groups"`
}

// Static is an in-memory Authorizer backed by a StaticConfig.
type Static struct {
	users  map[string]map[string]bool
	groups map[string]map[string]bool
}

// NewStatic builds a Static authorizer, normalising keys to lower case.
func NewStatic(cfg StaticConfig) *Static {
	s := &Static{
		users:  map[string]map[string]bool{},
		groups: map[string]map[string]bool{},
	}
	for u, nss := range cfg.Users {
		s.users[strings.ToLower(u)] = toSet(nss)
	}
	for g, nss := range cfg.Groups {
		s.groups[strings.ToLower(g)] = toSet(nss)
	}
	return s
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

func (s *Static) Name() string { return "static" }

func (s *Static) Authorize(_ context.Context, sub Subject, _ Action, ns string) (Decision, error) {
	if set, ok := s.users[strings.ToLower(sub.User)]; ok {
		if set["*"] || set[ns] {
			return allow(ns, fmt.Sprintf("user %q grant", sub.User)), nil
		}
	}
	for _, g := range sub.Groups {
		if set, ok := s.groups[strings.ToLower(g)]; ok {
			if set["*"] || set[ns] {
				return allow(ns, fmt.Sprintf("group %q grant", g)), nil
			}
		}
	}
	return deny(ns, fmt.Sprintf("no static grant for %s in %q", sub.User, ns)), nil
}

// ListAllowed returns the union of namespaces granted to the user and its
// groups. If any grant is "*" the wildcard is returned verbatim, since the full
// namespace list is not known to a static backend.
func (s *Static) ListAllowed(_ context.Context, sub Subject, _ Action) ([]string, error) {
	out := map[string]bool{}
	collect := func(set map[string]bool) {
		for ns := range set {
			out[ns] = true
		}
	}
	if set, ok := s.users[strings.ToLower(sub.User)]; ok {
		collect(set)
	}
	for _, g := range sub.Groups {
		if set, ok := s.groups[strings.ToLower(g)]; ok {
			collect(set)
		}
	}
	result := make([]string, 0, len(out))
	for ns := range out {
		result = append(result, ns)
	}
	return result, nil
}

func allow(ns, reason string) Decision { return Decision{Namespace: ns, Allowed: true, Reason: reason} }
func deny(ns, reason string) Decision  { return Decision{Namespace: ns, Allowed: false, Reason: reason} }
