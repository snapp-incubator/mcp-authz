package authz

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// implicitGroups are the groups OpenShift attaches to every authenticated user.
// `oc auth can-i --as=<user>` includes them, so a SubjectAccessReview must too —
// otherwise RoleBindings to all authenticated users are missed.
var implicitGroups = []string{"system:authenticated", "system:authenticated:oauth"}

// groupCache resolves a user's OpenShift group memberships. RBAC is group-based,
// and a SubjectAccessReview does NOT auto-resolve a user's groups — the caller
// must supply them. The bot doesn't know them, so mcp-authz (in-cluster) reads
// the user.openshift.io Group objects and maps user -> groups, cached briefly.
//
// On a cluster without the OpenShift Group API (plain Kubernetes) the fetch
// fails and groupsFor returns nil — only the implicit groups are then used.
type groupCache struct {
	fetch func(context.Context) ([]byte, error)
	ttl   time.Duration

	mu      sync.Mutex
	expires time.Time
	byUser  map[string][]string
}

func newGroupCache(fetch func(context.Context) ([]byte, error), ttl time.Duration) *groupCache {
	return &groupCache{fetch: fetch, ttl: ttl, byUser: map[string][]string{}}
}

// groupsFor returns the OpenShift groups the user belongs to (excluding the
// implicit ones).
func (g *groupCache) groupsFor(ctx context.Context, user string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if time.Now().After(g.expires) {
		if data, err := g.fetch(ctx); err == nil {
			g.byUser = parseGroups(data)
		}
		// Back off even on error so we don't hammer the API server.
		g.expires = time.Now().Add(g.ttl)
	}
	return g.byUser[user]
}

func parseGroups(data []byte) map[string][]string {
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Users []string `json:"users"`
		} `json:"items"`
	}
	if json.Unmarshal(data, &list) != nil {
		return map[string][]string{}
	}
	m := map[string][]string{}
	for _, grp := range list.Items {
		for _, u := range grp.Users {
			m[u] = append(m[u], grp.Metadata.Name)
		}
	}
	return m
}

// subjectGroups returns the full group set for a SAR: the caller-supplied groups,
// the user's resolved OpenShift groups, and the implicit authenticated groups,
// de-duplicated.
func subjectGroups(passed, resolved []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(gs []string) {
		for _, g := range gs {
			if g != "" && !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
		}
	}
	add(passed)
	add(resolved)
	add(implicitGroups)
	return out
}
