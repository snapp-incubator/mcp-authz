package authz

import (
	"context"
	"sync"
	"time"
)

// Cached wraps an Authorizer with a TTL cache keyed by subject+action+namespace.
// SubjectAccessReview is an API-server round trip; an MCP "show me flows across
// 5 namespaces" call would otherwise issue 5 SARs every time. A short TTL keeps
// decisions fresh against RBAC changes while collapsing repeated checks.
//
// Only positive and negative decisions are cached, not errors (errors are
// fail-closed and must be retried).
type Cached struct {
	inner Authorizer
	ttl   time.Duration

	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	decision Decision
	expires  time.Time
}

// NewCached wraps inner with a cache of the given TTL. A non-positive TTL
// disables caching and returns inner unchanged.
func NewCached(inner Authorizer, ttl time.Duration) Authorizer {
	if ttl <= 0 {
		return inner
	}
	return &Cached{inner: inner, ttl: ttl, entries: map[string]cacheEntry{}}
}

func (c *Cached) Name() string { return c.inner.Name() + "+cache" }

func (c *Cached) Authorize(ctx context.Context, sub Subject, act Action, ns string) (Decision, error) {
	key := cacheKey(sub, act, ns)

	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if ok && time.Now().Before(e.expires) {
		return e.decision, nil
	}

	d, err := c.inner.Authorize(ctx, sub, act, ns)
	if err != nil {
		return d, err
	}

	c.mu.Lock()
	c.entries[key] = cacheEntry{decision: d, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return d, nil
}

// ListAllowed is delegated when the inner backend supports it; results are not
// cached (listing is an API-side operation used off the hot path).
func (c *Cached) ListAllowed(ctx context.Context, sub Subject, act Action) ([]string, error) {
	if l, ok := c.inner.(NamespaceLister); ok {
		return l.ListAllowed(ctx, sub, act)
	}
	return nil, ErrListUnsupported
}

func cacheKey(sub Subject, act Action, ns string) string {
	// Groups affect the decision; include them deterministically. Subject
	// groups arrive in a stable order from the identity layer.
	g := ""
	for _, x := range sub.Groups {
		g += x + ","
	}
	return sub.User + "|" + g + "|" + act.Verb + "|" + act.Group + "|" + act.Resource + "|" + ns
}
