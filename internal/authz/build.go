package authz

import (
	"fmt"
	"time"
)

// BuildOptions carries the bits of config the authz package needs to construct
// a backend without importing the config package (avoids an import cycle).
type BuildOptions struct {
	Provider string
	CacheTTL string

	// Kube backend.
	Kubeconfig            string
	KubeNamespaceSelector string
	KubeListConcurrency   int

	// Static backend.
	Static StaticConfig
}

// Build constructs the configured Authorizer, wrapped in a decision cache when
// a TTL is set.
func Build(o BuildOptions) (Authorizer, error) {
	var base Authorizer
	switch o.Provider {
	case "kube", "":
		k, err := NewKube(KubeOptions{
			Kubeconfig:        o.Kubeconfig,
			NamespaceSelector: o.KubeNamespaceSelector,
			ListConcurrency:   o.KubeListConcurrency,
		})
		if err != nil {
			return nil, err
		}
		base = k
	case "static":
		base = NewStatic(o.Static)
	case "allow":
		base = AllowAll{}
	default:
		return nil, fmt.Errorf("unknown authz provider %q", o.Provider)
	}

	if o.CacheTTL != "" {
		ttl, err := time.ParseDuration(o.CacheTTL)
		if err != nil {
			return nil, fmt.Errorf("parse authorizer.cacheTTL: %w", err)
		}
		base = NewCached(base, ttl)
	}
	return base, nil
}
