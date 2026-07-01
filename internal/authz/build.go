package authz

import "fmt"

// BuildOptions configures the single-cluster authorizer this instance runs.
type BuildOptions struct {
	// Provider: kube | static.
	Provider          string
	NamespaceSelector string
	ListConcurrency   int
	QPS               float32
	Burst             int
	// Static is used only when Provider == static.
	Static StaticConfig
}

// Build constructs the configured authorizer for the local cluster. It must
// implement NamespaceLister (the API enumerates a user's namespaces).
func Build(o BuildOptions) (NamespaceLister, error) {
	switch o.Provider {
	case "kube", "":
		return NewKube(KubeOptions{
			NamespaceSelector: o.NamespaceSelector,
			ListConcurrency:   o.ListConcurrency,
			QPS:               o.QPS,
			Burst:             o.Burst,
		})
	case "static":
		return NewStatic(o.Static), nil
	default:
		return nil, fmt.Errorf("authorizer.provider %q invalid (want kube|static)", o.Provider)
	}
}
