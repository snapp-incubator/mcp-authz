package authz

import (
	"context"
	"fmt"
	"sync"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Kube authorizes against live OpenShift/Kubernetes RBAC using
// SubjectAccessReview. This is the recommended backend: it asks the API server
// "can user X do verb V on resource R in namespace N?" and thereby reuses every
// Role/RoleBinding/ClusterRole already governing the cluster. No second source
// of truth to keep in sync — a user sees in an MCP exactly the namespaces they
// see with `oc`.
//
// The mcp-authz ServiceAccount needs `create` on
// authorization.k8s.io/subjectaccessreviews (cluster-scoped) and, for
// ListAllowed, `list` on core/namespaces.
type Kube struct {
	client kubernetes.Interface
	// nsSelector optionally restricts ListAllowed to namespaces matching a
	// label selector (e.g. exclude system namespaces). Empty = all.
	nsSelector string
	// listConcurrency caps parallel SARs during ListAllowed.
	listConcurrency int
}

// KubeOptions configures the Kube backend.
type KubeOptions struct {
	// Kubeconfig path; empty means in-cluster config.
	Kubeconfig string
	// NamespaceSelector limits ListAllowed enumeration (metav1 label selector).
	NamespaceSelector string
	// ListConcurrency bounds parallel checks in ListAllowed (default 16).
	ListConcurrency int
	// QPS/Burst raise the client-go rate limit. ListAllowed issues one SAR per
	// namespace; the default QPS 5 / Burst 10 throttles a multi-hundred-namespace
	// sweep ("Waited ... due to client-side throttling"). Defaults: 50 / 100.
	QPS   float32
	Burst int
}

// NewKube builds a Kube authorizer, using in-cluster config by default.
func NewKube(opts KubeOptions) (*Kube, error) {
	cfg, err := loadRESTConfig(opts.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kube config: %w", err)
	}
	cfg.QPS = opts.QPS
	if cfg.QPS <= 0 {
		cfg.QPS = 50
	}
	cfg.Burst = opts.Burst
	if cfg.Burst <= 0 {
		cfg.Burst = 100
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build kube client: %w", err)
	}
	conc := opts.ListConcurrency
	if conc <= 0 {
		conc = 16
	}
	return &Kube{client: cs, nsSelector: opts.NamespaceSelector, listConcurrency: conc}, nil
}

func loadRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		return rest.InClusterConfig()
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func (k *Kube) Name() string { return "kube" }

func (k *Kube) Authorize(ctx context.Context, sub Subject, act Action, ns string) (Decision, error) {
	act = withDefaults(act)
	sar := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   sub.User,
			Groups: sub.Groups,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: ns,
				Verb:      act.Verb,
				Group:     act.Group,
				Resource:  act.Resource,
			},
		},
	}
	resp, err := k.client.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return deny(ns, "SubjectAccessReview failed"), fmt.Errorf("subjectaccessreview: %w", err)
	}
	if resp.Status.Allowed {
		return allow(ns, fmt.Sprintf("RBAC allows %s on %s/%s", act.Verb, nz(act.Group), act.Resource)), nil
	}
	reason := resp.Status.Reason
	if reason == "" {
		reason = fmt.Sprintf("RBAC denies %s on %s in %q", act.Verb, act.Resource, ns)
	}
	return deny(ns, reason), nil
}

// ListAllowed lists every namespace then runs a SAR per namespace, returning
// those the subject may access. Concurrency-bounded. Best used by the decision
// API, not on the hot path of every MCP call.
func (k *Kube) ListAllowed(ctx context.Context, sub Subject, act Action) ([]string, error) {
	act = withDefaults(act)
	nsList, err := k.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: k.nsSelector})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	var (
		mu       sync.Mutex
		allowed  []string
		wg       sync.WaitGroup
		sem      = make(chan struct{}, k.listConcurrency)
		firstErr error
	)
	for _, ns := range nsList.Items {
		ns := ns
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			d, aerr := k.Authorize(ctx, sub, act, ns.Name)
			mu.Lock()
			defer mu.Unlock()
			if aerr != nil {
				if firstErr == nil {
					firstErr = aerr
				}
				return
			}
			if d.Allowed {
				allowed = append(allowed, ns.Name)
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return allowed, nil
}

func withDefaults(act Action) Action {
	if act.Verb == "" {
		act.Verb = "get"
	}
	if act.Resource == "" {
		act.Resource = "pods"
	}
	return act
}

func nz(group string) string {
	if group == "" {
		return "core"
	}
	return group
}

// compile-time guards
var (
	_ Authorizer      = (*Kube)(nil)
	_ NamespaceLister = (*Kube)(nil)
	_ Authorizer      = (*Static)(nil)
	_ NamespaceLister = (*Static)(nil)
	_ Authorizer      = AllowAll{}
)
