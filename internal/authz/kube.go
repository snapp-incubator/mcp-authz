package authz

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	// groups resolves a user's OpenShift group memberships for the SAR.
	groups *groupCache
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
	// sweep ("Waited ... due to client-side throttling"). Defaults: 100 / 200.
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
		cfg.QPS = 100
	}
	cfg.Burst = opts.Burst
	if cfg.Burst <= 0 {
		cfg.Burst = 200
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build kube client: %w", err)
	}
	conc := opts.ListConcurrency
	if conc <= 0 {
		conc = 16
	}
	// Resolve OpenShift groups via the raw API path (no openshift client dep).
	gc := newGroupCache(func(ctx context.Context) ([]byte, error) {
		return cs.CoreV1().RESTClient().Get().AbsPath("/apis/user.openshift.io/v1/groups").DoRaw(ctx)
	}, 5*time.Minute)
	return &Kube{client: cs, nsSelector: opts.NamespaceSelector, listConcurrency: conc, groups: gc}, nil
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
	var resolved []string
	if k.groups != nil {
		resolved = k.groups.groupsFor(ctx, sub.User)
	}
	sar := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   sub.User,
			Groups: subjectGroups(sub.Groups, resolved),
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

	// Fast path: if the subject can perform the action CLUSTER-WIDE (a
	// cluster-admin, or anyone with a cluster-scoped RoleBinding for it), grant
	// every namespace and skip the per-namespace sweep. A SAR with an empty
	// namespace checks cluster scope. This both fixes cluster-admins (who the
	// per-namespace sweep can miss) and is far cheaper (one SAR, not hundreds).
	if d, err := k.Authorize(ctx, sub, act, ""); err == nil && d.Allowed {
		all := make([]string, 0, len(nsList.Items))
		for _, ns := range nsList.Items {
			all = append(all, ns.Name)
		}
		return all, nil
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

// ResolveNamespaces maps each resource ref to the namespace(s) it lives in,
// using in-cluster reads. Fail-closed: an API error aborts the whole resolve.
func (k *Kube) ResolveNamespaces(ctx context.Context, refs []ResourceRef) (map[string][]string, error) {
	out := make(map[string][]string, len(refs))
	for _, ref := range refs {
		ns, err := k.resolveOne(ctx, ref)
		if err != nil {
			return nil, err
		}
		if len(ns) > 0 {
			out[ref.Value] = ns
		}
	}
	return out, nil
}

func (k *Kube) resolveOne(ctx context.Context, ref ResourceRef) ([]string, error) {
	switch ref.Kind {
	case "namespace":
		return []string{ref.Value}, nil
	case "pod":
		return k.podNamespaces(ctx, "metadata.name="+ref.Value)
	case "ip":
		return k.podNamespaces(ctx, "status.podIP="+ref.Value)
	case "service":
		svcs, err := k.client.CoreV1().Services(metav1.NamespaceAll).List(ctx,
			metav1.ListOptions{FieldSelector: "metadata.name=" + ref.Value})
		if err != nil {
			return nil, fmt.Errorf("resolve service %q: %w", ref.Value, err)
		}
		ns := make([]string, 0, len(svcs.Items))
		for _, s := range svcs.Items {
			ns = append(ns, s.Namespace)
		}
		return uniqueNamespaces(ns), nil
	default:
		return nil, nil
	}
}

func uniqueNamespaces(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range in {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func (k *Kube) podNamespaces(ctx context.Context, fieldSelector string) ([]string, error) {
	pods, err := k.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx,
		metav1.ListOptions{FieldSelector: fieldSelector})
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", fieldSelector, err)
	}
	ns := make([]string, 0, len(pods.Items))
	for _, p := range pods.Items {
		ns = append(ns, p.Namespace)
	}
	return uniqueNamespaces(ns), nil
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
