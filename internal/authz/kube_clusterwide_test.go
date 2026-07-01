package authz

import (
	"context"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// clusterAdmin: SAR always allowed → ListAllowed returns every namespace via the
// cluster-wide fast path (one SAR).
func TestListAllowedClusterWideFastPath(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-operators"}},
	)
	var sarCount int
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sarCount++
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: true}}, nil
	})
	k := &Kube{client: cs, listConcurrency: 4}

	got, err := k.ListAllowed(context.Background(), Subject{User: "admin@x"}, Action{Verb: "get", Resource: "pods"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("admin should see all namespaces, got %v", got)
	}
	if sarCount != 1 {
		t.Fatalf("cluster-wide fast path should use exactly 1 SAR, used %d", sarCount)
	}
}
