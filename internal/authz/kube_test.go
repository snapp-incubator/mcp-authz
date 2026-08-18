package authz

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolveIPsBulk(t *testing.T) {
	pods := []runtime.Object{
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "team-a"},
			Status: corev1.PodStatus{PodIP: "10.0.0.1", PodIPs: []corev1.PodIP{{IP: "10.0.0.1"}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "team-b"},
			Status: corev1.PodStatus{PodIP: "10.0.0.2", PodIPs: []corev1.PodIP{{IP: "10.0.0.2"}}}},
	}
	k := &Kube{client: fake.NewSimpleClientset(pods...), listConcurrency: 4}

	// > bulkIPThreshold forces the bulk path; include unknown IPs (unresolved).
	refs := make([]ResourceRef, 0, bulkIPThreshold+3)
	refs = append(refs, ResourceRef{Kind: "ip", Value: "10.0.0.1"}, ResourceRef{Kind: "ip", Value: "10.0.0.2"})
	for i := 0; i < bulkIPThreshold+1; i++ {
		refs = append(refs, ResourceRef{Kind: "ip", Value: fmt.Sprintf("172.30.9.%d", i)})
	}
	out, err := k.ResolveNamespaces(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	if got := out["10.0.0.1"]; len(got) != 1 || got[0] != "team-a" {
		t.Fatalf("10.0.0.1 -> %v, want [team-a]", got)
	}
	if got := out["10.0.0.2"]; len(got) != 1 || got[0] != "team-b" {
		t.Fatalf("10.0.0.2 -> %v, want [team-b]", got)
	}
	if _, ok := out["172.30.9.0"]; ok {
		t.Fatal("unknown IP should not resolve")
	}
}
