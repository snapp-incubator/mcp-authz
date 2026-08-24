package authz

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestParseGroups(t *testing.T) {
	data := []byte(`{"items":[
	  {"metadata":{"name":"team-a"},"users":["saman","ali"]},
	  {"metadata":{"name":"platform"},"users":["saman"]}]}`)
	m := parseGroups(data)
	if !reflect.DeepEqual(m["saman"], []string{"team-a", "platform"}) {
		t.Fatalf("saman groups: %v", m["saman"])
	}
	if !reflect.DeepEqual(m["ali"], []string{"team-a"}) {
		t.Fatalf("ali groups: %v", m["ali"])
	}
}

func TestSubjectGroupsMergesAndIncludesImplicit(t *testing.T) {
	got := subjectGroups("alice@x", []string{"x"}, []string{"team-a", "x"})
	want := []string{"x", "team-a", "system:authenticated", "system:authenticated:oauth"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestGroupCacheResolvesAndCaches(t *testing.T) {
	calls := 0
	gc := newGroupCache(func(context.Context) ([]byte, error) {
		calls++
		return []byte(`{"items":[{"metadata":{"name":"team-a"},"users":["saman"]}]}`), nil
	}, time.Minute)
	for i := 0; i < 3; i++ {
		if g := gc.groupsFor(context.Background(), "saman"); !reflect.DeepEqual(g, []string{"team-a"}) {
			t.Fatalf("groups: %v", g)
		}
	}
	if calls != 1 {
		t.Fatalf("expected 1 fetch within TTL, got %d", calls)
	}
}

func TestSubjectGroupsHumanGetsResolvedAndImplicit(t *testing.T) {
	got := subjectGroups("alice@snapp.cab", []string{"passed"}, []string{"team-a"})
	want := map[string]bool{"passed": true, "team-a": true,
		"system:authenticated": true, "system:authenticated:oauth": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected group %q in %v", g, got)
		}
	}
}

// A ServiceAccount must NOT inherit the human implicit groups: claiming
// system:authenticated:oauth would grant access the API server would refuse.
func TestSubjectGroupsServiceAccountTrustsOnlyTokenReviewGroups(t *testing.T) {
	got := subjectGroups(
		"system:serviceaccount:team-a:ci",
		[]string{"system:serviceaccounts", "system:serviceaccounts:team-a", "system:authenticated"},
		[]string{"should-not-appear"},
	)
	for _, g := range got {
		if g == "system:authenticated:oauth" || g == "should-not-appear" {
			t.Fatalf("service account must not gain %q (groups: %v)", g, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected only the TokenReview groups, got %v", got)
	}
}

func TestIsServiceAccount(t *testing.T) {
	if !IsServiceAccount("system:serviceaccount:ns:name") {
		t.Fatal("SA username not detected")
	}
	if IsServiceAccount("alice@snapp.cab") {
		t.Fatal("human username misdetected as SA")
	}
}
