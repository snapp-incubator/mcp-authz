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
	got := subjectGroups([]string{"x"}, []string{"team-a", "x"})
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
