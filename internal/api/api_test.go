package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
)

type fakeLister struct {
	ns  []string
	err error
}

func (f *fakeLister) ListAllowed(_ context.Context, _ authz.Subject, _ authz.Action) ([]string, error) {
	return f.ns, f.err
}

func newServer(l *fakeLister, token string) *httptest.Server {
	h := New(l, nil, authz.Action{}, token, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	h.Routes(mux)
	return httptest.NewServer(mux)
}

func TestNamespacesReturnsAllowed(t *testing.T) {
	srv := newServer(&fakeLister{ns: []string{"team-a", "team-b"}}, "secret")
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/namespaces?user=saman@snapp.cab", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out namespacesResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Namespaces) != 2 || out.Namespaces[0] != "team-a" {
		t.Fatalf("unexpected namespaces: %v", out.Namespaces)
	}
}

func TestBearerTokenEnforced(t *testing.T) {
	srv := newServer(&fakeLister{ns: []string{"team-a"}}, "secret")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/namespaces?user=x") // no token
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}
}

func TestMissingUserIsBadRequest(t *testing.T) {
	srv := newServer(&fakeLister{}, "")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/namespaces")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}
