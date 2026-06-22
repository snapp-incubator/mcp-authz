package bot

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
	"github.com/snapp-incubator/mcp-authz/internal/mattermost"
)

type fakeMM struct {
	email  string
	getErr error
	posted []string
}

func (f *fakeMM) GetUser(_ context.Context, _ string) (mattermost.User, error) {
	return mattermost.User{Email: f.email}, f.getErr
}
func (f *fakeMM) CreatePost(_ context.Context, _, msg string) error {
	f.posted = append(f.posted, msg)
	return nil
}

type fakeDify struct {
	called bool
	gotNS  any
	answer string
}

func (f *fakeDify) Chat(_ context.Context, _, _ string, inputs map[string]any) (string, error) {
	f.called = true
	f.gotNS = inputs["allowed_namespaces"]
	return f.answer, nil
}

type fakeLister struct {
	ns  []string
	err error
}

func (f *fakeLister) ListAllowed(_ context.Context, _ authz.Subject, _ authz.Action) ([]string, error) {
	return f.ns, f.err
}

func newSvc(mm *fakeMM, d *fakeDify, l *fakeLister) *Service {
	return New(mm, d, l, authz.Action{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func post() mattermost.Post {
	return mattermost.Post{UserID: "u1", ChannelID: "c1", Message: "show dropped flows"}
}

func TestUnauthorizedNeverReachesDify(t *testing.T) {
	mm := &fakeMM{email: "nobody@snapp.cab"}
	d := &fakeDify{}
	svc := newSvc(mm, d, &fakeLister{ns: nil}) // no allowed namespaces

	if err := svc.OnPost(context.Background(), post()); err != nil {
		t.Fatalf("OnPost: %v", err)
	}
	if d.called {
		t.Fatal("Dify was called for an unauthorized user")
	}
	if len(mm.posted) != 1 || mm.posted[0] != msgUnauthorized {
		t.Fatalf("expected unauthorized reply, got %v", mm.posted)
	}
}

func TestAuthorizedForwardsScopedToDify(t *testing.T) {
	mm := &fakeMM{email: "saman@snapp.cab"}
	d := &fakeDify{answer: "here are the flows"}
	svc := newSvc(mm, d, &fakeLister{ns: []string{"team-a", "team-b"}})

	if err := svc.OnPost(context.Background(), post()); err != nil {
		t.Fatalf("OnPost: %v", err)
	}
	if !d.called {
		t.Fatal("Dify was not called for an authorized user")
	}
	if d.gotNS != "team-a, team-b" {
		t.Fatalf("allowed_namespaces not passed correctly: %v", d.gotNS)
	}
	if len(mm.posted) != 1 || mm.posted[0] != "here are the flows" {
		t.Fatalf("expected answer reply, got %v", mm.posted)
	}
}

func TestBackendErrorFailsClosed(t *testing.T) {
	mm := &fakeMM{email: "saman@snapp.cab"}
	d := &fakeDify{}
	svc := newSvc(mm, d, &fakeLister{err: errors.New("apiserver down")})

	if err := svc.OnPost(context.Background(), post()); err != nil {
		t.Fatalf("OnPost: %v", err)
	}
	if d.called {
		t.Fatal("Dify was called despite an authorization backend error")
	}
	if len(mm.posted) != 1 || mm.posted[0] != msgBackendError {
		t.Fatalf("expected backend-error reply, got %v", mm.posted)
	}
}
