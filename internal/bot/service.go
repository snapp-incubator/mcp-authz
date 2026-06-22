// Package bot is the orchestration core of the SnappCloud Bot backend. For each
// incoming Mattermost message it: resolves the user's real SSO identity, asks
// the authorizer which namespaces that user may access, and — only if the user
// is authorized — forwards the query to the Dify workflow with that namespace
// scope, then posts the answer back. An unauthorized user never reaches Dify.
package bot

import (
	"context"
	"log/slog"
	"strings"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
	"github.com/snapp-incubator/mcp-authz/internal/mattermost"
)

// difyClient is the subset of the Dify client the bot uses (eases testing).
type difyClient interface {
	Chat(ctx context.Context, user, query string, inputs map[string]any) (string, error)
}

// mmClient is the subset of the Mattermost client the bot uses.
type mmClient interface {
	GetUser(ctx context.Context, userID string) (mattermost.User, error)
	CreatePost(ctx context.Context, channelID, message string) error
}

// Service ties identity, authorization, and the Dify workflow together.
type Service struct {
	mm          mmClient
	dify        difyClient
	lister      authz.NamespaceLister
	action      authz.Action
	identityMap map[string]string
	log         *slog.Logger
}

// New builds the orchestration service.
func New(mm mmClient, d difyClient, lister authz.NamespaceLister, action authz.Action, identityMap map[string]string, log *slog.Logger) *Service {
	return &Service{mm: mm, dify: d, lister: lister, action: action, identityMap: identityMap, log: log}
}

const (
	msgUnauthorized = "You are not authorized: you have no namespaces you can query. Contact your cluster admin if this is unexpected."
	msgBackendError = "Authorization is temporarily unavailable. Please try again shortly."
	msgDifyError    = "Sorry — I couldn't complete that request. Please try again."
)

// OnPost handles one incoming Mattermost post. Errors returned here are logged
// by the listener; user-facing failures are also posted back to the channel.
func (s *Service) OnPost(ctx context.Context, p mattermost.Post) error {
	query := strings.TrimSpace(p.Message)
	if query == "" {
		return nil
	}

	// 1. Resolve the authenticated SSO identity.
	user, err := s.mm.GetUser(ctx, p.UserID)
	if err != nil {
		return err // can't identify the user; do not answer
	}
	identity := s.resolveIdentity(user.Email)
	if identity == "" {
		s.reply(ctx, p.ChannelID, msgUnauthorized)
		return nil
	}

	// 2. Authorize: which namespaces may this user query?
	sub := authz.Subject{User: identity}
	namespaces, err := s.lister.ListAllowed(ctx, sub, s.action)
	if err != nil {
		s.log.Error("authorize", "user", identity, "err", err)
		s.reply(ctx, p.ChannelID, msgBackendError)
		return nil
	}
	if len(namespaces) == 0 {
		s.log.Info("denied", "user", identity, "reason", "no allowed namespaces")
		s.reply(ctx, p.ChannelID, msgUnauthorized)
		return nil
	}
	s.log.Info("authorized", "user", identity, "namespaces", len(namespaces))

	// 3. Authorized — forward to the Dify workflow, scoped to those namespaces.
	answer, err := s.dify.Chat(ctx, identity, query, map[string]any{
		"allowed_namespaces": strings.Join(namespaces, ", "),
	})
	if err != nil {
		s.log.Error("dify", "user", identity, "err", err)
		s.reply(ctx, p.ChannelID, msgDifyError)
		return nil
	}
	s.reply(ctx, p.ChannelID, answer)
	return nil
}

// resolveIdentity maps a Mattermost email to the OpenShift username used for
// RBAC. Default is identity (email == username); identityMap overrides.
func (s *Service) resolveIdentity(email string) string {
	email = strings.TrimSpace(email)
	if mapped, ok := s.identityMap[email]; ok {
		return mapped
	}
	return email
}

func (s *Service) reply(ctx context.Context, channelID, msg string) {
	if err := s.mm.CreatePost(ctx, channelID, msg); err != nil {
		s.log.Error("post reply", "channel", channelID, "err", err)
	}
}
