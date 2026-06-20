// Package identity extracts the authenticated Subject from an HTTP request.
//
// mcp-authz does not authenticate users itself — an upstream auth proxy already
// did that and forwards the result in trusted headers. This package only reads
// those headers. The deployment must guarantee mcp-authz is not reachable
// except through that proxy, or callers could spoof identity headers.
package identity

import (
	"net/http"
	"strings"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
	"github.com/snapp-incubator/mcp-authz/internal/config"
)

// Extractor reads identity headers per the configured Identity rules.
type Extractor struct {
	userHeaders  []string
	groupsHeader string
	delimiter    string
}

// New builds an Extractor from config.Identity.
func New(cfg config.Identity) *Extractor {
	return &Extractor{
		userHeaders:  cfg.UserHeaders,
		groupsHeader: cfg.GroupsHeader,
		delimiter:    cfg.GroupsDelimiter,
	}
}

// Extract returns the Subject and whether an identity was present at all.
func (e *Extractor) Extract(r *http.Request) (authz.Subject, bool) {
	var user string
	for _, h := range e.userHeaders {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			user = v
			break
		}
	}
	if user == "" {
		return authz.Subject{}, false
	}

	var groups []string
	if e.groupsHeader != "" {
		if raw := r.Header.Get(e.groupsHeader); raw != "" {
			for _, g := range strings.Split(raw, e.delimiter) {
				if g = strings.TrimSpace(g); g != "" {
					groups = append(groups, g)
				}
			}
		}
	}
	return authz.Subject{User: user, Groups: groups}, true
}
