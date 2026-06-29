// Package scopetoken signs and verifies a short-lived, HMAC-signed token that
// carries a user's per-cluster authorized namespaces. The bot mints it (it knows
// the identity + scope); the MCP gateway verifies it and enforces, so an agent
// can never query a namespace outside the token — no LLM, no trust in the prompt.
//
// Format: base64url(payloadJSON) + "." + base64url(HMAC-SHA256(secret, payloadJSON)).
package scopetoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Scope maps cluster name -> authorized namespaces.
type Scope map[string][]string

// Claims is the token payload.
type Claims struct {
	User  string `json:"u"`
	Scope Scope  `json:"s"`
	Exp   int64  `json:"exp"` // unix seconds
}

var (
	ErrMalformed = errors.New("scope token malformed")
	ErrSignature = errors.New("scope token signature invalid")
	ErrExpired   = errors.New("scope token expired")
)

// Sign produces a token for the claims, signed with secret.
func Sign(c Claims, secret string) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := mac(payload, secret)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify checks the signature and expiry and returns the claims.
func Verify(token, secret string) (*Claims, error) {
	p, s, ok := strings.Cut(token, ".")
	if !ok {
		return nil, ErrMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return nil, fmt.Errorf("%w: payload", ErrMalformed)
	}
	sig, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: signature", ErrMalformed)
	}
	if !hmac.Equal(sig, mac(payload, secret)) {
		return nil, ErrSignature
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: json", ErrMalformed)
	}
	if time.Now().Unix() > c.Exp {
		return nil, ErrExpired
	}
	return &c, nil
}

func mac(payload []byte, secret string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(payload)
	return m.Sum(nil)
}
