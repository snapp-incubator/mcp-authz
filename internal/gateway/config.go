// Package gateway is the MCP-layer enforcement proxy: a transparent reverse
// proxy in front of ONE MCP server (one cluster). For every tools/call it
// extracts the referenced namespaces and authorizes them against the user's
// signed scope token, blocking unauthorized calls before they reach the MCP
// server. The MCP server is unchanged; the agent cannot bypass it.
package gateway

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/snapp-incubator/mcp-authz/internal/mcpwire"
)

// Config is the gateway configuration.
type Config struct {
	// Cluster is this gateway's cluster name. It must match a key in the scope
	// token (e.g. okd4-ts-2): the gateway authorizes against scope[cluster].
	Cluster string `yaml:"cluster"`
	// Upstream is the real MCP server base URL.
	Upstream string `yaml:"upstream"`
	// TokenHeader carries the signed scope token (default X-Scope-Token).
	TokenHeader string `yaml:"tokenHeader"`
	// TokenSecretEnv names the env var with the HMAC secret shared with the bot.
	TokenSecretEnv string `yaml:"tokenSecretEnv"`
	// Required: reject tools/call with no/invalid token (default true, fail-closed).
	Required *bool `yaml:"required"`
	// Tools maps tool name -> extraction rule; "*" is the default.
	Tools map[string]mcpwire.Tool `yaml:"tools"`
}

// Load reads, defaults, and validates the config.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.TokenHeader == "" {
		c.TokenHeader = "X-Scope-Token"
	}
	if c.TokenSecretEnv == "" {
		c.TokenSecretEnv = "SCOPE_TOKEN_SECRET"
	}
	if strings.TrimSpace(c.Cluster) == "" {
		return nil, fmt.Errorf("cluster is required")
	}
	if strings.TrimSpace(c.Upstream) == "" {
		return nil, fmt.Errorf("upstream is required")
	}
	return &c, nil
}

// RequireToken reports whether a missing/invalid token denies (default true).
func (c *Config) RequireToken() bool { return c.Required == nil || *c.Required }

// ToolRule resolves the rule for a tool, falling back to "*".
func (c *Config) ToolRule(tool string) (mcpwire.Tool, bool) {
	if t, ok := c.Tools[tool]; ok {
		return t, true
	}
	if t, ok := c.Tools["*"]; ok {
		return t, true
	}
	return mcpwire.Tool{}, false
}
