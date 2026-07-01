// Package config loads and validates the mcp-authz configuration.
//
// mcp-authz is the authorization API for the SnappCloud bot. One instance runs
// per cluster and answers, for its OWN cluster (via in-cluster RBAC), "which
// namespaces may this user access?". The bot calls every region's instance and
// aggregates the answers — so mcp-authz needs no kubeconfigs and no knowledge of
// other clusters, Mattermost, Dify, or MCP servers.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
)

// Config is the root configuration document.
type Config struct {
	Server     Server     `yaml:"server"`
	Authorizer Authorizer `yaml:"authorizer"`
}

// Server configures the HTTP API.
type Server struct {
	// AuthTokenEnv names the env var holding a bearer token the caller (the bot)
	// must present. Empty disables auth (rely on network policy only).
	AuthTokenEnv string `yaml:"authTokenEnv"`
}

// Authorizer selects the decision backend and its options. The only question
// asked is "may user X get pods in namespace N?" on this cluster.
type Authorizer struct {
	// Provider is one of: kube, static.
	Provider string `yaml:"provider"`
	// Action is the RBAC action checked per namespace.
	Action authz.Action `yaml:"action"`
	// NamespaceSelector optionally limits which namespaces are enumerated.
	NamespaceSelector string `yaml:"namespaceSelector"`
	// ListConcurrency bounds parallel SARs during enumeration (default 16).
	ListConcurrency int `yaml:"listConcurrency"`
	// QPS/Burst raise the client-go rate limit so a many-namespace SAR sweep is
	// not throttled. 0 = defaults (50 / 100).
	QPS   float32 `yaml:"qps"`
	Burst int     `yaml:"burst"`
	// Static is used only when provider: static.
	Static authz.StaticConfig `yaml:"static"`
}

// Load reads, parses, defaults, and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Server.AuthTokenEnv == "" {
		c.Server.AuthTokenEnv = "AUTH_TOKEN"
	}
	if c.Authorizer.Provider == "" {
		c.Authorizer.Provider = "kube"
	}
	if c.Authorizer.ListConcurrency <= 0 {
		c.Authorizer.ListConcurrency = 16
	}
	if c.Authorizer.Action.Verb == "" {
		c.Authorizer.Action.Verb = "get"
	}
	if c.Authorizer.Action.Resource == "" {
		c.Authorizer.Action.Resource = "pods"
	}
}

func (c *Config) validate() error {
	switch c.Authorizer.Provider {
	case "kube", "static":
	default:
		return fmt.Errorf("authorizer.provider %q invalid (want kube|static)", c.Authorizer.Provider)
	}
	return nil
}
