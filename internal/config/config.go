// Package config loads and validates the mcp-authz configuration.
//
// mcp-authz is the backend for the SnappCloud Mattermost bot. It authenticates
// the chatting user (real SSO identity), decides whether that user is authorized
// for their query, and — only if so — forwards the query to the Dify workflow.
// The config therefore has three concerns: the Mattermost connection, the
// authorization backend, and the Dify workflow endpoint. It knows nothing about
// MCP servers — authorization is a pure "may this user see namespace N?" check.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
)

// Config is the root configuration document.
type Config struct {
	Mattermost Mattermost `yaml:"mattermost"`
	Dify       Dify       `yaml:"dify"`
	Authorizer Authorizer `yaml:"authorizer"`
}

// Mattermost configures the bot's connection to the Mattermost server.
type Mattermost struct {
	// URL is the Mattermost base URL, e.g. https://mattermost.snapp.cab.
	URL string `yaml:"url"`
	// TokenEnv names the env var holding the bot access token (never in YAML).
	TokenEnv string `yaml:"tokenEnv"`
	// IdentityMap optionally maps a Mattermost email to a different OpenShift
	// username. Empty = use the Mattermost email verbatim as the SSO identity.
	IdentityMap map[string]string `yaml:"identityMap"`
}

// Dify configures the workflow the bot forwards authorized queries to.
type Dify struct {
	// URL is the Dify API base, e.g. https://dify.snappcloud.io/v1.
	URL string `yaml:"url"`
	// APIKeyEnv names the env var holding the Dify app API key.
	APIKeyEnv string `yaml:"apiKeyEnv"`
}

// Authorizer selects the decision backend and its options. Reused unchanged from
// the original gateway: the only question asked is "may user X get pods in ns N?"
type Authorizer struct {
	// Provider is one of: kube, static, allow.
	Provider string `yaml:"provider"`
	// CacheTTL caches decisions for this duration (e.g. "30s"). Empty disables.
	CacheTTL string `yaml:"cacheTTL"`
	// Action is the RBAC action checked per namespace.
	Action authz.Action `yaml:"action"`

	Kube   KubeConfig         `yaml:"kube"`
	Static authz.StaticConfig `yaml:"static"`
}

// KubeConfig configures the SubjectAccessReview backend.
type KubeConfig struct {
	Kubeconfig        string `yaml:"kubeconfig"`
	NamespaceSelector string `yaml:"namespaceSelector"`
	ListConcurrency   int    `yaml:"listConcurrency"`
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
	if c.Mattermost.TokenEnv == "" {
		c.Mattermost.TokenEnv = "MATTERMOST_TOKEN"
	}
	if c.Dify.APIKeyEnv == "" {
		c.Dify.APIKeyEnv = "DIFY_API_KEY"
	}
	if c.Authorizer.Provider == "" {
		c.Authorizer.Provider = "kube"
	}
	if c.Authorizer.Action.Verb == "" {
		c.Authorizer.Action.Verb = "get"
	}
	if c.Authorizer.Action.Resource == "" {
		c.Authorizer.Action.Resource = "pods"
	}
}

func (c *Config) validate() error {
	if strings.TrimSpace(c.Mattermost.URL) == "" {
		return fmt.Errorf("mattermost.url is required")
	}
	if strings.TrimSpace(c.Dify.URL) == "" {
		return fmt.Errorf("dify.url is required")
	}
	switch c.Authorizer.Provider {
	case "kube", "static", "allow":
	default:
		return fmt.Errorf("authorizer.provider %q invalid (want kube|static|allow)", c.Authorizer.Provider)
	}
	return nil
}
