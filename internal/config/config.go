// Package config loads and validates the mcp-authz configuration. The config
// is the single place that encodes how to extract identity, which backend to
// authorize against, and — per MCP server — how to discover which namespaces a
// tool call touches. Adding a new MCP server is a config change, not a code
// change, which is what keeps the enforcement engine reusable.
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
	// Identity controls how the caller's identity is extracted from requests.
	Identity Identity `yaml:"identity"`
	// Authorizer selects and configures the decision backend.
	Authorizer Authorizer `yaml:"authorizer"`
	// MCPs registers the upstream MCP servers to protect, keyed by name.
	MCPs map[string]MCP `yaml:"mcps"`
}

// Identity describes where to read the authenticated user and groups from.
// In SnappCloud an upstream auth proxy injects these headers; mcp-authz trusts
// them and must therefore only be reachable through that proxy.
type Identity struct {
	// UserHeaders are tried in order; first non-empty wins.
	UserHeaders []string `yaml:"userHeaders"`
	// GroupsHeader carries a delimited list of groups (optional).
	GroupsHeader string `yaml:"groupsHeader"`
	// GroupsDelimiter splits GroupsHeader (default ",").
	GroupsDelimiter string `yaml:"groupsDelimiter"`
	// Required rejects requests without an identity (default true). When false
	// an anonymous request yields an empty subject and is denied by the
	// backend, which is still fail-closed but returns a 403 not a 401.
	Required *bool `yaml:"required"`
}

// Authorizer selects the decision backend and its options.
type Authorizer struct {
	// Provider is one of: kube, static, allow.
	Provider string `yaml:"provider"`
	// CacheTTL caches decisions for this duration (e.g. "30s"). Empty disables.
	CacheTTL string `yaml:"cacheTTL"`
	// Action is the default RBAC action checked per namespace.
	Action authz.Action `yaml:"action"`

	Kube   KubeConfig          `yaml:"kube"`
	Static authz.StaticConfig  `yaml:"static"`
}

// KubeConfig configures the SubjectAccessReview backend.
type KubeConfig struct {
	Kubeconfig        string `yaml:"kubeconfig"`
	NamespaceSelector string `yaml:"namespaceSelector"`
	ListConcurrency   int    `yaml:"listConcurrency"`
}

// MCP describes one protected upstream MCP server.
type MCP struct {
	// Upstream is the base URL of the real MCP server (e.g.
	// http://cilium-hubble-mcp-svc:8080).
	Upstream string `yaml:"upstream"`
	// Action overrides the global Action for this MCP (optional). This lets a
	// read-only flow MCP check "get pods" while another checks something else.
	Action *authz.Action `yaml:"action"`
	// Tools maps tool name -> extraction rules. The key "*" is the default
	// applied to any tool without an explicit entry.
	Tools map[string]Tool `yaml:"tools"`
}

// Tool declares how to find the namespaces referenced by a single MCP tool
// call and whether an unscoped call is permitted.
type Tool struct {
	// NamespaceArgs lists the tool arguments that carry a namespace.
	NamespaceArgs []NamespaceArg `yaml:"namespaceArgs"`
	// RequireNamespace denies the call when no namespace could be extracted
	// (i.e. cluster-wide queries). Default true: unscoped == deny.
	RequireNamespace *bool `yaml:"requireNamespace"`
	// Public skips authorization entirely for this tool (e.g. server_status,
	// get_namespaces). Use sparingly.
	Public bool `yaml:"public"`
}

// NamespaceArg points at one tool argument and says how to read a namespace
// out of its value.
type NamespaceArg struct {
	// Key is the argument name in the tool call (e.g. "namespace", "source_pod").
	Key string `yaml:"key"`
	// Format is how to parse the value:
	//   "plain" — the value is the namespace itself.
	//   "slash" — the value is "namespace/name"; take the part before "/".
	//             If there is no "/", the namespace is unknown (treated as
	//             cluster-wide for that arg).
	Format string `yaml:"format"`
}

const (
	FormatPlain = "plain"
	FormatSlash = "slash"
)

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
	if len(c.Identity.UserHeaders) == 0 {
		// SnappCloud auth-proxy defaults; override per cluster as needed.
		c.Identity.UserHeaders = []string{"X-Forwarded-Email", "X-Forwarded-User", "X-Auth-Request-Email", "X-Remote-User"}
	}
	if c.Identity.GroupsHeader == "" {
		c.Identity.GroupsHeader = "X-Forwarded-Groups"
	}
	if c.Identity.GroupsDelimiter == "" {
		c.Identity.GroupsDelimiter = ","
	}
	if c.Identity.Required == nil {
		c.Identity.Required = boolPtr(true)
	}
	if c.Authorizer.Provider == "" {
		c.Authorizer.Provider = "kube"
	}
}

func (c *Config) validate() error {
	switch c.Authorizer.Provider {
	case "kube", "static", "allow":
	default:
		return fmt.Errorf("authorizer.provider %q invalid (want kube|static|allow)", c.Authorizer.Provider)
	}
	if len(c.MCPs) == 0 {
		return fmt.Errorf("at least one mcp must be configured under mcps:")
	}
	for name, m := range c.MCPs {
		if strings.TrimSpace(m.Upstream) == "" {
			return fmt.Errorf("mcp %q: upstream is required", name)
		}
		for tname, t := range m.Tools {
			for _, na := range t.NamespaceArgs {
				if na.Key == "" {
					return fmt.Errorf("mcp %q tool %q: namespaceArg.key is empty", name, tname)
				}
				switch na.Format {
				case FormatPlain, FormatSlash, "":
				default:
					return fmt.Errorf("mcp %q tool %q key %q: format %q invalid (want plain|slash)", name, tname, na.Key, na.Format)
				}
			}
		}
	}
	return nil
}

// RequireIdentity reports whether anonymous requests must be rejected.
func (c *Config) RequireIdentity() bool { return c.Identity.Required != nil && *c.Identity.Required }

func boolPtr(b bool) *bool { return &b }
