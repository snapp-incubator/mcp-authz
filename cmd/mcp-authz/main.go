// Command mcp-authz is the backend for the SnappCloud Mattermost bot. It listens
// for messages over the Mattermost WebSocket, authenticates the user via their
// real SSO identity, checks whether they are authorized for their query (reusing
// OpenShift RBAC via SubjectAccessReview), and only then forwards the query to
// the Dify workflow. It knows nothing about MCP servers — authorization is a
// pure "may this user see this namespace?" decision.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/snapp-incubator/mcp-authz/internal/authz"
	"github.com/snapp-incubator/mcp-authz/internal/bot"
	"github.com/snapp-incubator/mcp-authz/internal/config"
	"github.com/snapp-incubator/mcp-authz/internal/dify"
	"github.com/snapp-incubator/mcp-authz/internal/mattermost"
	"github.com/snapp-incubator/mcp-authz/internal/version"
)

func main() {
	var (
		configPath  string
		addr        string
		logLevel    string
		showVersion bool
	)
	flag.StringVar(&configPath, "config", "/etc/mcp-authz/config.yaml", "Path to config file")
	flag.StringVar(&addr, "addr", ":8080", "Health/readiness HTTP listen address")
	flag.StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn, error")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version.String())
		return
	}

	log := newLogger(logLevel)
	if err := run(configPath, addr, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(configPath, addr string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	mmToken := os.Getenv(cfg.Mattermost.TokenEnv)
	if mmToken == "" {
		return fmt.Errorf("mattermost token env %q is empty", cfg.Mattermost.TokenEnv)
	}
	difyKey := os.Getenv(cfg.Dify.APIKeyEnv)
	if difyKey == "" {
		return fmt.Errorf("dify api key env %q is empty", cfg.Dify.APIKeyEnv)
	}

	authorizer, err := authz.Build(authz.BuildOptions{
		Provider:              cfg.Authorizer.Provider,
		CacheTTL:              cfg.Authorizer.CacheTTL,
		Kubeconfig:            cfg.Authorizer.Kube.Kubeconfig,
		KubeNamespaceSelector: cfg.Authorizer.Kube.NamespaceSelector,
		KubeListConcurrency:   cfg.Authorizer.Kube.ListConcurrency,
		Static:                cfg.Authorizer.Static,
	})
	if err != nil {
		return fmt.Errorf("build authorizer: %w", err)
	}
	lister, ok := authorizer.(authz.NamespaceLister)
	if !ok {
		return fmt.Errorf("authorizer %q cannot list namespaces; the bot needs a backend that enumerates a user's namespaces (kube or static)", authorizer.Name())
	}
	log.Info("authorizer ready", "provider", authorizer.Name())

	mm := mattermost.NewClient(cfg.Mattermost.URL, mmToken)
	difyClient := dify.NewClient(cfg.Dify.URL, difyKey)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	me, err := mm.Me(ctx)
	if err != nil {
		return fmt.Errorf("mattermost auth (check token/url): %w", err)
	}
	log.Info("connected to mattermost", "bot", me.Username, "id", me.ID)

	svc := bot.New(mm, difyClient, lister, cfg.Authorizer.Action, cfg.Mattermost.IdentityMap, log)

	// Health server for k8s probes (the bot itself runs over the WebSocket).
	go serveHealth(ctx, addr, log)

	log.Info("starting SnappCloud bot",
		"version", version.Version, "mattermost", cfg.Mattermost.URL, "dify", cfg.Dify.URL)
	mm.Listen(ctx, me.ID, svc.OnPost, log)
	log.Info("shut down")
	return nil
}

func serveHealth(ctx context.Context, addr string, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	hs := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = hs.Shutdown(sctx)
	}()
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("health server", "err", err)
	}
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}
