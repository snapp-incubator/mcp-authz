// Command mcp-authz is the authorization API for the SnappCloud bot. One
// instance runs per cluster. It answers, for its OWN cluster via in-cluster
// RBAC (SubjectAccessReview), which namespaces a user may access. The bot calls
// every region's instance and aggregates — so this service needs no kubeconfigs
// and knows nothing of Mattermost, Dify, or MCP servers.
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

	"github.com/snapp-incubator/mcp-authz/internal/api"
	"github.com/snapp-incubator/mcp-authz/internal/authz"
	"github.com/snapp-incubator/mcp-authz/internal/config"
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
	flag.StringVar(&addr, "addr", ":8080", "HTTP listen address")
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

	lister, err := authz.Build(authz.BuildOptions{
		Provider:          cfg.Authorizer.Provider,
		NamespaceSelector: cfg.Authorizer.NamespaceSelector,
		ListConcurrency:   cfg.Authorizer.ListConcurrency,
		QPS:               cfg.Authorizer.QPS,
		Burst:             cfg.Authorizer.Burst,
		Static:            cfg.Authorizer.Static,
	})
	if err != nil {
		return fmt.Errorf("build authorizer: %w", err)
	}

	token := os.Getenv(cfg.Server.AuthTokenEnv)
	if token == "" {
		log.Warn("no auth token set; the API is unauthenticated (rely on NetworkPolicy)", "env", cfg.Server.AuthTokenEnv)
	}

	// Resolver is optional: only backends that can map resources -> namespaces
	// (the kube backend) enable /v1/resolve.
	resolver, _ := lister.(authz.NamespaceResolver)

	mux := http.NewServeMux()
	registerHealth(mux)
	api.New(lister, resolver, cfg.Authorizer.Action, token, log).Routes(mux)

	log.Info("starting mcp-authz authorization API",
		"version", version.Version, "addr", addr, "provider", cfg.Authorizer.Provider, "authRequired", token != "")
	return serve(addr, mux, log)
}

func registerHealth(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func serve(addr string, handler http.Handler, log *slog.Logger) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	hs := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = hs.Shutdown(sctx)
	}()
	log.Info("listening", "addr", addr)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
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
