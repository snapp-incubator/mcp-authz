// Command mcp-authz is an authorization gateway for MCP servers. It enforces,
// per authenticated user, that MCP tool calls only touch namespaces the user is
// allowed to see — reusing OpenShift RBAC via SubjectAccessReview by default.
package main

import (
	"context"
	"encoding/json"
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
	"github.com/snapp-incubator/mcp-authz/internal/engine"
	"github.com/snapp-incubator/mcp-authz/internal/identity"
	"github.com/snapp-incubator/mcp-authz/internal/proxy"
	"github.com/snapp-incubator/mcp-authz/internal/version"
)

func main() {
	var (
		configPath  string
		addr        string
		mode        string
		logLevel    string
		showVersion bool
	)
	flag.StringVar(&configPath, "config", "/etc/mcp-authz/config.yaml", "Path to config file")
	flag.StringVar(&addr, "addr", ":8080", "HTTP listen address")
	flag.StringVar(&mode, "mode", "both", "Run mode: proxy, api, or both")
	flag.StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn, error")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version.String())
		return
	}

	log := newLogger(logLevel)

	if err := run(configPath, addr, mode, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(configPath, addr, mode string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
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
	log.Info("authorizer ready", "provider", authorizer.Name())

	eng := engine.New(authorizer, cfg.Authorizer.Action)
	ident := identity.New(cfg.Identity)

	mux := http.NewServeMux()
	registerHealth(mux)

	switch mode {
	case "api":
		api.New(eng, cfg.MCPs, ident, log).Routes(mux)
	case "proxy":
		ph, err := proxy.New(cfg.MCPs, eng, ident, cfg.RequireIdentity(), log)
		if err != nil {
			return err
		}
		mux.Handle("/", ph)
	case "both", "":
		api.New(eng, cfg.MCPs, ident, log).Routes(mux)
		ph, err := proxy.New(cfg.MCPs, eng, ident, cfg.RequireIdentity(), log)
		if err != nil {
			return err
		}
		mux.Handle("/", ph)
	default:
		return fmt.Errorf("invalid -mode %q (want proxy|api|both)", mode)
	}

	names := make([]string, 0, len(cfg.MCPs))
	for n := range cfg.MCPs {
		names = append(names, n)
	}
	log.Info("starting mcp-authz",
		"version", version.Version, "addr", addr, "mode", mode,
		"mcps", strings.Join(names, ","), "requireIdentity", cfg.RequireIdentity())

	return serve(addr, mux, log)
}

func registerHealth(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": version.Version})
	})
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
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		if err := hs.Shutdown(shutdownCtx); err != nil {
			log.Error("graceful shutdown", "err", err)
			_ = hs.Close()
		}
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
