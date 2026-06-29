// Command mcp-gateway is the MCP-layer enforcement proxy. One instance runs in
// front of one MCP server (one cluster). It parses each tools/call, extracts the
// referenced namespaces, and authorizes them against the user's signed scope
// token (minted by the bot). Unauthorized calls are rejected with a JSON-RPC
// error before reaching the MCP server — deterministic enforcement the agent
// cannot bypass.
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

	"github.com/snapp-incubator/mcp-authz/internal/gateway"
	"github.com/snapp-incubator/mcp-authz/internal/version"
)

func main() {
	var (
		configPath  string
		addr        string
		logLevel    string
		showVersion bool
	)
	flag.StringVar(&configPath, "config", "/etc/mcp-gateway/config.yaml", "Path to config file")
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
	cfg, err := gateway.Load(configPath)
	if err != nil {
		return err
	}
	secret := os.Getenv(cfg.TokenSecretEnv)
	if secret == "" && cfg.RequireToken() {
		return fmt.Errorf("scope token secret env %q is empty (required)", cfg.TokenSecretEnv)
	}

	h, err := gateway.New(cfg, secret, log)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/", h)

	log.Info("starting mcp-gateway",
		"version", version.Version, "addr", addr, "cluster", cfg.Cluster, "upstream", cfg.Upstream, "requireToken", cfg.RequireToken())
	return serve(addr, mux, log)
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
