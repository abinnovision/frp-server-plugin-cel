// Command frp-cel-plugin is an frp server plugin (HTTP) that decides
// allow/reject/rewrite per lifecycle op via configured CEL rules.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/abinnovision/frp-server-plugin-cel/internal/config"
	"github.com/abinnovision/frp-server-plugin-cel/internal/policy"
	"github.com/abinnovision/frp-server-plugin-cel/internal/server"
)

// version is injected by GoReleaser via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config", "error", err.Error())
		os.Exit(1)
	}
	for _, warning := range cfg.Lint() {
		logger.Warn("config lint", "warning", warning)
	}

	engine, err := policy.New(cfg, logger)
	if err != nil {
		logger.Error("compile policy", "error", err.Error())
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("POST "+cfg.Path, server.Handler(engine, logger))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// frps's plugin client has no timeout; bounding our side prevents a
	// stuck connection from pinning resources.
	srv := &http.Server{
		Addr:              cfg.Bind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	logger.Info("listening", "bind", cfg.Bind, "path", cfg.Path, "version", version, "rules", len(cfg.Rules))
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server", "error", err.Error())
		os.Exit(1)
	}
}
