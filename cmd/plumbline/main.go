// Command plumbline is the Plumbline SSPM server.
//
// main.go only wires things together: config -> database -> startup recovery
// -> rules -> connectors -> scan workers -> HTTP server -> graceful shutdown.
// All behaviour lives in the internal/ packages.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Rahul03082001/plumbline-sspm/internal/config"
	"github.com/Rahul03082001/plumbline-sspm/internal/connector/github"
	"github.com/Rahul03082001/plumbline-sspm/internal/connector/simulated"
	"github.com/Rahul03082001/plumbline-sspm/internal/metrics"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
	"github.com/Rahul03082001/plumbline-sspm/internal/rules"
	"github.com/Rahul03082001/plumbline-sspm/internal/scan"
	"github.com/Rahul03082001/plumbline-sspm/internal/store"
	"github.com/Rahul03082001/plumbline-sspm/internal/web"
)

// shutdownTimeout: Cloud Run gives an instance 10s after SIGTERM, so we use 8s
// for draining HTTP requests and running scans, leaving margin.
const shutdownTimeout = 8 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// run returns an error instead of calling os.Exit directly, so deferred
// cleanup (closing the database) always happens.
func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)

	// ctx is cancelled when SIGTERM (Cloud Run) or Ctrl-C (SIGINT) arrives.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	// Startup recovery: a scan left queued/running means the previous process
	// died mid-scan. Only matters when the DB file survives a restart (local
	// runs); on Cloud Run the in-memory filesystem resets with the instance.
	if n, err := st.RecoverInterrupted(ctx); err != nil {
		return fmt.Errorf("startup recovery: %w", err)
	} else if n > 0 {
		log.Warn("marked interrupted scans as failed", "count", n)
	}

	ruleset, err := rules.LoadBuiltin()
	if err != nil {
		return fmt.Errorf("load rules: %w", err) // invalid rules = refuse to start
	}

	m := metrics.New()
	svc := scan.New(st, ruleset, scan.Options{Logger: log, Metrics: m})
	m.RegisterQueueDepth(svc.QueueDepth)

	// Simulated tenant: always on. Continue its v1/v2 cycle where it left off.
	done, err := st.CountSucceeded(ctx, simulated.ConnectionID)
	if err != nil {
		return err
	}
	if err := svc.Register(ctx, model.Connection{
		ID: simulated.ConnectionID, Provider: "github", DisplayName: "Acme Corp (demo)", Mode: model.ModeSimulated,
	}, simulated.New(done, cfg.SimulatedScanDelay)); err != nil {
		return err
	}

	// Live GitHub connector: only when a token and org are configured.
	if cfg.LiveEnabled() {
		client, err := github.NewClient(github.ClientOptions{
			BaseURL: cfg.GitHubAPIURL, Token: cfg.GitHubToken, Observer: m, Logger: log,
		})
		if err != nil {
			return err
		}
		if err := svc.Register(ctx, model.Connection{
			ID: "github:" + cfg.GitHubOrg, Provider: "github", DisplayName: cfg.GitHubOrg, Mode: model.ModeLive,
		}, github.New(client, cfg.GitHubOrg)); err != nil {
			return err
		}
		log.Info("live GitHub connector enabled", "org", cfg.GitHubOrg) // never log the token
	} else {
		log.Info("live GitHub connector disabled (GITHUB_TOKEN/GITHUB_ORG not set)")
	}

	svc.Start()
	svc.SeedInitialScans(ctx) // so the dashboard is never empty after a reset

	liveOrg := ""
	if cfg.LiveEnabled() {
		liveOrg = cfg.GitHubOrg
	}
	handler, err := web.New(web.Options{
		Service: svc, Logger: log, MetricsHandler: m.Handler(),
		TrustedProxyHops: cfg.TrustedProxyHops, LiveOrg: liveOrg,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second, // protects against slow-header (Slowloris) clients
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Run the server in a goroutine so main can wait for a shutdown signal.
	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	// Graceful shutdown, one shared 8s budget: stop taking HTTP requests,
	// then stop accepting scans and wait for running ones.
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.Warn("http shutdown", "error", err)
	}
	svc.Shutdown(sctx)
	log.Info("stopped")
	return nil
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}
