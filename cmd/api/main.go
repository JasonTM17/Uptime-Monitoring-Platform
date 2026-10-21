// Package main is the composition root of the uptime monitoring API.
// It wires validated configuration, the platform logger, the HTTP server,
// and (in later phases) the database pool, scheduler, and notifier.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/database"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/logger"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "api: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	log := logger.New()
	log.Info("starting api", "config", cfg.Summary())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Identity seam: repository -> bounded KDF -> service -> handler.
	// The auth mux is public now that the CSRF gate (C15) wraps every
	// mutation; cookie Secure follows the deployment profile.
	repo := auth.NewRepository(pool, cfg.Database.QueryTimeout)
	hasher := auth.NewHasher(cfg.Auth)
	svc := auth.NewService(repo, hasher, cfg.Auth)
	secure := cfg.Profile == config.ProfileHosted
	csrfMgr := auth.NewCSRFManager(cfg.Auth.CSRFSigningKey,
		cfg.Auth.CSRFTokenTTL, secure, cfg.HTTP.TrustedOrigins)
	authHandler := auth.NewHandler(svc, auth.HandlerConfig{
		MaxJSONBody:    cfg.HTTP.MaxJSONBodyBytes,
		TrustedProxies: cfg.HTTP.TrustedProxies,
		CookieSecure:   secure,
		CSRF:           csrfMgr,
	})

	srv := httpserver.New(cfg, log, database.Ping(pool),
		httpserver.Mount{Pattern: "/auth/", Handler: authHandler.Mux()})
	return srv.Run(ctx)
}
