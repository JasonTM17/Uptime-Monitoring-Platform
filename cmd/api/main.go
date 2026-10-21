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
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/monitor"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/notification"
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
	svc := auth.NewService(repo, hasher, cfg.Auth, cfg.Engine.OwnerMonitorLimit)

	// Seed the quota singleton (F03): the row is the global live-cap
	// authority — config only supplies the first value, ON CONFLICT
	// keeps an operator-adjusted budget. Monitor creation fails closed
	// if this row is absent, so a failed ensure must not stay silent.
	monRepo := monitor.NewRepository(pool, cfg.Database.QueryTimeout)
	if err := monRepo.EnsureQuotaBudget(ctx, cfg.Engine.GlobalMonitorLimit); err != nil {
		log.Error("quota budget ensure failed; monitor create will refuse",
			"err", err)
	}
	monSvc := monitor.NewService(monRepo, monRepo, monitor.Caps{
		RetainedOwner:  cfg.Alloc.RetainedMonitorsOwner,
		RetainedGlobal: cfg.Alloc.RetainedMonitorsGlobal,
	})
	secure := cfg.Profile == config.ProfileHosted
	if secure && len(cfg.HTTP.TrustedProxies) == 0 {
		// With no trusted proxy, every login attempt lands in one
		// bucket keyed on the LB address — a shared 5/min budget.
		// Fail-closed and correct, but an availability footgun.
		log.Warn("hosted profile with empty TRUSTED_PROXIES: " +
			"login/register limiters will key on the proxy address")
	}
	csrfMgr := auth.NewCSRFManager(cfg.Auth.CSRFSigningKey,
		cfg.Auth.CSRFTokenTTL, secure, cfg.HTTP.TrustedOrigins)
	authHandler := auth.NewHandler(svc, auth.HandlerConfig{
		MaxJSONBody:    cfg.HTTP.MaxJSONBodyBytes,
		TrustedProxies: cfg.HTTP.TrustedProxies,
		CookieSecure:   secure,
		CSRF:           csrfMgr,
		Logger:         log,
	})
	monHandler := monitor.NewHandler(monSvc, svc, monitor.HandlerConfig{
		MaxJSONBody:        cfg.HTTP.MaxJSONBodyBytes,
		CSRF:               csrfMgr,
		Logger:             log,
		ChannelEligibility: notification.EligibleChannelIDs,
	})
	chanRepo := notification.NewRepository(pool, cfg.Database.QueryTimeout)
	chanSvc := notification.NewService(chanRepo, chanRepo, notification.Caps{
		PendingOwner:   cfg.Alloc.PendingChannelsOwner,
		PendingGlobal:  cfg.Alloc.PendingChannelsGlobal,
		RetainedOwner:  cfg.Alloc.RetainedChannelsOwner,
		RetainedGlobal: cfg.Alloc.RetainedChannelsGlobal,
	})
	chanHandler := notification.NewHandler(chanSvc, svc, notification.HandlerConfig{
		MaxJSONBody: cfg.HTTP.MaxJSONBodyBytes,
		CSRF:        csrfMgr,
		Logger:      log,
	})

	srv := httpserver.New(cfg, log, database.Ping(pool),
		httpserver.Mount{Pattern: "/auth/", Handler: authHandler.Mux()},
		// Both the bare collection and the subtree mount so POST
		// /monitors never hits a ServeMux trailing-slash redirect.
		httpserver.Mount{Pattern: "/monitors", Handler: monHandler.Mux()},
		httpserver.Mount{Pattern: "/monitors/", Handler: monHandler.Mux()},
		httpserver.Mount{Pattern: "/notification-channels", Handler: chanHandler.Mux()},
		httpserver.Mount{Pattern: "/notification-channels/", Handler: chanHandler.Mux()})
	return srv.Run(ctx)
}
