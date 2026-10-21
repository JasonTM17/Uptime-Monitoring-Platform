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
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/engine"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/monitor"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/notification"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/database"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

	// Engine: dedicated owner conn + assembled lifecycle. A start
	// failure is NOT fatal — another instance may legitimately hold
	// the advisory lock, and the API still serves. When an engine
	// runs, readiness requires both the DB ping and a live owner.
	var eng *engine.Engine
	if engConn, err := pgx.Connect(ctx, cfg.Database.EngineURL); err != nil {
		log.Error("engine conn failed; checks will not run", "err", err)
	} else if e, err := engine.StartEngine(ctx, engConn, uuid.New(),
		engine.EngineParams{
			// Spec cadence: the scheduler ticks every second; per-monitor
			// cadence lives in interval_seconds, not in the tick rate.
			TickEvery:  time.Second,
			BatchLimit: cfg.Engine.QueueSize,
			Workers:    cfg.Engine.Workers,
			QueueSize:  cfg.Engine.QueueSize,
			Caps: engine.AdmissionCaps{
				OwnerPer60s:  cfg.Admission.OwnerPer60s,
				GlobalPer60s: cfg.Admission.GlobalPer60s,
			},
			HeartbeatEvery:  5 * time.Second,
			FinalizeTimeout: cfg.Database.QueryTimeout,
		}, checker.NewChecker(checker.SystemResolver{})); err != nil {
		log.Error("engine start failed; checks will not run", "err", err)
		_ = engConn.Close(ctx)
	} else {
		eng = e
	}
	ready := func(ctx context.Context) error {
		if err := database.Ping(pool)(ctx); err != nil {
			return err
		}
		if eng != nil {
			return eng.Ready(ctx)
		}
		return nil
	}

	srv := httpserver.New(cfg, log, ready,
		httpserver.Mount{Pattern: "/auth/", Handler: authHandler.Mux()},
		// Both the bare collection and the subtree mount so POST
		// /monitors never hits a ServeMux trailing-slash redirect.
		httpserver.Mount{Pattern: "/monitors", Handler: monHandler.Mux()},
		httpserver.Mount{Pattern: "/monitors/", Handler: monHandler.Mux()},
		httpserver.Mount{Pattern: "/notification-channels", Handler: chanHandler.Mux()},
		httpserver.Mount{Pattern: "/notification-channels/", Handler: chanHandler.Mux()})
	err = srv.Run(ctx)
	// HTTP drained first, then the engine's own ordered stop:
	// readiness flips inside Shutdown before its worker/finalize
	// drain — bounded by the same shutdown timeout.
	if eng != nil {
		sctx, cancel := context.WithTimeout(context.Background(),
			cfg.HTTP.ShutdownTimeout)
		defer cancel()
		if serr := eng.Shutdown(sctx); serr != nil {
			log.Error("engine shutdown incomplete", "err", serr)
		}
	}
	return err
}
