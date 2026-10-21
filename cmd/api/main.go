// Package main is the composition root of the uptime monitoring API.
// It wires validated configuration, the platform logger, the HTTP server,
// and (in later phases) the database pool, scheduler, and notifier.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/analytics"
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

	// Analytics: owner-scoped history/stats/dashboard reads (C50).
	// Retention contract: local keeps raw 30d, hosted-free 24h;
	// hourly aggregates keep 30d in both profiles.
	anaProfile := "local"
	rawHours := 30 * 24
	if cfg.Profile == config.ProfileHosted {
		anaProfile = "hosted-free"
		rawHours = 24
	}
	anaRepo := analytics.NewRepository(pool, cfg.Database.QueryTimeout)
	anaSvc := analytics.NewService(anaRepo, analytics.ServiceConfig{
		RawRetentionHours:   rawHours,
		HourlyRetentionDays: 30,
		Profile:             anaProfile,
	})
	anaHandler := analytics.NewHandler(anaSvc, svc, log)

	// Admin: role catalog + bounded role mutations (C59). The handler
	// re-derives authorization under the security anchor — the session
	// principal is only a snapshot. The shared pool conn is safe: every
	// privileged recipe runs inside one transaction.
	adminHandler := admin.NewRolesHandler(pool, svc, csrfMgr,
		cfg.HTTP.MaxJSONBodyBytes, log)

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
	// Maintenance loops (Phase 06): rollup + retention + lease
	// reclaim are always-on duties — gating them behind the
	// notification flag would silently void the retention contract
	// in the default configuration. The dispatcher alone is gated:
	// without a keyring+token no delivery can legitimately send.
	// One dedicated conn per goroutine — pgx.Conn is not goroutine-safe.
	// Liveness: readiness pings each loop's conn — a dropped conn
	// (pgx.Conn never reconnects) flips /ready honest instead of a
	// permanently silent dead loop.
	var bgCancel context.CancelFunc
	var bgWG sync.WaitGroup
	var dispConn, janConn *pgx.Conn
	var disp *notification.Dispatcher
	bgCtx, bgCancelFn := context.WithCancel(context.Background())
	bgCancel = bgCancelFn

	leaseCfg := notification.LeaseConfig{
		Batch:       10,
		LeaseFor:    90 * time.Second, // > Batch*SendTimeout + ACK margin
		MaxAttempts: notification.DefaultRetryPolicy.MaxAttempts,
	}

	if jconn, jerr := pgx.Connect(ctx, cfg.Database.URL); jerr != nil {
		log.Error("janitor conn failed; rollup/retention off", "err", jerr)
	} else {
		janConn = jconn
		bgWG.Add(1)
		go func() {
			defer bgWG.Done()
			defer janConn.Close(context.Background())
			reclaim := time.NewTicker(30 * time.Second)
			rollup := time.NewTicker(60 * time.Second)
			retain := time.NewTicker(time.Hour)
			defer reclaim.Stop()
			defer rollup.Stop()
			defer retain.Stop()
			for {
				select {
				case <-bgCtx.Done():
					return
				case <-reclaim.C:
					_, err := notification.ReclaimExpired(bgCtx, janConn, leaseCfg)
					if err != nil {
						log.Error("lease reclaim failed", "err", err)
					}
				case <-rollup.C:
					_, err := analytics.RollupUntilQuiet(bgCtx, pool,
						analytics.RollupConfig{Batch: 500})
					if err != nil {
						log.Error("rollup failed", "err", err)
					}
				case <-retain.C:
					_, err := analytics.RunRetention(bgCtx, pool,
						analytics.RetentionConfig{
							RawRetentionHours:   rawHours,
							HourlyRetentionDays: 30,
							OutboxRetentionDays: 30,
							Batch:               500,
						}, time.Now())
					if err != nil {
						log.Error("retention failed", "err", err)
					}
				}
			}
		}()
	}

	if cfg.Notify.Enabled {
		if ring, kerr := notification.ParseKeyring(
			cfg.Notify.KeyringRead, cfg.Notify.KeyringWriteV); kerr != nil {
			log.Error("notification keyring invalid; delivery off", "err", kerr)
		} else if dconn, derr := pgx.Connect(ctx, cfg.Database.URL); derr != nil {
			log.Error("dispatcher conn failed; delivery off", "err", derr)
		} else {
			dispConn = dconn
			bot := cfg.Notify.BotToken
			disp = notification.NewDispatcher(dispConn, chanRepo, ring,
				notification.NewTelegramSender(nil),
				notification.DispatcherConfig{
					Lease:       leaseCfg,
					Retry:       notification.DefaultRetryPolicy,
					SendTimeout: 5 * time.Second,
					TickEvery:   time.Second,
					BotToken:    bot,
				}, notification.NewLimiter(30, 1, nil))
			bgWG.Add(1)
			go func() {
				defer bgWG.Done()
				defer dispConn.Close(context.Background())
				_ = disp.Run(bgCtx)
			}()
		}
	}

	ready := func(ctx context.Context) error {
		if err := database.Ping(pool)(ctx); err != nil {
			return err
		}
		if eng != nil {
			if err := eng.Ready(ctx); err != nil {
				return err
			}
		}
		// A dead maintenance or delivery loop is not "ready": each
		// loop owns one conn, and pgx.Conn never reconnects — a ping
		// failure means the loop died silently.
		if janConn != nil {
			if err := janConn.Ping(ctx); err != nil {
				return fmt.Errorf("janitor conn: %w", err)
			}
		}
		if dispConn != nil {
			if err := dispConn.Ping(ctx); err != nil {
				return fmt.Errorf("dispatcher conn: %w", err)
			}
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
		httpserver.Mount{Pattern: "/notification-channels/", Handler: chanHandler.Mux()},
		// Specific {id} patterns outrank the /monitors/ subtree mount.
		httpserver.Mount{Pattern: "/monitors/{id}/checks", Handler: anaHandler.Mux()},
		httpserver.Mount{Pattern: "/monitors/{id}/incidents", Handler: anaHandler.Mux()},
		httpserver.Mount{Pattern: "/monitors/{id}/stats", Handler: anaHandler.Mux()},
		httpserver.Mount{Pattern: "/dashboard/", Handler: anaHandler.Mux()},
		httpserver.Mount{Pattern: "/admin/", Handler: adminHandler.Mux()})
	err = srv.Run(ctx)
	// HTTP drained first. Then the delivery loops stop accepting
	// work — the dispatcher's own in-flight send finishes inside
	// its send timeout before the engine's ordered stop runs.
	if bgCancel != nil {
		bgCancel()
		done := make(chan struct{})
		go func() { bgWG.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(cfg.HTTP.ShutdownTimeout):
			log.Error("delivery loops did not stop in time")
		}
	}
	// Finally the engine's own ordered stop: readiness flips inside
	// Shutdown before its worker/finalize drain — bounded by the
	// same shutdown timeout.
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
