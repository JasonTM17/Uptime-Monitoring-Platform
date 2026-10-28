// Command testapp is the acceptance-harness composition root (C79):
// the REAL API surface, engine, janitor, and delivery pipeline,
// wired against the disposable test network with three controlled
// seams:
//
//   - fixtureResolver: "*.fixture" hosts resolve via the embedded
//     docker DNS of the isolated public-subnet network; resolved
//     addresses still pass the unchanged production destination
//     policy. There is no allow-private flag — isolation comes
//     from the network itself.
//   - recordingSender: notification.Sender that records every
//     delivery in memory (served at GET /__test__/deliveries)
//     instead of contacting Telegram. The provider is never
//     touched.
//   - TESTAPP_TICK_MS: faster scheduler cadence so lifecycle
//     flows complete on test timescales without fake sleeps.
//
// This binary is test-composition only — the release Dockerfile
// builds ./cmd/api exclusively, and the build-context verifier
// excludes cmd/testapp and cmd/fixture.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/analytics"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/checker"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/engine"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/monitor"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/notification"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/observability"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/database"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/httpserver"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/logger"
)

// fixtureResolver maps "*.fixture" to the bare service name inside
// the test network (docker embedded DNS). All resolved addresses
// still flow through the real transport policy.
type fixtureResolver struct{}

const fixtureSuffix = ".fixture"

func (fixtureResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	for len(host) > len(fixtureSuffix) &&
		host[len(host)-len(fixtureSuffix):] == fixtureSuffix {
		host = host[:len(host)-len(fixtureSuffix)]
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// recordingSender is the provider seam: records every send the
// dispatcher attempts, in delivery order. Thread-safe — the
// dispatcher may send concurrently.
type recordingSender struct {
	mu   sync.Mutex
	sent []recordedSend
}

type recordedSend struct {
	At     time.Time `json:"at"`
	ChatID string    `json:"chat_id"`
	Text   string    `json:"text"`
}

func (s *recordingSender) Send(_ context.Context, _, chatID, text string) (notification.Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, recordedSend{
		At: time.Now().UTC(), ChatID: chatID, Text: text,
	})
	return notification.Delivery{ProviderMessageID: int64(len(s.sent))}, nil
}

func (s *recordingSender) snapshot() []recordedSend {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]recordedSend, len(s.sent))
	copy(out, s.sent)
	return out
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "testapp: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	log := logger.New()
	log.Info("starting testapp", "config", cfg.Summary())

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	repo := auth.NewRepository(pool, cfg.Database.QueryTimeout)
	hasher := auth.NewHasher(cfg.Auth)
	svc := auth.NewService(repo, hasher, cfg.Auth, cfg.Engine.OwnerMonitorLimit)

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
	// Testapp is always the local profile: raw 30d / hourly 30d.
	const rawHours = 30 * 24
	anaRepo := analytics.NewRepository(pool, cfg.Database.QueryTimeout)
	anaSvc := analytics.NewService(anaRepo, analytics.ServiceConfig{
		RawRetentionHours:   rawHours,
		HourlyRetentionDays: 30,
		Profile:             "local",
	})
	anaHandler := analytics.NewHandler(anaSvc, svc, log)
	opsSvc := notification.NewOperations(pool, cfg.Database.QueryTimeout)
	testHandler := notification.NewTestHandler(opsSvc, svc, csrfMgr,
		notification.DefaultTestRate, cfg.HTTP.MaxJSONBodyBytes, log)
	adminHandler := admin.NewRolesHandler(pool, svc, csrfMgr,
		cfg.HTTP.MaxJSONBodyBytes, admin.QuotaCeilings{
			RetainedOwner: cfg.Alloc.RetainedMonitorsOwner,
			ColumnBound:   10000,
		}, log)

	metrics := observability.NewMetrics(nil, nil)

	// Engine: real lifecycle, fixture resolver injected — the
	// production checker and destination policy are unchanged.
	// TESTAPP_TICK_MS shortens the scheduler cadence for tests.
	tick := 250 * time.Millisecond
	if raw := os.Getenv("TESTAPP_TICK_MS"); raw != "" {
		if ms, convErr := strconv.Atoi(raw); convErr == nil && ms >= 50 {
			tick = time.Duration(ms) * time.Millisecond
		}
	}
	var eng *engine.Engine
	if engConn, err := pgx.Connect(ctx, cfg.Database.EngineURL); err != nil {
		log.Error("engine conn failed; checks will not run", "err", err)
	} else if e, err := engine.StartEngine(ctx, engConn, uuid.New(),
		engine.EngineParams{
			TickEvery:  tick,
			BatchLimit: cfg.Engine.QueueSize,
			Workers:    cfg.Engine.Workers,
			QueueSize:  cfg.Engine.QueueSize,
			Caps: engine.AdmissionCaps{
				OwnerPer60s:  cfg.Admission.OwnerPer60s,
				GlobalPer60s: cfg.Admission.GlobalPer60s,
			},
			HeartbeatEvery:  time.Second,
			FinalizeTimeout: cfg.Database.QueryTimeout,
			Metrics:         metrics,
		}, checker.NewChecker(fixtureResolver{})); err != nil {
		log.Error("engine start failed; checks will not run", "err", err)
		_ = engConn.Close(ctx)
	} else {
		eng = e
	}

	outboxSrc := observability.NewOutboxGauges(
		func(ctx context.Context) ([len(observability.OutboxStates)]int64, error) {
			var counts [len(observability.OutboxStates)]int64
			rows, err := pool.Query(ctx,
				`SELECT state, count(*) FROM uptime.notification_outbox GROUP BY state`)
			if err != nil {
				return counts, err
			}
			defer rows.Close()
			for rows.Next() {
				var state string
				var n int64
				if err := rows.Scan(&state, &n); err != nil {
					return counts, err
				}
				for i, s := range observability.OutboxStates {
					if state == s {
						counts[i] = n
						break
					}
				}
			}
			return counts, rows.Err()
		}, cfg.Observability.GaugeRefresh, cfg.Observability.GaugeTimeout)
	var gaugeFn func() engine.EngineGauges
	if eng != nil {
		gaugeFn = eng.Gauges
	}
	metrics.BindSources(gaugeFn, outboxSrc)

	// Janitor (lease reclaim + rollup + retention) and dispatcher —
	// same duties as cmd/api. The provider seam is recordingSender.
	sender := &recordingSender{}
	var bgWG sync.WaitGroup
	var dispConn, janConn *pgx.Conn
	bgCtx, bgCancel := context.WithCancel(context.Background())

	leaseCfg := notification.LeaseConfig{
		Batch:       10,
		LeaseFor:    90 * time.Second,
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

	if ring, kerr := notification.ParseKeyring(
		cfg.Notify.KeyringRead, cfg.Notify.KeyringWriteV); kerr != nil {
		log.Error("testapp keyring invalid; delivery off", "err", kerr)
	} else if dconn, derr := pgx.Connect(ctx, cfg.Database.URL); derr != nil {
		log.Error("dispatcher conn failed; delivery off", "err", derr)
	} else {
		dispConn = dconn
		disp := notification.NewDispatcher(dispConn, chanRepo, ring,
			sender,
			notification.DispatcherConfig{
				Lease:       leaseCfg,
				Retry:       notification.DefaultRetryPolicy,
				SendTimeout: 5 * time.Second,
				TickEvery:   200 * time.Millisecond,
				BotToken:    "dummy-recording-token",
			}, notification.NewLimiter(30, 1, nil))
		bgWG.Add(1)
		go func() {
			defer bgWG.Done()
			defer dispConn.Close(context.Background())
			_ = disp.Run(bgCtx)
		}()
	}

	readyProbes := []observability.Probe{
		{Name: "database", Check: database.Ping(pool)},
	}
	if eng != nil {
		readyProbes = append(readyProbes,
			observability.Probe{Name: "engine", Check: eng.Ready})
	}
	if janConn != nil {
		readyProbes = append(readyProbes,
			observability.Probe{Name: "janitor", Check: janConn.Ping})
	}
	if dispConn != nil {
		readyProbes = append(readyProbes,
			observability.Probe{Name: "dispatcher", Check: dispConn.Ping})
	}
	ready := observability.NewHealth(readyProbes...).Ready

	// Test-only evidence endpoint: recorded deliveries. Exists only
	// in this binary, only on the isolated acceptance network.
	testMux := http.NewServeMux()
	testMux.HandleFunc("GET /__test__/deliveries", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"deliveries": sender.snapshot(),
		})
	})

	mounts := []httpserver.Mount{
		{Pattern: "/auth/", Handler: authHandler.Mux()},
		{Pattern: "/monitors", Handler: monHandler.Mux()},
		{Pattern: "/monitors/", Handler: monHandler.Mux()},
		{Pattern: "/notification-channels", Handler: chanHandler.Mux()},
		{Pattern: "/notification-channels/", Handler: chanHandler.Mux()},
		{Pattern: "/notification-channels/{id}/test", Handler: testHandler.Mux()},
		{Pattern: "/monitors/{id}/checks", Handler: anaHandler.Mux()},
		{Pattern: "/monitors/{id}/incidents", Handler: anaHandler.Mux()},
		{Pattern: "/monitors/{id}/stats", Handler: anaHandler.Mux()},
		{Pattern: "/dashboard/", Handler: anaHandler.Mux()},
		{Pattern: "/admin/", Handler: adminHandler.Mux()},
		{Pattern: "/__test__/", Handler: testMux},
	}
	if cfg.Observability.MetricsEnabled {
		h := metrics.Handler()
		if cfg.Observability.MetricsToken != "" {
			h = observability.RequireBearer(cfg.Observability.MetricsToken, h)
		}
		mounts = append(mounts,
			httpserver.Mount{Pattern: "/metrics", Handler: h})
	}
	srv := httpserver.New(cfg, log, ready, mounts...)
	err = srv.Run(ctx)
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
