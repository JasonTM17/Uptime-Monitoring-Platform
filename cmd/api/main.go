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

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
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

	srv := httpserver.New(cfg, log, nil)
	return srv.Run(ctx)
}
