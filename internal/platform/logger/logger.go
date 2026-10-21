// Package logger builds the structured logger. Only allowlisted, safe
// fields may be logged — never DSNs, tokens, request bodies, or raw query
// strings.
package logger

import (
	"log/slog"
	"os"
)

// New returns a JSON slog writing to stdout at Info level.
func New() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}
