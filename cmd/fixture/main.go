// Command fixture is the deterministic check target for the local
// acceptance harness (C79). It listens only on the isolated
// public-subnet test network: the production checker's destination
// policy admits its address, and `internal: true` on the compose
// network guarantees nothing escapes.
//
// Two listeners:
//   - :80   /check — the monitored target; behavior set by the mode
//   - :9080 /control — test-driver control plane (GET/POST mode)
//
// Modes: "up" -> 200, "down" -> 500, "timeout" -> hangs past any
// sane client deadline. Not part of the release image.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	modeUp      = "up"
	modeDown    = "down"
	modeTimeout = "timeout"
)

var mode atomic.Int32 // 0 up, 1 down, 2 timeout

var modes = map[string]int32{
	modeUp: 0, modeDown: 1, modeTimeout: 2,
}

func main() {
	check := http.NewServeMux()
	check.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 0:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ok")
		case 1:
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "simulated target failure")
		default: // timeout: hang far past the 5s target timeout
			select {
			case <-r.Context().Done():
			case <-time.After(60 * time.Second):
			}
		}
	})
	// A fixed always-200 health endpoint for harness readiness.
	check.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	control := http.NewServeMux()
	control.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			fmt.Fprintf(w, `{"mode":%q}`, currentMode())
		case http.MethodPost:
			var in struct {
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"bad json"}`)
				return
			}
			v, ok := modes[in.Mode]
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"mode must be up|down|timeout"}`)
				return
			}
			mode.Store(v)
			fmt.Fprintf(w, `{"mode":%q}`, in.Mode)
		default:
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()
	for _, srv := range []*http.Server{
		{Addr: ":80", Handler: check},
		{Addr: ":9080", Handler: control},
	} {
		s := srv
		go func() {
			if err := s.ListenAndServe(); err != nil &&
				err != http.ErrServerClosed {
				fmt.Fprintln(os.Stderr, "fixture: "+err.Error())
				os.Exit(1)
			}
		}()
		go func() {
			<-ctx.Done()
			_ = s.Shutdown(context.Background())
		}()
	}
	fmt.Fprintln(os.Stderr, "fixture: target on :80, control on :9080")
	<-ctx.Done()
}

func currentMode() string {
	for name, v := range modes {
		if mode.Load() == v {
			return name
		}
	}
	return modeUp
}
