package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: release-smoke-probe <https-url>")
		os.Exit(2)
	}
	target, err := url.Parse(os.Args[1])
	if err != nil || target.Scheme != "https" || target.Host == "" {
		fmt.Fprintln(os.Stderr, "smoke target must be an absolute HTTPS URL")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create HTTPS request:", err)
		os.Exit(1)
	}
	req.Header.Set("User-Agent", "uptime-platform-release-smoke/1.0")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "HTTPS request failed:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		fmt.Fprintln(os.Stderr, "HTTPS response has no verified certificate chain")
		os.Exit(1)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
		fmt.Fprintf(os.Stderr, "unexpected HTTPS status: %d\n", resp.StatusCode)
		os.Exit(1)
	}
	fmt.Printf("verified TLS chain for %s (status %d)\n", resp.Request.URL.Host, resp.StatusCode)
}
