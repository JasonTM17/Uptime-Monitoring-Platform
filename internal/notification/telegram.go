package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// TelegramSender is the bounded provider adapter. The endpoint is
// FIXED — no runtime base URL, no proxy environment, no redirects —
// so a bot token can never be steered to an attacker host. The token
// rides in the request path per the Bot API; every error surface is
// scrubbed so the token can never reach a log or a caller.
//
// Send returns a provider message reference on acceptance only —
// a 2xx is provider intent, not proof a human saw the message.
type TelegramSender struct {
	client *http.Client
}

const (
	telegramHost     = "api.telegram.org"
	telegramTimeout  = 5 * time.Second
	telegramBodyCap  = 64 << 10
	telegramMaxText  = 4096 // Telegram message ceiling
	maxProviderField = 512  // bound parsed provider strings
)

// NewTelegramSender builds the adapter. rt is injectable ONLY for
// tests (fake provider); production callers pass nil and get a
// pinned transport: no proxy, no redirects, verified TLS, bounded
// timeout — the SSRF discipline applied to an egress URL we control.
func NewTelegramSender(rt http.RoundTripper) *TelegramSender {
	if rt == nil {
		rt = &http.Transport{
			Proxy: nil, // never honor proxy env for a token-bearing URL
		}
	}
	return &TelegramSender{client: &http.Client{
		Transport: rt,
		Timeout:   telegramTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never follow — ever
		},
	}}
}

// Delivery is the per-attempt provider outcome.
type Delivery struct {
	ProviderMessageID int64
	RetryAfter        time.Duration // provider-supplied backoff (429)
}

// SendError classifies provider failures for the retry budget.
type SendError struct {
	Permanent bool  // true: never retry (bot blocked, bad chat/token)
	Retryable bool  // true: retry inside the delivery budget
	RateLimit bool  // true: external provider rate limit refusal
	Cause     error // scrubbed — never contains the token or raw URL
}

func (e *SendError) Error() string { return e.Cause.Error() }
func (e *SendError) Unwrap() error { return e.Cause }

func permanentf(format string, a ...any) *SendError {
	return &SendError{Permanent: true, Cause: fmt.Errorf(format, a...)}
}
func retryablef(format string, a ...any) *SendError {
	return &SendError{Retryable: true, Cause: fmt.Errorf(format, a...)}
}
func ratelimitf(format string, a ...any) *SendError {
	return &SendError{Retryable: true, RateLimit: true, Cause: fmt.Errorf(format, a...)}
}

// Send delivers one message to one VERIFIED recipient destination.
// botToken and chatID are secrets-in-transit: they enter the request
// and are never returned, logged, or embedded in any error.
func (s *TelegramSender) Send(ctx context.Context, botToken, chatID,
	text string) (Delivery, error) {
	if len(text) == 0 || len(text) > telegramMaxText {
		return Delivery{}, permanentf("telegram: text length %d out of bounds", len(text))
	}
	u := "https://" + telegramHost + "/bot" + url.PathEscape(botToken) +
		"/sendMessage"
	body, err := json.Marshal(map[string]any{
		"chat_id": chatID,
		"text":    text,
	})
	if err != nil {
		return Delivery{}, permanentf("telegram: encode: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u,
		bytes.NewReader(body))
	if err != nil {
		return Delivery{}, permanentf("telegram: request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		// Scrub: url.Error carries the token-bearing URL. Surface only
		// the classified failure — never the request identity.
		if errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, context.Canceled) {
			return Delivery{}, retryablef("telegram: %v", ctxErr(err))
		}
		return Delivery{}, retryablef("telegram: transport failure")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, telegramBodyCap))
	if err != nil {
		return Delivery{}, retryablef("telegram: read body")
	}

	var reply struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
		Result struct {
			MessageID int64 `json:"message_id"`
		} `json:"result"`
	}
	malformed := json.Unmarshal(raw, &reply) != nil ||
		len(reply.Description) > maxProviderField

	switch {
	case resp.StatusCode == http.StatusOK && !malformed && reply.OK:
		return Delivery{ProviderMessageID: reply.Result.MessageID}, nil

	case resp.StatusCode == http.StatusTooManyRequests:
		d := Delivery{RetryAfter: time.Duration(reply.Parameters.RetryAfter) *
			time.Second}
		return d, ratelimitf("telegram: rate limited (retry_after=%ds)",
			reply.Parameters.RetryAfter)

	case resp.StatusCode >= 500:
		return Delivery{}, retryablef("telegram: provider %d",
			resp.StatusCode)

	case malformed:
		// An unparsable 2xx is provider ambiguity — the message may or
		// may not exist. Retryable inside the budget; dedup downstream
		// is the event-key's job, not the adapter's.
		return Delivery{}, retryablef("telegram: malformed response (http %d)",
			resp.StatusCode)

	default:
		return Delivery{}, permanentf("telegram: rejected (http %d, code %d)",
			resp.StatusCode, reply.ErrorCode)
	}
}

func ctxErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
