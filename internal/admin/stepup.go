package admin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Step-up bounds: the reauthentication receipt lives 5 minutes; an
// idempotency key replays a committed response for 24 hours. Both are
// server-side facts — never client-supplied timestamps.
const (
	RecentAuthTTL  = 5 * time.Minute
	IdempotencyTTL = 24 * time.Hour

	// MaxIdempotencyKey bounds the client-supplied key.
	MaxIdempotencyKey = 128
)

var (
	// ErrReauthRequired maps to 403 REAUTH_REQUIRED.
	ErrReauthRequired = errors.New("recent authentication required")
	// ErrIdempotencyConflict maps to 409: the same key was used with a
	// different request body.
	ErrIdempotencyConflict = errors.New("idempotency key reused with a different request")
)

// RequireRecentAuth verifies the actor's session carries a server-side
// recent_auth_at inside the TTL. The session row is already locked by
// the privileged guard, so the check serializes with revocation.
func RequireRecentAuth(ctx context.Context, tx pgx.Tx,
	sessionID uuid.UUID, now time.Time) error {
	var recent *time.Time
	err := tx.QueryRow(ctx, `
		SELECT recent_auth_at FROM uptime.sessions WHERE id=$1`,
		sessionID).Scan(&recent)
	if err != nil {
		return err
	}
	if recent == nil || now.Sub(*recent) > RecentAuthTTL || recent.After(now.Add(time.Minute)) {
		return ErrReauthRequired
	}
	return nil
}

// PrivilegedResult is the sanitized, replayable response of a
// privileged mutation — what the client saw, and what a retried
// request with the same idempotency key sees again.
type PrivilegedResult struct {
	Status   int
	Response map[string]any
}

// WithIdempotentPrivilegedTx is the full privileged-mutation recipe
// (spec 03 transaction recipe + RT F06 ordering):
//
//  1. security anchor → users in ascending order → actor session /
//     epoch / permission guards  (WithPrivilegedTx)
//  2. recent-auth check
//  3. idempotency lookup: same key + same request-hash → replay the
//     stored safe response BEFORE any mutable business guards run —
//     a version advanced by the first request's effect must not turn
//     its retry into a conflict
//  4. same key + different hash → 409
//  5. absent → run fn (business guards, mutation, audit), persist the
//     sanitized response, commit — exactly one SUCCESS record
func WithIdempotentPrivilegedTx(ctx context.Context, conn *pgx.Conn,
	actor ActorRef, permission, action, targetID, idemKey string,
	body []byte, targets []uuid.UUID, now time.Time,
	fn func(tx pgx.Tx, perms map[string]bool) (PrivilegedResult, error)) (PrivilegedResult, error) {

	if len(idemKey) == 0 || len(idemKey) > MaxIdempotencyKey {
		return PrivilegedResult{}, fmt.Errorf("%w: idempotency key length", ErrValidation)
	}
	keyHash := sha256.Sum256([]byte(idemKey))
	reqHash := sha256.Sum256(body)

	var out PrivilegedResult
	err := withPrivilegedTxUsers(ctx, conn, actor, targets, permission, now,
		func(tx pgx.Tx, _ []LockedUser, perms map[string]bool) error {
			if err := RequireRecentAuth(ctx, tx, actor.SessionID, now); err != nil {
				return err
			}
			var storedHash []byte
			var storedResp []byte
			var storedStatus int
			err := tx.QueryRow(ctx, `
				SELECT request_hash, safe_response, http_status
				FROM uptime.admin_idempotency
				WHERE actor_id=$1 AND action=$2 AND target_id=$3 AND key_hash=$4`,
				actor.UserID, action, targetID, keyHash[:]).
				Scan(&storedHash, &storedResp, &storedStatus)
			switch {
			case err == nil:
				if string(storedHash) != string(reqHash[:]) {
					return ErrIdempotencyConflict
				}
				var resp map[string]any
				if jerr := json.Unmarshal(storedResp, &resp); jerr != nil {
					return jerr
				}
				out = PrivilegedResult{Status: storedStatus, Response: resp}
				return nil
			case errors.Is(err, pgx.ErrNoRows):
				// New intent — run the business mutation.
			default:
				return err
			}

			res, err := fn(tx, perms)
			if err != nil {
				return err
			}
			// Persist the sanitized response for replay. Redact once
			// more at the boundary — the caller's DTO is already safe,
			// and the stored blob must stay that way.
			raw, err := json.Marshal(RedactAuditDiff(res.Response))
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO uptime.admin_idempotency
				  (actor_id, action, target_id, key_hash, request_hash,
				   safe_response, http_status, expires_at)
				VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`,
				actor.UserID, action, targetID, keyHash[:], reqHash[:],
				string(raw), res.Status, now.Add(IdempotencyTTL)); err != nil {
				return err
			}
			out = res
			return nil
		})
	return out, err
}

// ErrValidation marks a malformed privileged request (bounded fields);
// handlers map it to 422.
var ErrValidation = errors.New("invalid privileged request")
