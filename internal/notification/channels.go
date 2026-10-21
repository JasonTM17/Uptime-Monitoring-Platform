// Package notification owns operator-verified notification channels:
// metadata CRUD under pending/retained allocation caps, AES-GCM
// destination encryption, masking, and the eligibility rules a
// monitor binding must satisfy. No notification is ever sent from
// this package — delivery wiring lands in the engine phases.
package notification

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrChannelNotFound is indistinguishable across missing,
	// foreign-owned, and soft-deleted rows.
	ErrChannelNotFound = errors.New("notification channel not found")
	ErrVersionConflict = errors.New("stale channel version")
	ErrPendingQuota    = errors.New("pending channel limit reached")
	ErrRetainedQuota   = errors.New("channel allocation limit reached")
	ErrBudgetMissing   = errors.New("quota budget not initialized")
	ErrActorInactive   = errors.New("owner is not active")
	ErrUnavailable     = errors.New("channel store unavailable")
)

// Channel statuses mirror the CHECK constraint.
const (
	StatusPending  = "PENDING_VERIFICATION"
	StatusVerified = "VERIFIED"
	StatusDisabled = "DISABLED"
	KindTelegram   = "TELEGRAM"
	maxLabelRunes  = 120
	maxReceiptLen  = 256
)

// Channel mirrors one uptime.notification_channels row. The
// ciphertext never leaves the repository boundary — DTOs carry only
// destination_mask.
type Channel struct {
	ID                    uuid.UUID
	UserID                uuid.UUID
	Label                 string
	Kind                  string
	Status                string
	DestinationMask       *string
	EncryptionKeyVersion  *int
	VerifiedAt            *time.Time
	VerificationReceipt   *string
	Enabled               bool
	Version               int64
	DeletedAt             *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
	destinationCiphertext []byte
}

// Ciphertext returns the encrypted destination — exported so the
// operator CLI and (later) the delivery path can decrypt under the
// right key version. It is never serialized into an API DTO.
func (c Channel) Ciphertext() []byte { return c.destinationCiphertext }

var ErrNotDeliverable = errors.New("channel is not a verified, enabled recipient")

// Deliverable is the single gate every send path must pass: only a
// VERIFIED, enabled, live channel carrying a sealed destination may
// receive traffic. PENDING/DISABLED/tombstoned rows and verified
// rows missing ciphertext all fail closed.
func (c Channel) Deliverable() bool {
	return c.Status == StatusVerified && c.Enabled &&
		c.DeletedAt == nil && len(c.destinationCiphertext) > 0
}

// FieldError carries per-field failures for VALIDATION_ERROR.
type FieldError struct {
	Fields map[string]string
}

func (e *FieldError) Error() string { return "validation failed" }

// CreateInput is the accepted browser body — label only. The strict
// JSON decoder rejects every other key, so destination/chat_id/token
// fields can never be smuggled: destinations arrive only via the
// operator CLI verification flow.
type CreateInput struct {
	Label string `json:"label"`
}

// ValidateCreate checks the label bounds.
func ValidateCreate(in CreateInput) error {
	l := strings.TrimSpace(in.Label)
	if l == "" {
		return &FieldError{Fields: map[string]string{"label": "required"}}
	}
	if len([]rune(l)) > maxLabelRunes {
		return &FieldError{Fields: map[string]string{
			"label": fmt.Sprintf("must be at most %d characters", maxLabelRunes)}}
	}
	return nil
}

// ValidateReceipt bounds the operator-supplied verification receipt.
func ValidateReceipt(r string) error {
	r = strings.TrimSpace(r)
	if r == "" || len(r) > maxReceiptLen {
		return errors.New("receipt required (1-256 chars)")
	}
	return nil
}

// Caps carries the configured allocation ceilings for channels (F03):
// pending counts every PENDING_VERIFICATION row including tombstoned
// pending; retained counts every row including deleted.
type Caps struct {
	PendingOwner   int
	PendingGlobal  int
	RetainedOwner  int
	RetainedGlobal int
}
