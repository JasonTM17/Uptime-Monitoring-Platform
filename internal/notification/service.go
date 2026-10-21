package notification

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Store is the read seam; TxStore is the mutation seam for callers
// holding the owner actor lock. *Repository satisfies both.
type Store interface {
	GetChannel(ctx context.Context, ownerID, id uuid.UUID) (Channel, error)
	ListChannels(ctx context.Context, ownerID uuid.UUID, limit int) ([]Channel, error)
}

type TxStore interface {
	CreateChannelTx(ctx context.Context, tx pgx.Tx, ownerID uuid.UUID, label string, caps Caps) (Channel, error)
	DisableChannelTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, expectedVersion int64) (Channel, error)
	SoftDeleteChannelTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, expectedVersion int64) error
}

// Service orchestrates validation + persistence for channels.
type Service struct {
	store Store
	tx    TxStore
	caps  Caps
}

func NewService(store Store, tx TxStore, caps Caps) *Service {
	return &Service{store: store, tx: tx, caps: caps}
}

// CreateTx validates and inserts a pending channel inside the
// caller's actor-locked transaction. The browser can only ever
// create PENDING metadata — destination arrives via operator CLI.
func (s *Service) CreateTx(ctx context.Context, tx pgx.Tx, ownerID uuid.UUID, in CreateInput) (Channel, error) {
	if err := ValidateCreate(in); err != nil {
		return Channel{}, err
	}
	return s.tx.CreateChannelTx(ctx, tx, ownerID, strings.TrimSpace(in.Label), s.caps)
}

func (s *Service) DisableTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, version int64) (Channel, error) {
	return s.tx.DisableChannelTx(ctx, tx, ownerID, id, version)
}

func (s *Service) DeleteTx(ctx context.Context, tx pgx.Tx, ownerID, id uuid.UUID, version int64) error {
	return s.tx.SoftDeleteChannelTx(ctx, tx, ownerID, id, version)
}

func (s *Service) Get(ctx context.Context, ownerID, id uuid.UUID) (Channel, error) {
	return s.store.GetChannel(ctx, ownerID, id)
}

func (s *Service) List(ctx context.Context, ownerID uuid.UUID, limit int) ([]Channel, error) {
	return s.store.ListChannels(ctx, ownerID, limit)
}
