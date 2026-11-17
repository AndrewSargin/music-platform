package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/AndrewSargin/music-platform/server/internal/session"
)

// PostgresSessionRepository describes a repository for sessions.
type PostgresSessionRepository struct {
	db      *sql.DB
	queries *Queries
}

// NewPostgresSessionRepository creates new PostgresSessionRepository.
func NewPostgresSessionRepository(db *sql.DB, q *Queries) *PostgresSessionRepository {
	return &PostgresSessionRepository{
		db:      db,
		queries: q,
	}
}

// Create stores a new session in the database.
func (r *PostgresSessionRepository) Create(ctx context.Context, session *session.SessionData) error {
	params := CreateSessionParams{
		ID:                    session.ID,
		UserID:                session.UserID,
		DeviceName:            session.DeviceName,
		RefreshTokenHash:      session.RefreshTokenHash,
		RefreshTokenExpiresAt: session.RefreshTokenExpiresAt,
		CreatedAt:             session.CreatedAt,
	}

	err := r.queries.CreateSession(ctx, params)
	return err
}

// FindByRefreshTokenHash retrieves a session by the SHA-256 hash of its refresh token.
func (r *PostgresSessionRepository) FindByRefreshTokenHash(ctx context.Context, tokenHash [32]byte) (*session.SessionData, error) {

	data, err := r.queries.FindByRefreshTokenHash(ctx, tokenHash[:])
	if err != nil {
		return nil, err
	}

	session := &session.SessionData{
		ID:                    data.ID,
		UserID:                data.UserID,
		RefreshTokenExpiresAt: data.RefreshTokenExpiresAt,
	}

	return session, nil

}

// RefreshSession atomically rotates a session's refresh token.
// It verifies that the old token hash belongs to an active, unexpired session
// before storing the new token hash and expiration time.
func (r *PostgresSessionRepository) RefreshSession(
	ctx context.Context,
	oldTokenHash [32]byte,
	newTokenHash []byte,
	expiresAt time.Time,
	now time.Time,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	qtx := r.queries.WithTx(tx)

	data, err := qtx.FindSessionByRefreshTokenHashForUpdate(ctx, oldTokenHash[:])
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSessionNotFound
		}
		return err
	}
	if !data.RefreshTokenExpiresAt.After(now) {
		return ErrSessionNotFound
	}

	result, err := qtx.RotateSession(ctx, RotateSessionParams{
		ID:                    data.ID,
		RefreshTokenHash:      newTokenHash,
		RefreshTokenExpiresAt: expiresAt,
	})
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrSessionNotFound
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}
