package database

import (
	"context"

	"github.com/AndrewSargin/music-platform/server/internal/session"
)

type PostgresSessionRepository struct {
	queries *Queries
}

func NewPostgresSessionRepository(q *Queries) *PostgresSessionRepository {
	return &PostgresSessionRepository{
		queries: q,
	}
}

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
