package session

import (
	"context"
	"time"
)

// SessionRepository defines the persistence operations for user sessions.
type SessionRepository interface {
	Create(ctx context.Context, session *SessionData) error
	FindByRefreshTokenHash(ctx context.Context, refreshToken [32]byte) (*SessionData, error)
	RefreshSession(
		ctx context.Context,
		oldTokenHash [32]byte,
		newTokenHash []byte,
		expiresAt time.Time,
		now time.Time,
	) error
}
