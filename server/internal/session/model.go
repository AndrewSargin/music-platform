// Package session defines a model for session entity in database
package session

import (
	"time"

	"github.com/google/uuid"
)

// Session represents a user's authentication session stored in the database.
type Session struct {
	ID                    uuid.UUID
	UserID                uuid.UUID
	DeviceName            string
	RefreshTokenHash      string
	RefreshTokenExpiresAt time.Time
	CreatedAt             time.Time
	RevokedAt             time.Time
}
