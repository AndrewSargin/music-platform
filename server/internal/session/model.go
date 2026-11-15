// Package session defines a model for session entity in database
package session

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID                    uuid.UUID
	UserID                uuid.UUID
	DeviceName            string
	RefreshTokenHash      string
	RefreshTokenExpiresAt time.Time
	CreatedAt             time.Time
	RevokedAt             time.Time
}
