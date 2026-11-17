package session

import (
	"time"

	"github.com/google/uuid"
)

// SessionData contains the data required to work with user's sessions in the database.
type SessionData struct {
	ID                    uuid.UUID
	UserID                uuid.UUID
	DeviceName            string
	RefreshTokenHash      []byte
	RefreshTokenExpiresAt time.Time
	CreatedAt             time.Time
}
