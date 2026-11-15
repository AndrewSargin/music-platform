package session

import (
	"time"

	"github.com/google/uuid"
)

type SessionData struct {
	ID                    uuid.UUID
	UserID                uuid.UUID
	DeviceName            string
	RefreshTokenHash      []byte
	RefreshTokenExpiresAt time.Time
	CreatedAt             time.Time
}
