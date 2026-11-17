// Package user defines a model for user entity in database
package user

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user stored in the database.
type User struct {
	ID           uuid.UUID
	Username     string
	DisplayName  string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}
