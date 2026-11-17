package user

import "github.com/google/uuid"

// UserCredentials contains the data required to work with users in the database.
type UserCredentials struct {
	ID           uuid.UUID
	Username     string
	Email        string
	PasswordHash string
}
