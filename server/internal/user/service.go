package user

import "github.com/google/uuid"

type UserCredentials struct {
	ID           uuid.UUID
	Username     string
	Email        string
	PasswordHash string
}
