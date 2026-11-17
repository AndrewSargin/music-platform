package user

import (
	"context"
)

// UserRepository defines the persistence operations for users.
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	FindByUsername(ctx context.Context, username string) (*UserCredentials, error)
	FindByEmail(ctx context.Context, email string) (*UserCredentials, error)
}
