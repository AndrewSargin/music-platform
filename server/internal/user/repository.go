package user

import (
	"context"
)

type UserRepository interface {
	Create(ctx context.Context, user *User) error
	//FindByUsername(ctx context.Context, username string) (*User, error)
	//FindByEmail(ctx context.Context, email string) (*User, error)
}
