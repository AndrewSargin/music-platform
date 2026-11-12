package database

import (
	"context"

	userModel "github.com/AndrewSargin/music-platform/server/internal/user"
)

type PostgresUserRepository struct {
	queries *Queries
}

func NewPostgresUserRepository(q *Queries) *PostgresUserRepository {
	return &PostgresUserRepository{
		queries: q,
	}
}

func (r *PostgresUserRepository) Create(ctx context.Context, user *userModel.User) error {
	params := CreateUserParams {
		ID: user.ID,
		Username: user.Username,
		DisplayName: user.DisplayName,
		Email: user.Email,
		PasswordHash: user.PasswordHash,
	}

	_, err := r.queries.CreateUser(ctx, params)
	return err
}
