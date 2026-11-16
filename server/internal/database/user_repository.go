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
	params := CreateUserParams{
		ID:           user.ID,
		Username:     user.Username,
		DisplayName:  user.DisplayName,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
	}

	_, err := r.queries.CreateUser(ctx, params)
	return err
}

func (r *PostgresUserRepository) FindByUsername(ctx context.Context, username string) (*userModel.UserCredentials, error) {
	dbData, err := r.queries.FindByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	userCred := userModel.UserCredentials{
		ID:           dbData.ID,
		Username:     dbData.Username,
		Email:        dbData.Email,
		PasswordHash: dbData.PasswordHash,
	}

	return &userCred, err
}

func (r *PostgresUserRepository) FindByEmail(ctx context.Context, email string) (*userModel.UserCredentials, error) {
	dbData, err := r.queries.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	userCred := userModel.UserCredentials{
		ID:           dbData.ID,
		Username:     dbData.Username,
		Email:        dbData.Email,
		PasswordHash: dbData.PasswordHash,
	}

	return &userCred, err
}
