// Package auth manages user authentication
package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/AndrewSargin/music-platform/server/internal/user"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrUserAlreadyExists = errors.New("user already exists")

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"

}

type UserService struct {
	repository user.UserRepository
}

func NewUserService(repo user.UserRepository) *UserService {
	return &UserService{
		repository: repo,
	}
}

func (s *UserService) Register(ctx context.Context, input *user.User) error {
	passwordHash, err := HashPassword(input.PasswordHash, defaultParams)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	input.PasswordHash = passwordHash

	err = s.repository.Create(ctx, input)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrUserAlreadyExists
		}

		return fmt.Errorf("register user: %w", err)
	}
	return nil
}
