// Package auth manages user authentication
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/AndrewSargin/music-platform/server/internal/session"
	"github.com/AndrewSargin/music-platform/server/internal/user"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type loginInput struct {
	login    string
	password string
}

type loginOutput struct {
	accessToken  string
	refreshToken string
	expiresIn    int
}

type tokenClaims struct {
	iss string
	sub string
	sid string
	exp time.Time
	iat time.Time
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

type UserService struct {
	userRepository    user.UserRepository
	sessionRepository session.SessionRepository
	tokenService      TokenService
}

func NewUserService(uRepo user.UserRepository, sRepo session.SessionRepository, ts TokenService) *UserService {
	return &UserService{
		userRepository:    uRepo,
		sessionRepository: sRepo,
		tokenService:      ts,
	}
}

func (s *UserService) Register(ctx context.Context, input *user.User) error {
	passwordHash, err := HashPassword(input.PasswordHash, defaultParams)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	input.PasswordHash = passwordHash

	err = s.userRepository.Create(ctx, input)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrUserAlreadyExists
		}

		return fmt.Errorf("register user: %w", err)
	}
	return nil
}

func (s *UserService) Login(ctx context.Context, input *loginInput) (loginOutput, error) {
	var err error
	var userCred *user.UserCredentials
	login := input.login

	if isValidEmail(login) {
		userCred, err = s.userRepository.FindByEmail(ctx, login)
	} else {
		userCred, err = s.userRepository.FindByUsername(ctx, login)
	}

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return loginOutput{}, ErrIncorrectLoginData
		}

		return loginOutput{}, fmt.Errorf("user search: %w", err)
	}

	if userCred == nil {
		return loginOutput{}, ErrIncorrectLoginData
	}

	passwordHash := userCred.PasswordHash

	ok, err := VerifyPassword(input.password, passwordHash)
	if err != nil {
		return loginOutput{}, fmt.Errorf("password verification: %w", err)
	}

	if !ok {
		return loginOutput{}, ErrIncorrectLoginData
	}

	sid := uuid.New()

	claims := tokenClaims{
		iss: "server",
		sub: userCred.ID.String(),
		sid: sid.String(),
		exp: time.Now().Add(accessTokenTTL),
		iat: time.Now(),
	}

	output, hash, err := s.tokenService.createTokenPair(claims)
	if err != nil {
		return loginOutput{}, fmt.Errorf("access token creation: %w", err)
	}

	err = s.sessionRepository.Create(ctx, &session.SessionData{
		ID:                    sid,
		UserID:                userCred.ID,
		DeviceName:            "",
		RefreshTokenHash:      hash,
		RefreshTokenExpiresAt: claims.iat.Add(refreshTokenTTL),
		CreatedAt:             claims.iat,
	})
	if err != nil {
		return loginOutput{}, fmt.Errorf("session creation: %w", err)
	}

	return output, nil
}
