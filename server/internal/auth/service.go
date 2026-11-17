// Package auth manages user authentication
package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/AndrewSargin/music-platform/server/internal/database"
	"github.com/AndrewSargin/music-platform/server/internal/session"
	"github.com/AndrewSargin/music-platform/server/internal/user"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// loginInput represents the credentials provided for user login.
type loginInput struct {
	login    string
	password string
}

// loginOutput represents authentication data returned after successful login.
type loginOutput struct {
	accessToken  string
	refreshToken string
	expiresIn    int
}

// tokenClaims represents the claims included in access token.
type tokenClaims struct {
	iss string
	sub string
	sid string
	exp time.Time
	iat time.Time
}

// isUniqueViolation checks whether an error represents a PostgreSQL unique constraint violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// UserService provides business logic for user registration and authentication.
type UserService struct {
	userRepository    user.UserRepository
	sessionRepository session.SessionRepository
	tokenService      TokenService
}

// NewUserService creates new UserService.
func NewUserService(uRepo user.UserRepository, sRepo session.SessionRepository, ts TokenService) *UserService {
	return &UserService{
		userRepository:    uRepo,
		sessionRepository: sRepo,
		tokenService:      ts,
	}
}

// Register registers a new user.
// It hashes the provided password and stores the user through the repository.
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

// Login authenticates a user using their username or email and password.
// It returns access and refresh tokens after successfully creating a session.
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
	now := time.Now()

	output, hash, err := s.generateSessionTokens(userCred.ID, sid, now)
	if err != nil {
		return loginOutput{}, err
	}

	err = s.sessionRepository.Create(ctx, &session.SessionData{
		ID:                    sid,
		UserID:                userCred.ID,
		DeviceName:            "",
		RefreshTokenHash:      hash,
		RefreshTokenExpiresAt: now.Add(refreshTokenTTL),
		CreatedAt:             now,
	})
	if err != nil {
		return loginOutput{}, fmt.Errorf("session creation: %w", err)
	}

	return output, nil
}

// RefreshTokens verifies provided token and makes a token rotation,
// returning new pair of tokens
func (s *UserService) RefreshTokens(ctx context.Context, refreshToken string) (loginOutput, error) {

	tokenHash := sha256.Sum256([]byte(refreshToken))
	now := time.Now()

	sessionData, err := s.sessionRepository.FindByRefreshTokenHash(ctx, tokenHash)
	if errors.Is(err, sql.ErrNoRows) {
		return loginOutput{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return loginOutput{}, fmt.Errorf("session search: %w", err)
	}
	if sessionData == nil {
		return loginOutput{}, ErrInvalidRefreshToken
	}
	if now.After(sessionData.RefreshTokenExpiresAt) {
		return loginOutput{}, ErrInvalidRefreshToken
	}

	output, hash, err := s.generateSessionTokens(sessionData.UserID, sessionData.ID, now)
	if err != nil {
		return loginOutput{}, fmt.Errorf("session token generation: %w", err)
	}

	err = s.sessionRepository.RefreshSession(
		ctx,
		tokenHash,
		hash,
		now.Add(refreshTokenTTL),
		now,
	)
	if err != nil {
		if errors.Is(err, database.ErrSessionNotFound) {
			return loginOutput{}, ErrInvalidRefreshToken
		}
		return loginOutput{}, fmt.Errorf("session rotation: %w", err)
	}

	return output, nil
}

// generateSessionTokens generates a pair of tokens
func (s *UserService) generateSessionTokens(userID, sessionID uuid.UUID, now time.Time) (loginOutput, []byte, error) {
	claims := tokenClaims{
		iss: "server",
		sub: userID.String(),
		sid: sessionID.String(),
		exp: now.Add(accessTokenTTL),
		iat: now,
	}

	output, hash, err := s.tokenService.createTokenPair(claims)
	if err != nil {
		return loginOutput{}, nil, fmt.Errorf("token pair creation: %w", err)
	}

	return output, hash, nil
}
