package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/AndrewSargin/music-platform/server/internal/user"
	"github.com/google/uuid"
)

func TestUserServiceRegister(t *testing.T) {
	userRepo := &mockUserRepository{}
	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	input := &user.User{
		Username:     "test_username",
		DisplayName:  "test_display",
		Email:        "test@example.com",
		PasswordHash: "testPassword123!",
	}

	err := service.Register(context.Background(), input)

	if err != nil {
		t.Fatalf("no error expected, got %v", err)
	}

	if userRepo.created == nil {
		t.Fatal("expected repository to receive user")
	}

	if userRepo.created.Username != input.Username {
		t.Errorf("expected username %q, got %q", input.Username, userRepo.created.Username)
	}

	if userRepo.created.DisplayName != input.DisplayName {
		t.Errorf("expected display name %q, got %q", input.DisplayName, userRepo.created.DisplayName)
	}

	if userRepo.created.Email != input.Email {
		t.Errorf("expected email %q, got %q", input.Email, userRepo.created.Email)
	}

	ok, err := VerifyPassword("testPassword123!", userRepo.created.PasswordHash)
	if err != nil {
		t.Fatalf("failed to verify password hash: %v", err)
	}
	if !ok {
		t.Fatalf("password hash does not match original password")
	}
}

func TestUserServiceRegisterRepositoryError(t *testing.T) {
	userRepo := &mockUserRepository{
		createErr: errors.New("database unavailable"),
	}

	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	input := &user.User{
		Username:     "test_username",
		DisplayName:  "test_display",
		Email:        "test@example.com",
		PasswordHash: "testPassword123!",
	}

	err := service.Register(context.Background(), input)

	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !errors.Is(err, userRepo.createErr) {
		t.Fatalf("expected database error, got %v", err)
	}
}

func TestUserServiceLoginByUsername(t *testing.T) {
	password := "testPassword123!"
	passwordHash, err := HashPassword(password, defaultParams)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	userId := uuid.New()

	userRepo := &mockUserRepository{
		userCredentials: &user.UserCredentials{
			ID:           userId,
			Username:     "test_username",
			Email:        "test@example.com",
			PasswordHash: passwordHash,
		},
	}

	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	input := &loginInput{
		login:    "test_username",
		password: password,
	}

	output, err := service.Login(context.Background(), input)

	if err != nil {
		t.Fatalf("no error expected, got %v", err)
	}

	if output.accessToken == "" {
		t.Error("expected access token")
	}

	if output.refreshToken == "" {
		t.Error("expected refresh token")
	}

	if sessionRepo.created == nil {
		t.Fatalf("expected session to be created")
	}

	if sessionRepo.created.UserID != userId {
		t.Errorf("expected user ID %v, got %v", userId, sessionRepo.created.UserID)
	}

	if len(sessionRepo.created.RefreshTokenHash) != 32 {
		t.Errorf("expected SHA-256 hash of 32 bytes, got %d", len(sessionRepo.created.RefreshTokenHash))
	}
}

func TestUserServiceLoginByEmail(t *testing.T) {
	password := "testPassword123!"
	passwordHash, err := HashPassword(password, defaultParams)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	userId := uuid.New()

	userRepo := &mockUserRepository{
		userCredentials: &user.UserCredentials{
			ID:           userId,
			Username:     "test_username",
			Email:        "test@example.com",
			PasswordHash: passwordHash,
		},
	}

	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	input := &loginInput{
		login:    "test@example.com",
		password: password,
	}

	output, err := service.Login(context.Background(), input)

	if err != nil {
		t.Fatalf("no error expected, got %v", err)
	}

	if output.accessToken == "" {
		t.Error("expected access token")
	}

	if output.refreshToken == "" {
		t.Error("expected refresh token")
	}

	if sessionRepo.created == nil {
		t.Fatalf("expected session to be created")
	}

	if sessionRepo.created.UserID != userId {
		t.Errorf("expected user ID %v, got %v", userId, sessionRepo.created.UserID)
	}

	if len(sessionRepo.created.RefreshTokenHash) != 32 {
		t.Errorf("expected SHA-256 hash of 32 bytes, got %d", len(sessionRepo.created.RefreshTokenHash))
	}
}

func TestUserServiceLoginUserNotFound(t *testing.T) {
	userRepo := &mockUserRepository{
		findByUsernameErr: sql.ErrNoRows,
	}

	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	input := &loginInput{
		login:    "unknown_user",
		password: "password123!",
	}

	_, err := service.Login(context.Background(), input)

	if !errors.Is(err, ErrIncorrectLoginData) {
		t.Fatalf("expexted ErrIncorrectLoignData, got %v", err)
	}

	if sessionRepo.created != nil {
		t.Fatal("session should not be created")
	}
}

func TestUserServiceLoginUserNotFoundNil(t *testing.T) {
	userRepo := &mockUserRepository{}
	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	input := &loginInput{
		login:    "unknown_user",
		password: "password123!",
	}

	_, err := service.Login(context.Background(), input)

	if !errors.Is(err, ErrIncorrectLoginData) {
		t.Fatalf("expexted ErrIncorrectLoignData, got %v", err)
	}

	if sessionRepo.created != nil {
		t.Fatal("session should not be created")
	}
}

func TestUserServiceLoginWrongPassword(t *testing.T) {
	passwordHash, err := HashPassword("correctPassword123!", defaultParams)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userRepo := &mockUserRepository{
		userCredentials: &user.UserCredentials{
			ID:           uuid.New(),
			Username:     "test_user",
			Email:        "test@example.com",
			PasswordHash: passwordHash,
		},
	}

	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	input := &loginInput{
		login:    "unknown_user",
		password: "wrongPassword123!",
	}

	_, err = service.Login(context.Background(), input)

	if !errors.Is(err, ErrIncorrectLoginData) {
		t.Fatalf("expexted ErrIncorrectLoignData, got %v", err)
	}

	if sessionRepo.created != nil {
		t.Fatal("session should not be created")
	}
}

func TestUserServiceLoginRepositoryError(t *testing.T) {
	repoErr := errors.New("database unavailable")

	userRepo := &mockUserRepository{
		findByUsernameErr: repoErr,
	}

	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	input := &loginInput{
		login:    "test_user",
		password: "testPassword123!",
	}

	_, err := service.Login(context.Background(), input)

	if !errors.Is(err, repoErr) {
		t.Fatalf("expexted wrapped repository error, got %v", err)
	}

	if sessionRepo.created != nil {
		t.Fatal("session should not be created")
	}
}

func TestUserServiceLoginIvalidPasswordHash(t *testing.T) {
	userRepo := &mockUserRepository{
		userCredentials: &user.UserCredentials{
			ID:           uuid.New(),
			Username:     "test_user",
			Email:        "test@example.com",
			PasswordHash: "invalid_hash",
		},
	}

	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	input := &loginInput{
		login:    "test_user",
		password: "testPassword123!",
	}

	_, err := service.Login(context.Background(), input)

	if err == nil {
		t.Fatalf("expected password verification error, got nil")
	}

	if !strings.Contains(err.Error(), "password verification") {
		t.Fatalf("expected password verification context, got %v", err)
	}

	if sessionRepo.created != nil {
		t.Fatal("session should not be created")
	}
}

func TestUserServiceLoginSessionRepositoryError(t *testing.T) {
	passwordHash, err := HashPassword("testPassword123!", defaultParams)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repoErr := errors.New("database ubavailable")

	userRepo := &mockUserRepository{
		userCredentials: &user.UserCredentials{
			ID:           uuid.New(),
			Username:     "test_user",
			Email:        "test@example.com",
			PasswordHash: passwordHash,
		},
	}

	sessionRepo := &mockSessionRepository{
		createErr: repoErr,
	}

	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	input := &loginInput{
		login:    "test_user",
		password: "testPassword123!",
	}

	_, err = service.Login(context.Background(), input)

	if err == nil {
		t.Fatalf("expected session creation error, got nil")
	}

	if !errors.Is(err, repoErr) {
		t.Fatalf("expected wrapped session repository error, got %v", err)
	}
}
