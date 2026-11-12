package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/AndrewSargin/music-platform/server/internal/user"
)

func TestUserServiceRegister(t *testing.T) {
	repo := &mockUserRepository{}
	service := NewUserService(repo)

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

	if repo.created == nil {
		t.Fatal("expected repository to receive user")
	}

	if repo.created.PasswordHash == "testPassword123!" {
		t.Fatalf("password was not hashed")
	}
}

func TestUserServiceRegisterRepositoryError(t *testing.T) {
	repo := &mockUserRepository{
		createErr: errors.New("database unavailable"),
	}

	service := NewUserService(repo)

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
}
