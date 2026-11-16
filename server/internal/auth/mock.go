package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/AndrewSargin/music-platform/server/internal/session"
	"github.com/AndrewSargin/music-platform/server/internal/user"
)

type mockUserRepository struct {
	createErr         error
	created           *user.User
	userCredentials   *user.UserCredentials
	findByUsernameErr error
	findByEmailErr    error
}

func (m *mockUserRepository) Create(
	ctx context.Context,
	input *user.User,
) error {
	m.created = input
	return m.createErr
}

func (m *mockUserRepository) FindByUsername(
	ctx context.Context,
	username string,
) (*user.UserCredentials, error) {

	return m.userCredentials, m.findByUsernameErr
}

func (m *mockUserRepository) FindByEmail(
	ctx context.Context,
	email string,
) (*user.UserCredentials, error) {

	return m.userCredentials, m.findByEmailErr
}

type mockSessionRepository struct {
	createErr error
	created   *session.SessionData
}

func (mS *mockSessionRepository) Create(
	ctx context.Context,
	data *session.SessionData,
) error {
	mS.created = data
	return mS.createErr
}

func newTestTokenService(t *testing.T) *TokenService {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	return NewTokenService(privateKey)
}
