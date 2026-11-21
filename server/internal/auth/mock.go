package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

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

	findByRefreshTokenHashData *session.SessionData
	findByRefreshTokenHashErr  error

	refreshSessionErr       error
	refreshSessionCalls     int
	refreshSessionOldHash   [32]byte
	refreshSessionNewHash   []byte
	refreshSessionExpiresAt time.Time
	refreshSessionNow       time.Time

	logoutErr       error
	logoutCalls     int
	logoutTokenHash [32]byte
	logoutNow       time.Time
}

func (mS *mockSessionRepository) Create(
	ctx context.Context,
	data *session.SessionData,
) error {
	mS.created = data
	return mS.createErr
}

func (mS *mockSessionRepository) FindByRefreshTokenHash(
	ctx context.Context,
	refreshToken [32]byte,
) (*session.SessionData, error) {
	return mS.findByRefreshTokenHashData, mS.findByRefreshTokenHashErr
}

func (mS *mockSessionRepository) RefreshSession(
	ctx context.Context,
	oldTokenHash [32]byte,
	newTokenHash []byte,
	expiresAt time.Time,
	now time.Time,
) error {
	mS.refreshSessionCalls++
	mS.refreshSessionOldHash = oldTokenHash
	mS.refreshSessionNewHash = newTokenHash
	mS.refreshSessionExpiresAt = expiresAt
	mS.refreshSessionNow = now
	return mS.refreshSessionErr
}

func (mS *mockSessionRepository) Logout(
	ctx context.Context,
	refreshTokenHash [32]byte,
	now time.Time,
) error {
	mS.logoutCalls++
	mS.logoutTokenHash = refreshTokenHash
	mS.logoutNow = now
	return mS.logoutErr
}

func newTestTokenService(t *testing.T) *TokenService {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	return NewTokenService(privateKey)
}
