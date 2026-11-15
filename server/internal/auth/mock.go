package auth

import (
	"context"
	"crypto/ed25519"

	"github.com/AndrewSargin/music-platform/server/internal/session"
	"github.com/AndrewSargin/music-platform/server/internal/user"
)

type mockUserRepository struct {
	createErr error
	created   *user.User
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

	return nil, nil
}

func (m *mockUserRepository) FindByEmail(
	ctx context.Context,
	email string,
) (*user.UserCredentials, error) {

	return nil, nil
}

type mockSessionRepository struct {
	ed25519.PrivateKey
	createError error
}

func (mS *mockSessionRepository) Create(
	ctx context.Context,
	data *session.SessionData,
) error {
	return mS.createError
}

/*type mockTokenService struct {
	output loginOutput
	hash []byte
	err error
}

func (mts *mockTokenService) createTokenPair(claims tokenClaims) (loginOutput, []byte, error) {
	return mts.output, mts.hash, mts.err
}*/
