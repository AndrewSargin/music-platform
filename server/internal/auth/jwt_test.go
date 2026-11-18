package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestTokenService_CreateTokenPair(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tS := NewTokenService(privateKey)

	now := time.Now().UTC()
	claims := tokenClaims{
		iss: "music-server",
		sub: uuid.NewString(),
		sid: uuid.NewString(),
		exp: now.Add(time.Hour),
		iat: now,
	}

	output, refreshTokenHash, err := tS.createTokenPair(claims)

	require.NoError(t, err)
	require.NotEmpty(t, output.accessToken)
	require.Equal(t, int(accessTokenTTL.Seconds()), output.expiresIn)

	parsedToken, err := jwt.Parse(
		output.accessToken,
		func(token *jwt.Token) (any, error) {
			require.Equal(t, jwt.SigningMethodEdDSA, token.Method)
			return publicKey, nil
		},
	)

	require.NoError(t, err)
	require.True(t, parsedToken.Valid)

	parsedClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)

	require.Equal(t, claims.iss, parsedClaims["iss"])
	require.Equal(t, claims.sub, parsedClaims["sub"])
	require.Equal(t, claims.sid, parsedClaims["sid"])
	require.Equal(t, float64(claims.exp.Unix()), parsedClaims["exp"])
	require.Equal(t, float64(claims.iat.Unix()), parsedClaims["iat"])

	expectedHash := sha256.Sum256([]byte(output.refreshToken))

	require.NotEmpty(t, output.refreshToken)
	require.Equal(t, expectedHash[:], refreshTokenHash)
	require.NotEqual(t, output.refreshToken, string(refreshTokenHash))
}

func TestTokenService_CreateTokenPair_InvalidSignature(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, wrongPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tS := NewTokenService(wrongPrivateKey)

	now := time.Now().UTC()
	claims := tokenClaims{
		iss: "music-server",
		sub: uuid.NewString(),
		sid: uuid.NewString(),
		exp: now.Add(time.Hour),
		iat: now,
	}

	output, refreshTokenHash, err := tS.createTokenPair(claims)

	require.NoError(t, err)
	require.NotEmpty(t, output.accessToken)
	require.NotEmpty(t, refreshTokenHash)

	parsedToken, err := jwt.Parse(
		output.accessToken,
		func(token *jwt.Token) (any, error) {
			require.Equal(t, jwt.SigningMethodEdDSA, token.Method)
			return publicKey, nil
		},
	)

	require.Error(t, err)
	if parsedToken != nil {
		require.False(t, parsedToken.Valid)
	}
}

func TestTokenService_CreateTokenPair_ExpiredToken(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tS := NewTokenService(privateKey)

	now := time.Now().UTC()
	claims := tokenClaims{
		iss: "music-server",
		sub: uuid.NewString(),
		sid: uuid.NewString(),
		exp: now.Add(-time.Hour),
		iat: now,
	}

	output, refreshTokenHash, err := tS.createTokenPair(claims)

	require.NoError(t, err)
	require.NotEmpty(t, output.accessToken)
	require.NotEmpty(t, refreshTokenHash)

	parsedToken, err := jwt.Parse(
		output.accessToken,
		func(token *jwt.Token) (any, error) {
			require.Equal(t, jwt.SigningMethodEdDSA, token.Method)
			return publicKey, nil
		},
	)

	require.Error(t, err)
	if parsedToken != nil {
		require.False(t, parsedToken.Valid)
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	first := generateRefreshToken()
	second := generateRefreshToken()

	require.NotEmpty(t, first.token)
	require.NotEmpty(t, second.token)

	expectedFirstHash := sha256.Sum256([]byte(first.token))
	expectedSecondHash := sha256.Sum256([]byte(second.token))

	require.Equal(t, expectedFirstHash, first.hash)
	require.Equal(t, expectedSecondHash, second.hash)

	require.NotEqual(t, first.token, string(first.hash[:]))
	require.NotEqual(t, second.token, string(second.hash[:]))
	require.NotEqual(t, first.token, second.token)
	require.NotEqual(t, first.hash, second.hash)
}
