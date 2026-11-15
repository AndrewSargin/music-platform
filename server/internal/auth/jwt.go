package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const refreshTokenTTL = 20160 * time.Minute
const accessTokenTTL = 60 * time.Minute

type refreshToken struct {
	token string
	hash  [32]byte
}

type TokenService struct {
	privateKey ed25519.PrivateKey
}

func NewTokenService(privateKey ed25519.PrivateKey) *TokenService {
	return &TokenService{
		privateKey: privateKey,
	}
}

func (t *TokenService) createTokenPair(claims tokenClaims) (loginOutput, []byte, error) {
	jwtClaims := jwt.MapClaims{
		"iss": claims.iss,
		"sub": claims.sub,
		"sid": claims.sid,
		"exp": jwt.NewNumericDate(claims.exp),
		"iat": jwt.NewNumericDate(claims.iat),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwtClaims)
	sign, err := token.SignedString(t.privateKey)
	if err != nil {
		return loginOutput{}, nil, fmt.Errorf("create session: %w", err)
	}

	rT := generateRefreshToken()

	output := loginOutput{
		accessToken:  sign,
		refreshToken: rT.token,
		expiresIn:    int(accessTokenTTL.Seconds()),
	}

	return output, rT.hash[:], nil
}

func generateRefreshToken() refreshToken {
	token := rand.Text()
	hash := sha256.Sum256([]byte(token))

	return refreshToken{
		token: token,
		hash:  hash,
	}
}
