package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type Params struct {
	Memory     uint32
	Iterations uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

var defaultParams = &Params{
	Memory:     64 * 1024,
	Iterations: 1,
	Threads:    2,
	SaltLength: 16,
	KeyLength:  32,
}

func HashPassword(password string, params *Params) (string, error) {
	salt, err := generateRandomBytes(params.SaltLength)
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Threads, params.KeyLength)

	b64salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	hash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, params.Memory, params.Iterations, params.Threads, b64salt, b64Key)
	return hash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
