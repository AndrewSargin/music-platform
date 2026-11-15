package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("argin2id: hash is not in the correct format")
	ErrIncompatibleVariant = errors.New("argon2id: incompatible variant of argon2")
	ErrIncompatibleVersion = errors.New("argon2id: incompatible version of argon2")
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

// Creates hash of provided password
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

// Compares password and hash, returns true if they match
func VerifyPassword(password, hash string) (bool, error) {
	match, _, err := CheckHash(password, hash)
	return match, err
}

func CheckHash(password string, hash string) (bool, *Params, error) {
	params, salt, key, err := DecodeHash(hash)
	if err != nil {
		return false, nil, err
	}

	otherKey := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Threads, params.KeyLength)

	keyLen := int32(len(key))
	otherKeyLen := int32(len(otherKey))

	if subtle.ConstantTimeEq(keyLen, otherKeyLen) == 0 {
		return false, params, nil
	}
	if subtle.ConstantTimeCompare(key, otherKey) == 1 {
		return true, params, nil
	}
	return false, params, nil
}

func DecodeHash(hash string) (params *Params, salt, key []byte, err error) {
	r := strings.NewReader(hash)

	_, err = fmt.Fscanf(r, "$argon2id$")
	if err != nil {
		return nil, nil, nil, ErrIncompatibleVariant
	}

	var version int
	_, err = fmt.Fscanf(r, "v=%d$", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params = &Params{}
	_, err = fmt.Fscanf(r, "m=%d,t=%d,p=%d$", &params.Memory, &params.Iterations, &params.Threads)
	if err != nil {
		return nil, nil, nil, err
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, nil, err
	}
	if bytes.ContainsAny(rest, "\r\n") { // base64 decoder ignores these
		return nil, nil, nil, ErrInvalidHash
	}

	var i int
	if i = bytes.IndexByte(rest, '$'); i == -1 {
		return nil, nil, nil, ErrInvalidHash
	}

	b64Enc := base64.RawStdEncoding.Strict()

	salt = make([]byte, b64Enc.DecodedLen(i))
	_, err = b64Enc.Decode(salt, rest[:i])
	if err != nil {
		return nil, nil, nil, err
	}
	params.SaltLength = uint32(len(salt))

	key = make([]byte, b64Enc.DecodedLen(len(rest)-i-1))
	_, err = b64Enc.Decode(key, rest[i+1:])
	if err != nil {
		return nil, nil, nil, err
	}
	params.KeyLength = uint32(len(key))

	return params, salt, key, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
