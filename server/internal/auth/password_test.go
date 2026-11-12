package auth

import "testing"

func TestPassword(t *testing.T) {
	password := "secret_password"

	hash, err := HashPassword(password, defaultParams)

	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	if hash == password {
		t.Fatal("password was not hashed")
	}

	if ok, _ := VerifyPassword(password, hash); !ok {
		t.Fatal("hash does not match original password")
	}

	if ok, _ := VerifyPassword("random_password", hash); ok {
		t.Fatal("wrong password was accepted")
	}
}
