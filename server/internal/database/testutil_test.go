package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/AndrewSargin/music-platform/server/internal/session"
	"github.com/AndrewSargin/music-platform/server/internal/user"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func NewTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Fatalf("TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()

	db, err := sql.Open("pgx", dbURL)

	if err != nil {
		t.Fatalf("open test database: %v", err)
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Fatalf("ping test database: %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})

	return db
}

func makeSessionData(t *testing.T) *session.SessionData {
	t.Helper()
	sessionID := uuid.New()
	userID := uuid.New()
	refreshToken := "test-refresh-token"
	refreshTokenHash := sha256.Sum256([]byte(refreshToken))
	expiresAt := time.Now().Add(14 * 24 * time.Hour)
	createdAt := time.Now()

	session := &session.SessionData{
		ID:                    sessionID,
		UserID:                userID,
		DeviceName:            "test-device",
		RefreshTokenHash:      refreshTokenHash[:],
		RefreshTokenExpiresAt: expiresAt,
		CreatedAt:             createdAt,
	}

	return session
}

func makeTestUser(t *testing.T) *user.User {
	t.Helper()

	testUser := &user.User{
		ID:           uuid.New(),
		Username:     "test_" + uuid.NewString(),
		DisplayName:  "Test User",
		Email:        uuid.NewString() + "@example.com",
		PasswordHash: "test-hash",
	}

	return testUser
}

func makeUserAndSession(t *testing.T) (*sql.DB, *session.SessionData, *user.User) {
	t.Helper()

	db := NewTestDB(t)
	queries := New(db)
	sessionRepo := NewPostgresSessionRepository(db, queries)

	ctx := context.Background()

	userRepo := NewPostgresUserRepository(queries)

	session := makeSessionData(t)
	testUser := makeTestUser(t)
	session.UserID = testUser.ID

	err := userRepo.Create(ctx, testUser)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, session.ID)
		require.NoError(t, err)

		_, err = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, testUser.ID)
		require.NoError(t, err)
	})

	err = sessionRepo.Create(ctx, session)
	require.NoError(t, err)

	return db, session, testUser
}
