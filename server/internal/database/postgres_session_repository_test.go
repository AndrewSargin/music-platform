package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPostgresSessionRepository_Create(t *testing.T) {
	db, session, _ := makeUserAndSession(t)
	ctx := context.Background()

	var (
		gotUserID     uuid.UUID
		gotDeviceName string
		gotTokenHash  []byte
		gotExpiresAt  time.Time
		gotCreatedAt  time.Time
	)

	err := db.QueryRowContext(ctx, `
		SELECT user_id, device_name, refresh_token_hash,
			refresh_token_expires_at, created_at
		FROM sessions
		WHERE id = $1
	`, session.ID).Scan(
		&gotUserID,
		&gotDeviceName,
		&gotTokenHash,
		&gotExpiresAt,
		&gotCreatedAt,
	)

	require.NoError(t, err)
	require.Equal(t, session.UserID, gotUserID)
	require.Equal(t, session.DeviceName, gotDeviceName)
	require.Equal(t, session.RefreshTokenHash[:], gotTokenHash)
	require.WithinDuration(t, session.RefreshTokenExpiresAt, gotExpiresAt, time.Second)
	require.WithinDuration(t, session.CreatedAt, gotCreatedAt, time.Second)
}

func TestPostgresSessionRepository_RefreshSession(t *testing.T) {
	db, session, _ := makeUserAndSession(t)
	queries := New(db)
	ctx := context.Background()

	repo := NewPostgresSessionRepository(db, queries)

	newToken := "new-refresh-token"
	newTokenHash := sha256.Sum256([]byte(newToken))
	now := time.Now()
	newExpiresAt := now.Add(time.Hour)

	err := repo.RefreshSession(
		ctx,
		[32]byte(session.RefreshTokenHash),
		newTokenHash[:],
		newExpiresAt,
		now,
	)
	require.NoError(t, err)

	var (
		gotRefreshTokenHash      []byte
		gotRefreshTokenExpiresAt time.Time
		gotCreatedAt             time.Time
	)

	err = db.QueryRowContext(ctx, `
		SELECT refresh_token_hash,
			refresh_token_expires_at, created_at
		FROM sessions
		WHERE id = $1
	`, session.ID).Scan(
		&gotRefreshTokenHash,
		&gotRefreshTokenExpiresAt,
		&gotCreatedAt,
	)

	require.NoError(t, err)
	require.Equal(t, newTokenHash[:], gotRefreshTokenHash)
	require.WithinDuration(t, newExpiresAt, gotRefreshTokenExpiresAt, time.Second)
	require.WithinDuration(t, session.CreatedAt, gotCreatedAt, time.Second)
}

func TestPostgresSessionRepository_RefreshSession_NotFound(t *testing.T) {
	db, session, _ := makeUserAndSession(t)
	queries := New(db)
	ctx := context.Background()

	repo := NewPostgresSessionRepository(db, queries)

	wrongOldToken := "wrong-token"
	wrongOldTokenHash := sha256.Sum256([]byte(wrongOldToken))
	newToken := "new-refresh-token"
	newTokenHash := sha256.Sum256([]byte(newToken))

	now := time.Now()
	newExpiresAt := now.Add(time.Hour)

	err := repo.RefreshSession(
		ctx,
		wrongOldTokenHash,
		newTokenHash[:],
		newExpiresAt,
		now,
	)

	require.ErrorIs(t, err, ErrSessionNotFound)

	var gotRefreshTokenHash []byte
	var gotRefreshTokenExpiresAt time.Time

	err = db.QueryRowContext(ctx, `
		SELECT refresh_token_hash, refresh_token_expires_at
		FROM sessions
		WHERE id = $1
	`, session.ID).Scan(&gotRefreshTokenHash, &gotRefreshTokenExpiresAt)

	require.NoError(t, err)
	require.Equal(t, session.RefreshTokenHash, gotRefreshTokenHash)
	require.WithinDuration(t, session.RefreshTokenExpiresAt, gotRefreshTokenExpiresAt, time.Second)
}

func TestPostgresSessionRepository_RefreshSession_Expired(t *testing.T) {
	db, session, _ := makeUserAndSession(t)
	queries := New(db)
	ctx := context.Background()

	repo := NewPostgresSessionRepository(db, queries)

	newToken := "new-refresh-token"
	newTokenHash := sha256.Sum256([]byte(newToken))

	// Now is set to "token expiratopn date + 1 second"
	now := session.RefreshTokenExpiresAt.Add(time.Second)
	newExpiresAt := now.Add(time.Hour)

	err := repo.RefreshSession(
		ctx,
		[32]byte(session.RefreshTokenHash),
		newTokenHash[:],
		newExpiresAt,
		now,
	)

	require.ErrorIs(t, err, ErrSessionNotFound)

	var gotRefreshTokenHash []byte
	var gotRefreshTokenExpiresAt time.Time

	err = db.QueryRowContext(ctx, `
		SELECT refresh_token_hash, refresh_token_expires_at
		FROM sessions
		WHERE id = $1
	`, session.ID).Scan(&gotRefreshTokenHash, &gotRefreshTokenExpiresAt)

	require.NoError(t, err)
	require.Equal(t, session.RefreshTokenHash, gotRefreshTokenHash)
	require.WithinDuration(t, session.RefreshTokenExpiresAt, gotRefreshTokenExpiresAt, time.Second)
}

func TestPostgresSessionRepository_RefreshSession_Concurrent(t *testing.T) {
	db, session, _ := makeUserAndSession(t)
	queries := New(db)
	ctx := context.Background()

	repo := NewPostgresSessionRepository(db, queries)

	const workers = 2
	start := make(chan struct{})
	results := make(chan error, workers)

	var wg sync.WaitGroup
	wg.Add(workers)

	for range workers {
		go func() {
			defer wg.Done()

			<-start

			newToken := rand.Text()
			newTokenHash := sha256.Sum256([]byte(newToken))
			now := time.Now()
			newExpiresAt := now.Add(time.Hour)

			err := repo.RefreshSession(
				ctx,
				[32]byte(session.RefreshTokenHash),
				newTokenHash[:],
				newExpiresAt,
				now,
			)

			results <- err
		}()
	}

	close(start)

	wg.Wait()
	close(results)

	var successCount int
	var notFoundCount int

	for err := range results {
		switch {
		case err == nil:
			successCount++
		case errors.Is(err, ErrSessionNotFound):
			notFoundCount++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}

	require.Equal(t, 1, successCount)
	require.Equal(t, 1, notFoundCount)

	var gotRefreshTokenHash []byte

	err := db.QueryRowContext(ctx, `
		SELECT refresh_token_hash
		FROM sessions
		WHERE id = $1
		`, session.ID).Scan(&gotRefreshTokenHash)

	require.NoError(t, err)
	require.NotEqual(t, session.RefreshTokenHash, gotRefreshTokenHash)
}
