package database

import (
	"context"
	"database/sql"
	"testing"

	"github.com/AndrewSargin/music-platform/server/internal/user"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestPostgresUserRepository_Create(t *testing.T) {
	db := NewTestDB(t)
	queries := New(db)
	repo := NewPostgresUserRepository(queries)

	ctx := context.Background()

	testUser := makeTestUser(t)

	err := repo.Create(ctx, testUser)
	require.NoError(t, err)

	var (
		id           uuid.UUID
		username     string
		displayName  string
		email        string
		passwordHash string
	)

	err = db.QueryRowContext(ctx, `
		SELECT id, username, display_name, email, password_hash
		FROM users
		WHERE id = $1
	`, testUser.ID).Scan(
		&id,
		&username,
		&displayName,
		&email,
		&passwordHash,
	)

	require.NoError(t, err)
	require.Equal(t, testUser.ID, id)
	require.Equal(t, testUser.Username, username)
	require.Equal(t, testUser.DisplayName, displayName)
	require.Equal(t, testUser.Email, email)
	require.Equal(t, testUser.PasswordHash, passwordHash)

	t.Cleanup(func() {
		_, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, testUser.ID)
		require.NoError(t, err)
	})
}

func TestPostgresUserRepository_FindByUsername(t *testing.T) {
	db, _, testUser := makeUserAndSession(t)
	queries := New(db)
	repo := NewPostgresUserRepository(queries)

	ctx := context.Background()

	got, err := repo.FindByUsername(ctx, testUser.Username)

	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, testUser.ID, got.ID)
	require.Equal(t, testUser.Username, got.Username)
	require.Equal(t, testUser.PasswordHash, got.PasswordHash)
}

func TestPostgresUserRepository_FindByEmail(t *testing.T) {
	db, _, testUser := makeUserAndSession(t)
	queries := New(db)
	repo := NewPostgresUserRepository(queries)

	ctx := context.Background()

	got, err := repo.FindByEmail(ctx, testUser.Email)

	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, testUser.ID, got.ID)
	require.Equal(t, testUser.Username, got.Username)
	require.Equal(t, testUser.PasswordHash, got.PasswordHash)
}

func TestPostgresUserRepository_FindNotFound(t *testing.T) {
	db, _, _ := makeUserAndSession(t)
	queries := New(db)
	repo := NewPostgresUserRepository(queries)

	ctx := context.Background()

	t.Run("by username", func(t *testing.T) {
		got, err := repo.FindByUsername(ctx, "nonexistent-user")

		require.ErrorIs(t, err, sql.ErrNoRows)
		require.Nil(t, got)
	})

	t.Run("by email", func(t *testing.T) {
		got, err := repo.FindByEmail(ctx, "nonexistent@example.com")

		require.ErrorIs(t, err, sql.ErrNoRows)
		require.Nil(t, got)
	})
}

func TestPostgresUserRepository_CreateDuplicate(t *testing.T) {
	db, _, testUser := makeUserAndSession(t)
	queries := New(db)
	repo := NewPostgresUserRepository(queries)

	ctx := context.Background()

	tests := []struct {
		name  string
		input *user.User
	}{
		{
			name: "duplicate username",
			input: &user.User{
				ID:           uuid.New(),
				Username:     testUser.Username,
				DisplayName:  "Another User",
				Email:        uuid.NewString() + "@example.com",
				PasswordHash: "another-password-hash",
			},
		},
		{
			name: "duplicate email",
			input: &user.User{
				ID:           uuid.New(),
				Username:     "test_" + uuid.NewString(),
				DisplayName:  "Another User",
				Email:        testUser.Email,
				PasswordHash: "another-password-hash",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.Create(ctx, tt.input)
			require.Error(t, err)

			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "23505", pgErr.Code)
		})
	}
}
