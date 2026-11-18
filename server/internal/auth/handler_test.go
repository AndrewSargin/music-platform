package auth

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AndrewSargin/music-platform/server/internal/session"
	"github.com/AndrewSargin/music-platform/server/internal/user"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRegisterSuccess(t *testing.T) {
	userRepo := &mockUserRepository{}
	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{
		"display_name": "Test_display",
		"username": "test_username",
		"email": "test@example.com",
		"password": "testPassword123!"		
		}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		strings.NewReader(body),
	)

	rec := httptest.NewRecorder()

	handler.Register(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusCreated, rec.Code, rec.Body.String())
	}
}

func TestRegisterInvalidJSON(t *testing.T) {
	userRepo := &mockUserRepository{}
	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		strings.NewReader("{invalid json}"),
	)

	rec := httptest.NewRecorder()

	handler.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestRegisterEmptyField(t *testing.T) {
	userRepo := &mockUserRepository{}
	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{
		"display_name": "Test_display",
		"username": "test_username",
		"email": "",
		"password": "testPassword123!"		
		}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		strings.NewReader(body),
	)

	rec := httptest.NewRecorder()

	handler.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	body = `{
		"display_name": "",
		"username": "test_username",
		"email": "test@example.com",
		"password": "testPassword123!"		
		}`

	req = httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		strings.NewReader(body),
	)

	rec = httptest.NewRecorder()

	handler.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	body = `{
		"display_name": "Test_display",
		"username": "",
		"email": "test@example.com",
		"password": "testPassword123!"		
		}`

	req = httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		strings.NewReader(body),
	)

	rec = httptest.NewRecorder()

	handler.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	body = `{
		"display_name": "Test_display",
		"username": "test_username",
		"email": "test@example.com",
		"password": ""		
		}`

	req = httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		strings.NewReader(body),
	)

	rec = httptest.NewRecorder()

	handler.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

// Test for integration with testing DB in future
/*func TestRegisterConflict(t *testing.T) {
	repo := &mockUserRepository{}
	service := NewUserService(repo)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{
		"display_name": "Test_display",
		"username": "test_username",
		"email": "test@example.com",
		"password": "testPassword123!"
		}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		strings.NewReader(body),
	)

	rec := httptest.NewRecorder()

	handler.Register(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusCreated, rec.Code, rec.Body.String())
	}

	body2 := `{
		"display_name": "New_display",
		"username": "test_username",
		"email": "NewTest@example.com",
		"password": "NewTestPassword123!"
		}`

	req = httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		strings.NewReader(body2),
	)

	rec = httptest.NewRecorder()

	handler.Register(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusConflict, rec.Code, rec.Body.String())
	}
}*/

func TestRegisterServerError(t *testing.T) {
	userRepo := &mockUserRepository{
		createErr: errors.New("database connection failed"),
	}
	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{
		"display_name": "Test_display",
		"username": "test_username",
		"email": "test@example.com",
		"password": "testPassword123!"		
		}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		strings.NewReader(body),
	)

	rec := httptest.NewRecorder()

	handler.Register(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusInternalServerError, rec.Code, rec.Body.String())
	}
}

func TestLoginSuccess(t *testing.T) {
	passwordHash, err := HashPassword("testPassword123!", defaultParams)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userRepo := &mockUserRepository{
		userCredentials: &user.UserCredentials{
			ID:           uuid.New(),
			Username:     "test_user",
			Email:        "test@example.com",
			PasswordHash: passwordHash,
		},
	}

	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{
		"login": "test_user",
		"password": "testPassword123!"	
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		strings.NewReader(body),
	)
	rec := httptest.NewRecorder()

	handler.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusOK, rec.Code, rec.Body.String())
	}

	var response JSONLoginResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.AccessToken == "" {
		t.Error("expected access token")
	}

	if response.RefreshToken == "" {
		t.Error("expected refresh token")
	}

	if response.TokenType != "Bearer" {
		t.Errorf("expected token type Bearer, got %s", response.TokenType)
	}

	if response.ExpiresIn <= 0 {
		t.Errorf("expected positive expires_in, got %d", response.ExpiresIn)
	}
}

func TestLoginIncorrectCredentials(t *testing.T) {
	userRepo := &mockUserRepository{
		findByUsernameErr: sql.ErrNoRows,
	}

	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{
		"login": "unknown_user",
		"password": "testPassword123!"	
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		strings.NewReader(body),
	)
	rec := httptest.NewRecorder()

	handler.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestLoginInvalidJSON(t *testing.T) {
	userRepo := &mockUserRepository{}
	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		strings.NewReader("{invalid json}"),
	)
	rec := httptest.NewRecorder()

	handler.Login(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if userRepo.userCredentials != nil {
		t.Fatalf("repository should not be called")
	}
}

func TestLoginEmptyLogin(t *testing.T) {
	userRepo := &mockUserRepository{}
	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{
		"login": "",
		"password": "testPassword123!"	
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		strings.NewReader(body),
	)
	rec := httptest.NewRecorder()

	handler.Login(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestLoginEmptyPassword(t *testing.T) {
	userRepo := &mockUserRepository{}
	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{
		"login": "test_user",
		"password": ""	
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		strings.NewReader(body),
	)
	rec := httptest.NewRecorder()

	handler.Login(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestLoginServerError(t *testing.T) {
	userRepo := &mockUserRepository{
		findByUsernameErr: errors.New("database connection failed"),
	}

	sessionRepo := &mockSessionRepository{}
	tS := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tS)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{
		"login": "test_user",
		"password": "testPassword123!"	
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		strings.NewReader(body),
	)
	rec := httptest.NewRecorder()

	handler.Login(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusInternalServerError, rec.Code, rec.Body.String())
	}

	if strings.Contains(rec.Body.String(), "database connection failed") {
		t.Fatalf("internal error details should not be exposed")
	}
}

func TestRefreshTokenSuccess(t *testing.T) {
	oldRefreshToken := "test-refresh-token"
	oldTokenHash := sha256.Sum256([]byte(oldRefreshToken))

	sessionRepo := &mockSessionRepository{
		findByRefreshTokenHashData: &session.SessionData{
			ID:                    uuid.New(),
			UserID:                uuid.New(),
			RefreshTokenHash:      oldTokenHash[:],
			RefreshTokenExpiresAt: time.Now().Add(time.Hour),
		},
	}

	userRepo := &mockUserRepository{}
	tS := newTestTokenService(t)

	service := NewUserService(userRepo, sessionRepo, *tS)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body, err := json.Marshal(JSONTokenRequest{
		RefreshToken: oldRefreshToken,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/refresh",
		bytes.NewReader(body),
	)
	rec := httptest.NewRecorder()

	handler.RefreshTokens(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, sessionRepo.refreshSessionCalls)

	var response JSONLoginResponse
	err = json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	require.NotEmpty(t, response.AccessToken)
	require.NotEmpty(t, response.RefreshToken)
	require.Equal(t, "Bearer", response.TokenType)
	require.Greater(t, response.ExpiresIn, 0)
	require.NotEqual(t, oldRefreshToken, response.RefreshToken)
}

func TestRefreshTokensInvalidJSON(t *testing.T) {
	sessionRepo := &mockSessionRepository{}
	userRepo := &mockUserRepository{}

	tokenService := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tokenService)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/refresh",
		strings.NewReader("token is invalid, expired or revoked"),
	)
	recorder := httptest.NewRecorder()

	handler.RefreshTokens(recorder, req)

	require.Equal(t, http.StatusUnauthorized, recorder.Code)
	require.Equal(t, 0, sessionRepo.refreshSessionCalls)

	var response ErrorResponse
	err := json.NewDecoder(recorder.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "token is invalid, expired or revoked", response.Error)
}

func TestRefreshTokensInvalidToken(t *testing.T) {
	sessionRepo := &mockSessionRepository{
		findByRefreshTokenHashErr: sql.ErrNoRows,
	}
	userRepo := &mockUserRepository{}

	tokenService := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tokenService)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{"refresh_token": "invalid-refresh-token"}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/refresh",
		strings.NewReader(body),
	)
	recorder := httptest.NewRecorder()

	handler.RefreshTokens(recorder, req)

	require.Equal(t, http.StatusUnauthorized, recorder.Code)

	var response ErrorResponse
	err := json.NewDecoder(recorder.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "token is invalid, expired or revoked", response.Error)

	require.Equal(t, 0, sessionRepo.refreshSessionCalls)
}

func TestRefreshTokensServerError(t *testing.T) {
	sessionRepo := &mockSessionRepository{
		findByRefreshTokenHashErr: errors.New("database connection failed"),
	}
	userRepo := &mockUserRepository{}

	tokenService := newTestTokenService(t)
	service := NewUserService(userRepo, sessionRepo, *tokenService)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewUserHandler(service, logger)

	body := `{"refresh_token": "valid-looking-refresh-token"}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/refresh",
		strings.NewReader(body),
	)
	recorder := httptest.NewRecorder()

	handler.RefreshTokens(recorder, req)

	require.Equal(t, http.StatusInternalServerError, recorder.Code)

	var response ErrorResponse
	err := json.NewDecoder(recorder.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "internal server error", response.Error)

	require.Equal(t, 0, sessionRepo.refreshSessionCalls)
	require.NotContains(t, recorder.Body.String(), "database connection failed")
}
