package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AndrewSargin/music-platform/server/internal/user"
	"github.com/google/uuid"
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
