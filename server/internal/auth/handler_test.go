package auth

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterSuccess(t *testing.T) {
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
}

func TestRegisterInvalidJSON(t *testing.T) {
	repo := &mockUserRepository{}
	service := NewUserService(repo)
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
	repo := &mockUserRepository{}
	service := NewUserService(repo)
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
	repo := &mockUserRepository{
		createErr: errors.New("database connection failed"),
	}
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

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d; body: %s",
			http.StatusInternalServerError, rec.Code, rec.Body.String())
	}
}
