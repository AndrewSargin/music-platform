package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/AndrewSargin/music-platform/server/internal/user"
	"github.com/google/uuid"
)

// JSONRegisterRequest represents the JSON payload for user registration.
type JSONRegisterRequest struct {
	DisplayName string `json:"display_name"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

// JSONLoginRequest represents the JSON payload for user login.
type JSONLoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// JSONTokenRequest represents the JSON payload for token refreshment.
type JSONTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// JSONLoginResponse represents the JSON response containing authentication tokens.
type JSONLoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// ErrorResponse represents the JSON response containing information about an error.
type ErrorResponse struct {
	Error string `json:"error"`
}

// writeJSONError writes the JSON response with HTTP-status.
func writeJSONError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(ErrorResponse{
		Error: message,
	})
}

// UserHandler handles HTTP requests related to user authentication.
type UserHandler struct {
	service *UserService
	logger  *slog.Logger
}

// NewUserHandler creates a UserHandler.
func NewUserHandler(service *UserService, logger *slog.Logger) *UserHandler {
	return &UserHandler{
		service: service,
		logger:  logger,
	}
}

// Register handles user registration requests.
// It validates the request, calls user service,
// and returns an appropriate HTTP response.
func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req JSONRegisterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Username == "" || len(req.Username) > 50 {
		writeJSONError(w, http.StatusBadRequest, "invalid username")
		return
	}

	if req.Email == "" || len(req.Email) > 255 || !isValidEmail(req.Email) {
		writeJSONError(w, http.StatusBadRequest, "invalid email address")
		return
	}

	if req.DisplayName == "" || len(req.DisplayName) > 50 {
		writeJSONError(w, http.StatusBadRequest, "invalid display name")
		return
	}

	if req.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "no password provided")
		return
	}

	user := user.User{
		ID:           uuid.New(),
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		Email:        req.Email,
		PasswordHash: req.Password,
	}

	if err := h.service.Register(r.Context(), &user); err != nil {
		if errors.Is(err, ErrUserAlreadyExists) {
			writeJSONError(w, http.StatusConflict, "username or email already exists")
			return
		}
		h.logger.Error("failed to register user", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// Login handles user login requests.
// It validates the request, calls user service,
// and returns an appropriate HTTP response.
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req JSONLoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Login == "" {
		writeJSONError(w, http.StatusBadRequest, "empty login field")
		return
	}

	if req.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "empty password field")
		return
	}

	input := loginInput{
		login:    req.Login,
		password: req.Password,
	}

	authData, err := h.service.Login(r.Context(), &input)
	if err != nil {
		if errors.Is(err, ErrIncorrectLoginData) {
			writeJSONError(w, http.StatusUnauthorized, "incorrect login or password")
			return
		}
		h.logger.Error("failed to log in user", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	response := JSONLoginResponse{
		AccessToken:  authData.accessToken,
		RefreshToken: authData.refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    authData.expiresIn,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode login response", "error", err)
	}
}

// RefreshTokens handles token refreshment.
func (h *UserHandler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	var req JSONTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "token is invalid, expired or revoked")
		return
	}

	authData, err := h.service.RefreshTokens(r.Context(), req.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrInvalidRefreshToken) {
			writeJSONError(w, http.StatusUnauthorized, "token is invalid, expired or revoked")
			return
		}
		h.logger.Error("failed to refresh token", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	response := JSONLoginResponse{
		AccessToken:  authData.accessToken,
		RefreshToken: authData.refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    authData.expiresIn,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode token refresh response", "error", err)
	}
}
