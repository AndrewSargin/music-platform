package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/AndrewSargin/music-platform/server/internal/user"
	"github.com/google/uuid"
)

type JSONRegisterRequest struct {
	DisplayName string `json:"display_name"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

type JSONLoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type JSONLoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

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

type UserHandler struct {
	service *UserService
	logger  *slog.Logger
}

func NewUserHandler(service *UserService, logger *slog.Logger) *UserHandler {
	return &UserHandler{
		service: service,
		logger:  logger,
	}
}

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
