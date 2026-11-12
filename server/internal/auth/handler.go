package auth

import (
	"encoding/json"
	"errors"
	"log"
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
}

func NewUserHandler(service *UserService) *UserHandler {
	log.Printf("NewUH: service = %p", service)

	return &UserHandler{
		service: service,
	}
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	log.Printf("Register: h = %p, service = %p", h, h.service)

	log.Println("1. handler started")

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

	if req.Email == "" || len(req.Email) > 255 {
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
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.WriteHeader(http.StatusCreated)
}
