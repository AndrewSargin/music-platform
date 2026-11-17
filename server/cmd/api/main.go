package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/AndrewSargin/music-platform/server/internal/auth"
	"github.com/AndrewSargin/music-platform/server/internal/database"
	"github.com/joho/godotenv"
)

// Config contains the configuration required to run the API server.
type Config struct {
	DatabaseURL string
	Port        int
}

// LoadPrivateKey reads an Ed25519 private key from PEM-encided file.
func LoadPrivateKey() (ed25519.PrivateKey, error) {
	b, err := os.ReadFile("../secrets/jwt-private.pem")
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	privateKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}

	return privateKey, nil
}

// LoadConfig load the server configuration from the environment.
func LoadConfig() (Config, error) {
	err := godotenv.Load("../.env")
	if err != nil {
		return Config{}, err
	}

	dbURL, ok := os.LookupEnv("DATABASE_URL")
	if !ok || dbURL == "" {
		return Config{}, errors.New("no database URL in the environment")
	}

	portStr, ok := os.LookupEnv("PORT")
	if !ok || portStr == "" {
		portStr = "8080"
	}
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		return Config{}, fmt.Errorf("error with loading port: %w", err)
	} else if portInt < 1 || portInt > 65535 {
		return Config{}, errors.New("port must be between 1 and 65535")
	}

	config := Config{
		DatabaseURL: dbURL,
		Port:        portInt,
	}

	return config, nil
}

func main() {
	signals := []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	signalCtx, signalStop := signal.NotifyContext(context.Background(), signals...)
	defer signalStop()

	cfg, err := LoadConfig()

	if err != nil {
		log.Fatalf("error loading config: %v", err)
	}

	privateKey, err := LoadPrivateKey()

	if err != nil {
		log.Fatalf("error loading private key: %v", err)
	}

	dbCtx, dbCtxStop := context.WithTimeout(context.Background(), 10*time.Second)
	defer dbCtxStop()

	db, err := database.NewPostgresDB(dbCtx, cfg.DatabaseURL)

	if err != nil {
		fmt.Printf("Error creating database: %v", err)
		return
	}

	defer db.Close()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	queries := database.New(db)
	userRepository := database.NewPostgresUserRepository(queries)
	sessionRepository := database.NewPostgresSessionRepository(db, queries)
	tokenService := auth.NewTokenService(privateKey)
	userService := auth.NewUserService(userRepository, sessionRepository, *tokenService)
	authHandler := auth.NewUserHandler(userService, logger)

	mux := http.NewServeMux()

	mux.HandleFunc("POST /auth/register", authHandler.Register)
	mux.HandleFunc("POST /auth/login", authHandler.Login)
	mux.HandleFunc("POST /auth/refresh", authHandler.RefreshTokens)

	//handler := middleware.LoggingMiddleware(logger)(mux)
	handler := mux

	ongoingCtx, stopOngoingCtx := context.WithCancel(context.Background())
	defer stopOngoingCtx()
	server := &http.Server{
		Addr: ":" + strconv.Itoa(cfg.Port),
		BaseContext: func(_ net.Listener) context.Context {
			return ongoingCtx
		},
		Handler: handler,
	}

	serverErrorChan := make(chan error, 1)

	go func() {
		fmt.Printf("Starting server on port :%v\n", cfg.Port)
		if listenErr := server.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
			serverErrorChan <- listenErr
		}
	}()

	select {
	case <-signalCtx.Done():
	case serverErr := <-serverErrorChan:
		fmt.Printf("Server error: %v", serverErr)
		return
	}

	fmt.Println("Stopping server")
	fmt.Println("Waiting for ongoing requests")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = server.Shutdown(shutdownCtx)
	stopOngoingCtx()

	if err != nil {
		fmt.Printf("Failed to wait for ongoing requests: %v", err)

		err := server.Close()
		if err != nil {
			fmt.Printf("Error closing server: %v", err)
		}
	}

	fmt.Println("Server is stopped")

}
