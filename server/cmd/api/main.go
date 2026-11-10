package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/AndrewSargin/music-platform/server/internal/database"
	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL string
	Port        int
}

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
		fmt.Printf("Error loading .env file: %v", err)
		return
	}

	dbCtx, dbCtxStop := context.WithTimeout(context.Background(), 10*time.Second)
	defer dbCtxStop()

	db, err := database.NewPostgresDB(dbCtx, cfg.DatabaseURL)

	if err != nil {
		fmt.Printf("Error creating database: %v", err)
		return
	}

	defer db.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Server is working")
	})

	ongoingCtx, stopOngoingCtx := context.WithCancel(context.Background())
	defer stopOngoingCtx()
	server := &http.Server{
		Addr: ":" + strconv.Itoa(cfg.Port),
		BaseContext: func(_ net.Listener) context.Context {
			return ongoingCtx
		},
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
