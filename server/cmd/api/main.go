package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	signals := []os.Signal{syscall.SIGINT, syscall.SIGTERM} 
	signalCtx, stop := signal.NotifyContext(context.Background(), signals...)
	defer stop()

	PORT := 8080

	http.HandleFunc("/", func(w http.ResponseWriter, r* http.Request) {
		fmt.Fprintln(w, "Server is working")
	})

	ongoingCtx, stopOngoingCtx := context.WithCancel(context.Background())
	defer stopOngoingCtx()
	server := &http.Server {
		Addr: ":" + strconv.Itoa(PORT),
		BaseContext: func(_ net.Listener) context.Context {
			return ongoingCtx
		},
	}

	serverErrorChan := make (chan error, 1)

	go func() {
		fmt.Printf("Starting server on port :%v\n", PORT)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrorChan <- err
		}
	} ()
	
	select {
	case <-signalCtx.Done():
		stop()
	case err:= <- serverErrorChan:
		fmt.Printf("Server error: %v", err)
		return
	}

	fmt.Println("Stopping server")
	fmt.Println("Waiting for ongoing requests")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10 * time.Second)
	defer cancel()
	
	err := server.Shutdown(shutdownCtx)
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
