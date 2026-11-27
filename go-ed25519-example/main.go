package main

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-ed25519-example/internal/auth"
	"go-ed25519-example/internal/httpapi"
)

const (
	defaultPort       = "8080"
	maxHeaderBytes    = 8 << 20
	readHeaderTimeout = 30 * time.Second
	shutdownTimeout   = 10 * time.Second
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	if err := run(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc, err := auth.New(auth.Config{
		RootPublicKey: os.Getenv("ROOT_PUBLIC_KEY"),
		PrivateKey:    os.Getenv("PRIVATE_KEY"),
		KeyID:         os.Getenv("KEY_ID"),
		OperatorID:    os.Getenv("OPERATOR_ID"),
	})
	if err != nil {
		return fmt.Errorf("init auth service: %w", err)
	}

	server := &http.Server{
		Addr:              ":" + cmp.Or(os.Getenv("PORT"), defaultPort),
		Handler:           httpapi.New(svc),
		MaxHeaderBytes:    maxHeaderBytes,
		ReadHeaderTimeout: readHeaderTimeout,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("server listening", "addr", server.Addr)
		serveErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	stop()

	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}
