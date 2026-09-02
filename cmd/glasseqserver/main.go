package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
	"github.com/juhokoskela/GlassEQServer/internal/config"
	"github.com/juhokoskela/GlassEQServer/internal/entitlement"
	"github.com/juhokoskela/GlassEQServer/internal/httpapi"
)

const (
	startupTimeout  = 10 * time.Second
	shutdownTimeout = 10 * time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	settings, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	startupCtx, cancelStartup := context.WithTimeout(ctx, startupTimeout)
	defer cancelStartup()

	awsSettings, err := awsconfig.LoadDefaultConfig(startupCtx)
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	signer, publicKey, err := entitlement.LoadKMSSigner(startupCtx, kms.NewFromConfig(awsSettings), settings.EntitlementKMSKeyID)
	if err != nil {
		return err
	}
	issuer, err := entitlement.NewIssuer(settings.EntitlementSigningKeyID, signer)
	if err != nil {
		return fmt.Errorf("create entitlement issuer: %w", err)
	}

	database, err := sql.Open("pgx", settings.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(10)
	database.SetMaxIdleConns(5)
	database.SetConnMaxLifetime(30 * time.Minute)
	if err := database.PingContext(startupCtx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	activationService, err := activation.NewService(database, issuer, settings.IdempotencyKey, settings.RateLimitHMACKey)
	if err != nil {
		return fmt.Errorf("create activation service: %w", err)
	}

	listener, err := net.Listen("tcp", settings.HTTPAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", settings.HTTPAddress, err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler:           httpapi.New(database, activationService, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	fingerprint := sha256.Sum256(publicKey)
	logger.Info("server listening",
		"address", listener.Addr().String(),
		"entitlement_key_id", settings.EntitlementSigningKeyID,
		"entitlement_public_key_sha256", hex.EncodeToString(fingerprint[:]),
	)
	return serve(ctx, server, listener)
}

type httpServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
	Close() error
}

func serve(ctx context.Context, server httpServer, listener net.Listener) error {
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()

	select {
	case err := <-serveResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownCtx)
	var closeErr error
	if shutdownErr != nil {
		closeErr = server.Close()
	}
	serveErr := <-serveResult
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(shutdownErr, closeErr, serveErr)
}
