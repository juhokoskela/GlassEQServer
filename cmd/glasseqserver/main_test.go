package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/billing"
)

func TestLogFailureIncludesSafeStripeDiagnostics(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	err := fmt.Errorf("check catalog: %w", &billing.StripeRequestError{
		HTTPStatusCode: http.StatusForbidden,
		Code:           "api_key_expired",
		RequestID:      "req_example",
	})

	logFailure(logger, "catalog failed", err)

	for _, field := range []string{
		`"msg":"catalog failed"`,
		`"stripe_http_status":403`,
		`"stripe_code":"api_key_expired"`,
		`"stripe_request_id":"req_example"`,
	} {
		if !strings.Contains(output.String(), field) {
			t.Errorf("log = %q, want field %s", output.String(), field)
		}
	}
}

func TestServeStopsAfterCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, server, listener)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop after cancellation")
	}
}

func TestServeReturnsGracefulAndForcedShutdownErrors(t *testing.T) {
	shutdownErr := errors.New("graceful shutdown failed")
	closeErr := errors.New("forced close failed")
	server := &failingShutdownServer{
		closed:      make(chan struct{}),
		shutdownErr: shutdownErr,
		closeErr:    closeErr,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := serve(ctx, server, nil)
	if !errors.Is(err, shutdownErr) {
		t.Errorf("serve error = %v, want graceful shutdown error", err)
	}
	if !errors.Is(err, closeErr) {
		t.Errorf("serve error = %v, want forced close error", err)
	}
}

func TestActivationCleanupStopsWithContext(t *testing.T) {
	cleaner := &recordingCleaner{called: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runActivationCleanup(ctx, cleaner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	select {
	case <-cleaner.called:
	case <-time.After(time.Second):
		t.Fatal("activation cleanup did not run")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("activation cleanup did not stop")
	}
}

func TestRecoveryEmailDispatchStopsWithContext(t *testing.T) {
	dispatcher := &recordingRecoveryDispatcher{
		called:      make(chan struct{}, 1),
		hasDeadline: make(chan bool, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runRecoveryEmailDispatch(ctx, dispatcher, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	select {
	case <-dispatcher.called:
	case <-time.After(time.Second):
		t.Fatal("recovery dispatcher did not run")
	}
	if <-dispatcher.hasDeadline {
		t.Error("dispatch loop imposed an outer deadline")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recovery dispatcher did not stop")
	}
}

type failingShutdownServer struct {
	closed      chan struct{}
	shutdownErr error
	closeErr    error
}

type recordingCleaner struct {
	called chan struct{}
}

type recordingRecoveryDispatcher struct {
	called      chan struct{}
	hasDeadline chan bool
}

func (c *recordingCleaner) CleanupExpired(context.Context, time.Time) (int64, error) {
	c.called <- struct{}{}
	return 0, nil
}

func (d *recordingRecoveryDispatcher) DispatchRecoveryEmail(ctx context.Context, _ time.Time) (bool, error) {
	_, hasDeadline := ctx.Deadline()
	d.hasDeadline <- hasDeadline
	d.called <- struct{}{}
	return false, nil
}

func (s *failingShutdownServer) Serve(net.Listener) error {
	<-s.closed
	return http.ErrServerClosed
}

func (s *failingShutdownServer) Shutdown(context.Context) error {
	return s.shutdownErr
}

func (s *failingShutdownServer) Close() error {
	close(s.closed)
	return s.closeErr
}
