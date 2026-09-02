package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

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

type failingShutdownServer struct {
	closed      chan struct{}
	shutdownErr error
	closeErr    error
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
