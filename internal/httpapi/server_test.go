package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthDoesNotDependOnDatabase(t *testing.T) {
	database := &fakeDatabase{err: errors.New("database unavailable")}
	response := httptest.NewRecorder()
	New(database, discardLogger()).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if response.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Errorf("body = %q", response.Body.String())
	}
	if database.calls != 0 {
		t.Errorf("database calls = %d, want 0", database.calls)
	}
}

func TestReadinessChecksDatabaseWithDeadline(t *testing.T) {
	database := &fakeDatabase{}
	response := httptest.NewRecorder()
	New(database, discardLogger()).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if database.calls != 1 {
		t.Errorf("database calls = %d, want 1", database.calls)
	}
	if database.deadlineRemaining <= 0 || database.deadlineRemaining > readinessTimeout {
		t.Errorf("database deadline remaining = %s", database.deadlineRemaining)
	}
}

func TestReadinessHidesDatabaseError(t *testing.T) {
	database := &fakeDatabase{err: errors.New("password authentication failed for secret-user")}
	response := httptest.NewRecorder()
	New(database, discardLogger()).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(response.Body.String(), "secret-user") {
		t.Fatalf("response disclosed database error: %q", response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
}

type fakeDatabase struct {
	err               error
	calls             int
	deadlineRemaining time.Duration
}

func (f *fakeDatabase) PingContext(ctx context.Context) error {
	f.calls++
	if deadline, ok := ctx.Deadline(); ok {
		f.deadlineRemaining = time.Until(deadline)
	}
	return f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
