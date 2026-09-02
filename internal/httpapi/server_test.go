package httpapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
)

func TestHealthDoesNotDependOnDatabase(t *testing.T) {
	database := &fakeDatabase{err: errors.New("database unavailable")}
	response := httptest.NewRecorder()
	New(database, nil, discardLogger()).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))

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
	New(database, nil, discardLogger()).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

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
	New(database, nil, discardLogger()).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

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

func TestActivationPassesBoundedRequestToService(t *testing.T) {
	activations := &fakeActivationService{response: activation.Response{
		Status: http.StatusCreated,
		Body:   []byte(`{"activation_token":"gea_token","entitlement":"signed"}`),
	}}
	request := activationHTTPRequest(`{"license_key":"GEQ1-KEY","installation_id":"4E70638A-A75B-4BFB-B4B0-15E959A91465"}`)
	request.Header.Set("X-Forwarded-For", "203.0.113.8, 198.51.100.4")
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
	if response.Body.String() != `{"activation_token":"gea_token","entitlement":"signed"}` {
		t.Errorf("body = %q", response.Body.String())
	}
	if activations.calls != 1 {
		t.Fatalf("activation calls = %d, want 1", activations.calls)
	}
	if activations.input.ClientIP != netip.MustParseAddr("198.51.100.4") {
		t.Errorf("client IP = %q", activations.input.ClientIP)
	}
	if activations.deadlineRemaining <= 0 || activations.deadlineRemaining > activationTimeout {
		t.Errorf("activation deadline remaining = %s", activations.deadlineRemaining)
	}
}

func TestActivationRejectsInvalidHTTPRequests(t *testing.T) {
	largeBody := `{"license_key":"` + strings.Repeat("A", maximumBodySize) + `","installation_id":"id"}`
	tests := []struct {
		name       string
		body       string
		mutate     func(*http.Request)
		wantStatus int
	}{
		{name: "missing content type", body: `{}`, mutate: func(request *http.Request) { request.Header.Del("Content-Type") }, wantStatus: http.StatusUnsupportedMediaType},
		{name: "missing idempotency key", body: `{}`, mutate: func(request *http.Request) { request.Header.Del("Idempotency-Key") }, wantStatus: http.StatusBadRequest},
		{name: "duplicate idempotency key", body: `{}`, mutate: func(request *http.Request) { request.Header.Add("Idempotency-Key", "second") }, wantStatus: http.StatusBadRequest},
		{name: "unknown field", body: `{"license_key":"key","installation_id":"id","extra":true}`, wantStatus: http.StatusBadRequest},
		{name: "trailing JSON", body: `{} {}`, wantStatus: http.StatusBadRequest},
		{name: "oversized", body: largeBody, wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			activations := &fakeActivationService{}
			request := activationHTTPRequest(test.body)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()

			New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Errorf("body = %q", response.Body.String())
			}
			if activations.calls != 0 {
				t.Errorf("activation calls = %d, want 0", activations.calls)
			}
		})
	}
}

func TestActivationHidesServiceErrorAndCredentials(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	activations := &fakeActivationService{err: errors.New("database unavailable")}
	request := activationHTTPRequest(`{"license_key":"GEQ1-SECRET","installation_id":"4E70638A-A75B-4BFB-B4B0-15E959A91465"}`)
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, logger).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(response.Body.String(), `"code":"temporarily_unavailable"`) {
		t.Errorf("body = %q", response.Body.String())
	}
	if strings.Contains(logs.String(), "GEQ1-SECRET") {
		t.Fatalf("log disclosed license key: %s", logs.String())
	}
}

func TestActivationWritesRetryAfter(t *testing.T) {
	activations := &fakeActivationService{response: activation.Response{
		Status:            http.StatusTooManyRequests,
		ErrorCode:         "rate_limited",
		ErrorMessage:      "Too many activation attempts. Try again later.",
		RetryAfterSeconds: 42,
	}}
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, activationHTTPRequest(`{}`))

	if response.Header().Get("Retry-After") != "42" {
		t.Errorf("Retry-After = %q, want 42", response.Header().Get("Retry-After"))
	}
	if !strings.Contains(response.Body.String(), `"request_id":"req_`) {
		t.Errorf("body has no generated request ID: %q", response.Body.String())
	}
}

func activationHTTPRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/activations", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23")
	return request
}

type fakeActivationService struct {
	response          activation.Response
	err               error
	input             activation.Input
	calls             int
	deadlineRemaining time.Duration
}

func (f *fakeActivationService) Activate(ctx context.Context, input activation.Input) (activation.Response, error) {
	f.calls++
	f.input = input
	if deadline, ok := ctx.Deadline(); ok {
		f.deadlineRemaining = time.Until(deadline)
	}
	return f.response, f.err
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
