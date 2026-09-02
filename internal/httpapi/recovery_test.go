package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
)

func TestRecoveryRequestPassesEmailClientIPAndDeadline(t *testing.T) {
	activations := &fakeActivationService{response: activation.Response{
		Status: http.StatusAccepted,
		Body:   []byte(`{"accepted":true}`),
	}}
	request := recoveryRequestHTTPRequest(`{"email":"customer@example.com"}`)
	request.Header.Set("X-Forwarded-For", "203.0.113.8, 198.51.100.4")
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusAccepted)
	}
	want := activation.RecoveryRequestInput{
		Email:          "customer@example.com",
		IdempotencyKey: "931ea290-c176-4d1e-ab5b-10c107e7d978",
		ClientIP:       netip.MustParseAddr("198.51.100.4"),
	}
	if activations.recoveryRequest != want {
		t.Errorf("recovery request = %+v, want %+v", activations.recoveryRequest, want)
	}
	if activations.deadlineRemaining <= 0 || activations.deadlineRemaining > activationTimeout {
		t.Errorf("recovery deadline remaining = %s", activations.deadlineRemaining)
	}
}

func TestRecoveryRequestRejectsInvalidHTTPRequests(t *testing.T) {
	largeBody := `{"email":"` + strings.Repeat("A", maximumBodySize) + `"}`
	tests := []struct {
		name       string
		body       string
		mutate     func(*http.Request)
		wantStatus int
	}{
		{name: "missing content type", body: `{}`, mutate: func(request *http.Request) { request.Header.Del("Content-Type") }, wantStatus: http.StatusUnsupportedMediaType},
		{name: "missing idempotency key", body: `{}`, mutate: func(request *http.Request) { request.Header.Del("Idempotency-Key") }, wantStatus: http.StatusBadRequest},
		{name: "duplicate idempotency key", body: `{}`, mutate: func(request *http.Request) { request.Header.Add("Idempotency-Key", "second") }, wantStatus: http.StatusBadRequest},
		{name: "unknown field", body: `{"email":"customer@example.com","extra":true}`, wantStatus: http.StatusBadRequest},
		{name: "trailing JSON", body: `{} {}`, wantStatus: http.StatusBadRequest},
		{name: "oversized", body: largeBody, wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			activations := &fakeActivationService{}
			request := recoveryRequestHTTPRequest(test.body)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()

			New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if activations.calls != 0 {
				t.Errorf("service calls = %d, want 0", activations.calls)
			}
		})
	}
}

func TestRecoveryRequestHidesServiceErrorAndEmail(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	activations := &fakeActivationService{err: errors.New("database unavailable")}
	request := recoveryRequestHTTPRequest(`{"email":"secret@example.com"}`)
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, logger).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(logs.String(), "secret@example.com") {
		t.Fatalf("log disclosed recovery email: %s", logs.String())
	}
}

func TestRecoverySessionPassesTokenAndDeadline(t *testing.T) {
	activations := &fakeActivationService{response: activation.Response{
		Status: http.StatusCreated,
		Body:   []byte(`{"management_token":"gem_token","expires_at":1800000900}`),
	}}
	request := recoverySessionHTTPRequest("ger_token")
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
	if activations.recoveryInput.RecoveryToken != "ger_token" {
		t.Errorf("recovery token = %q", activations.recoveryInput.RecoveryToken)
	}
	if activations.recoveryInput.IdempotencyKey != "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23" {
		t.Errorf("idempotency key = %q", activations.recoveryInput.IdempotencyKey)
	}
	if activations.deadlineRemaining <= 0 || activations.deadlineRemaining > activationTimeout {
		t.Errorf("recovery deadline remaining = %s", activations.deadlineRemaining)
	}
}

func TestRecoverySessionRejectsInvalidHTTPRequests(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*http.Request)
		wantStatus int
		wantCode   string
	}{
		{name: "missing authorization", mutate: func(request *http.Request) { request.Header.Del("Authorization") }, wantStatus: http.StatusUnauthorized, wantCode: "invalid_credentials"},
		{name: "duplicate authorization", mutate: func(request *http.Request) { request.Header.Add("Authorization", "Bearer ger_other") }, wantStatus: http.StatusUnauthorized, wantCode: "invalid_credentials"},
		{name: "wrong authorization scheme", mutate: func(request *http.Request) { request.Header.Set("Authorization", "Basic ger_token") }, wantStatus: http.StatusUnauthorized, wantCode: "invalid_credentials"},
		{name: "missing idempotency key", mutate: func(request *http.Request) { request.Header.Del("Idempotency-Key") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate idempotency key", mutate: func(request *http.Request) { request.Header.Add("Idempotency-Key", "other") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			activations := &fakeActivationService{}
			request := recoverySessionHTTPRequest("ger_token")
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()

			New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if !strings.Contains(response.Body.String(), `"code":"`+test.wantCode+`"`) {
				t.Errorf("body = %q", response.Body.String())
			}
			if activations.calls != 0 {
				t.Errorf("service calls = %d, want 0", activations.calls)
			}
		})
	}
}

func TestRecoverySessionHidesServiceErrorAndToken(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	activations := &fakeActivationService{err: errors.New("database unavailable")}
	request := recoverySessionHTTPRequest("ger_secret")
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, logger).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(logs.String(), "ger_secret") {
		t.Fatalf("log disclosed recovery token: %s", logs.String())
	}
}

func (f *fakeActivationService) ExchangeRecoveryToken(ctx context.Context, input activation.RecoverySessionInput) (activation.Response, error) {
	f.calls++
	f.recoveryInput = input
	f.recordDeadline(ctx)
	return f.response, f.err
}

func recoverySessionHTTPRequest(token string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/recovery-sessions", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23")
	return request
}

func recoveryRequestHTTPRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/recovery-requests", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "931ea290-c176-4d1e-ab5b-10c107e7d978")
	return request
}
