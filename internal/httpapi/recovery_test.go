package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
)

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
