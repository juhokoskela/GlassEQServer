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
	request := recoverySessionHTTPRequest(`{"recovery_token":"ger_token"}`)
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
	if activations.recoveryToken != "ger_token" {
		t.Errorf("recovery token = %q", activations.recoveryToken)
	}
	if activations.deadlineRemaining <= 0 || activations.deadlineRemaining > activationTimeout {
		t.Errorf("recovery deadline remaining = %s", activations.deadlineRemaining)
	}
}

func TestRecoverySessionRejectsInvalidHTTPRequests(t *testing.T) {
	largeBody := `{"recovery_token":"` + strings.Repeat("A", maximumBodySize) + `"}`
	tests := []struct {
		name       string
		body       string
		mutate     func(*http.Request)
		wantStatus int
	}{
		{name: "missing content type", body: `{}`, mutate: func(request *http.Request) { request.Header.Del("Content-Type") }, wantStatus: http.StatusUnsupportedMediaType},
		{name: "unknown field", body: `{"recovery_token":"ger_token","extra":true}`, wantStatus: http.StatusBadRequest},
		{name: "trailing JSON", body: `{} {}`, wantStatus: http.StatusBadRequest},
		{name: "oversized", body: largeBody, wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			activations := &fakeActivationService{}
			request := recoverySessionHTTPRequest(test.body)
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
				t.Errorf("service calls = %d, want 0", activations.calls)
			}
		})
	}
}

func TestRecoverySessionHidesServiceErrorAndToken(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	activations := &fakeActivationService{err: errors.New("database unavailable")}
	request := recoverySessionHTTPRequest(`{"recovery_token":"ger_secret"}`)
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, logger).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(logs.String(), "ger_secret") {
		t.Fatalf("log disclosed recovery token: %s", logs.String())
	}
}

func (f *fakeActivationService) ExchangeRecoveryToken(ctx context.Context, token string) (activation.Response, error) {
	f.calls++
	f.recoveryToken = token
	f.recordDeadline(ctx)
	return f.response, f.err
}

func recoverySessionHTTPRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/recovery-sessions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}
