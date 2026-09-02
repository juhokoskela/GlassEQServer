package httpapi

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
)

func TestManagementSessionPassesLicenseKeyClientIPAndDeadline(t *testing.T) {
	activations := &fakeActivationService{response: activation.Response{
		Status: http.StatusCreated,
		Body:   []byte(`{"management_token":"gem_token","expires_at":1800000900}`),
	}}
	request := httptest.NewRequest(http.MethodPost, "/v1/management-sessions", strings.NewReader(`{"license_key":"GEQ1-KEY"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", "203.0.113.8, 198.51.100.4")
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
	if activations.managementInput.LicenseKey != "GEQ1-KEY" || activations.managementInput.ClientIP != netip.MustParseAddr("198.51.100.4") {
		t.Errorf("management input = %+v", activations.managementInput)
	}
	if activations.deadlineRemaining <= 0 || activations.deadlineRemaining > activationTimeout {
		t.Errorf("management deadline remaining = %s", activations.deadlineRemaining)
	}
}

func TestManagementSessionRejectsInvalidHTTPRequests(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		mutate     func(*http.Request)
		wantStatus int
	}{
		{name: "missing content type", body: `{}`, mutate: func(request *http.Request) { request.Header.Del("Content-Type") }, wantStatus: http.StatusUnsupportedMediaType},
		{name: "unknown field", body: `{"license_key":"key","extra":true}`, wantStatus: http.StatusBadRequest},
		{name: "trailing JSON", body: `{} {}`, wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			activations := &fakeActivationService{}
			request := httptest.NewRequest(http.MethodPost, "/v1/management-sessions", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
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

func TestListManagedActivationsPassesBearerToken(t *testing.T) {
	activations := &fakeActivationService{response: activation.Response{
		Status: http.StatusOK,
		Body:   []byte(`{"activations":[]}`),
	}}
	request := httptest.NewRequest(http.MethodGet, "/v1/management/activations", nil)
	request.Header.Set("Authorization", "Bearer gem_token")
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if activations.managementToken != "gem_token" {
		t.Errorf("management token = %q", activations.managementToken)
	}
}

func TestDeactivateManagedPassesBearerTokenAndPath(t *testing.T) {
	activations := &fakeActivationService{response: activation.Response{Status: http.StatusNoContent}}
	request := httptest.NewRequest(http.MethodDelete, "/v1/management/activations/act_target", nil)
	request.Header.Set("Authorization", "Bearer gem_token")
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	want := (activation.ManagedDeactivationInput{ManagementToken: "gem_token", ActivationID: "act_target"})
	if activations.managedDeactivation != want {
		t.Errorf("managed deactivation = %+v, want %+v", activations.managedDeactivation, want)
	}
}

func TestManagementEndpointsRejectMissingBearerToken(t *testing.T) {
	for _, target := range []string{"/v1/management/activations", "/v1/management/activations/act_target"} {
		t.Run(target, func(t *testing.T) {
			activations := &fakeActivationService{}
			request := httptest.NewRequest(http.MethodGet, target, nil)
			if strings.Contains(target, "act_target") {
				request.Method = http.MethodDelete
			}
			response := httptest.NewRecorder()

			New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
			if activations.calls != 0 {
				t.Errorf("service calls = %d, want 0", activations.calls)
			}
		})
	}
}

func TestManagementSessionHidesServiceErrorAndLicenseKey(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	activations := &fakeActivationService{err: errors.New("database unavailable")}
	request := httptest.NewRequest(http.MethodPost, "/v1/management-sessions", strings.NewReader(`{"license_key":"GEQ1-SECRET"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, logger).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(logs.String(), "GEQ1-SECRET") {
		t.Fatalf("log disclosed license key: %s", logs.String())
	}
}

func TestManagementEndpointUsesBoundedDeadline(t *testing.T) {
	activations := &fakeActivationService{response: activation.Response{Status: http.StatusOK, Body: []byte(`{"activations":[]}`)}}
	request := httptest.NewRequest(http.MethodGet, "/v1/management/activations", nil)
	request.Header.Set("Authorization", "Bearer gem_token")
	response := httptest.NewRecorder()

	New(&fakeDatabase{}, activations, discardLogger()).ServeHTTP(response, request)

	if activations.deadlineRemaining <= 0 || activations.deadlineRemaining > activationTimeout {
		t.Errorf("deadline remaining = %s", activations.deadlineRemaining)
	}
}
