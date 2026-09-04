package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/billing"
)

func TestCheckoutPassesBoundedRequestToService(t *testing.T) {
	checkouts := &fakeCheckoutService{response: billing.CheckoutSession{
		ID:        "cs_test_example",
		URL:       "https://checkout.stripe.com/c/pay/example",
		ExpiresAt: time.Now().Add(time.Hour),
		State:     billing.CheckoutSessionOpen,
	}}
	request := checkoutHTTPRequest(`{"plan":"monthly"}`)
	request.Header.Set("Origin", checkoutOrigin)
	request.Header.Set("X-Forwarded-For", "203.0.113.8, 198.51.100.4")
	response := httptest.NewRecorder()

	NewWithCheckout(&fakeDatabase{}, nil, checkouts, discardLogger()).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
	if response.Body.String() != "{\"checkout_url\":\"https://checkout.stripe.com/c/pay/example\"}\n" {
		t.Errorf("body = %q", response.Body.String())
	}
	if response.Header().Get("Access-Control-Allow-Origin") != checkoutOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q", response.Header().Get("Access-Control-Allow-Origin"))
	}
	if checkouts.calls != 1 {
		t.Fatalf("Checkout calls = %d, want 1", checkouts.calls)
	}
	if checkouts.input.RequestID != "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23" || checkouts.input.Plan != billing.PlanMonthly {
		t.Errorf("Checkout input = %+v", checkouts.input)
	}
	if checkouts.input.ClientIP != netip.MustParseAddr("198.51.100.4") {
		t.Errorf("client IP = %q", checkouts.input.ClientIP)
	}
	if checkouts.deadlineRemaining <= 0 || checkouts.deadlineRemaining > checkoutTimeout {
		t.Errorf("Checkout deadline remaining = %s", checkouts.deadlineRemaining)
	}
}

func TestCheckoutRouteIsAbsentWithoutService(t *testing.T) {
	response := httptest.NewRecorder()
	New(&fakeDatabase{}, nil, discardLogger()).ServeHTTP(response, checkoutHTTPRequest(`{"plan":"monthly"}`))

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestCheckoutAllowsRequestWithoutOrigin(t *testing.T) {
	checkouts := &fakeCheckoutService{response: billing.CheckoutSession{URL: "https://checkout.stripe.com/c/pay/example"}}
	response := httptest.NewRecorder()

	NewWithCheckout(&fakeDatabase{}, nil, checkouts, discardLogger()).ServeHTTP(response, checkoutHTTPRequest(`{"plan":"monthly"}`))

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
	if response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty", response.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCheckoutRejectsInvalidHTTPRequests(t *testing.T) {
	largeBody := `{"plan":"` + strings.Repeat("A", maximumBodySize) + `"}`
	tests := []struct {
		name       string
		body       string
		mutate     func(*http.Request)
		wantStatus int
	}{
		{name: "missing content type", body: `{}`, mutate: func(request *http.Request) { request.Header.Del("Content-Type") }, wantStatus: http.StatusUnsupportedMediaType},
		{name: "missing idempotency key", body: `{}`, mutate: func(request *http.Request) { request.Header.Del("Idempotency-Key") }, wantStatus: http.StatusBadRequest},
		{name: "duplicate idempotency key", body: `{}`, mutate: func(request *http.Request) { request.Header.Add("Idempotency-Key", "second") }, wantStatus: http.StatusBadRequest},
		{name: "unknown field", body: `{"plan":"monthly","extra":true}`, wantStatus: http.StatusBadRequest},
		{name: "trailing JSON", body: `{} {}`, wantStatus: http.StatusBadRequest},
		{name: "oversized", body: largeBody, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "foreign origin", body: `{"plan":"monthly"}`, mutate: func(request *http.Request) { request.Header.Set("Origin", "https://example.com") }, wantStatus: http.StatusForbidden},
		{name: "duplicate origin", body: `{"plan":"monthly"}`, mutate: func(request *http.Request) { request.Header.Add("Origin", checkoutOrigin) }, wantStatus: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checkouts := &fakeCheckoutService{}
			request := checkoutHTTPRequest(test.body)
			request.Header.Set("Origin", checkoutOrigin)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()

			NewWithCheckout(&fakeDatabase{}, nil, checkouts, discardLogger()).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if checkouts.calls != 0 {
				t.Errorf("Checkout calls = %d, want 0", checkouts.calls)
			}
		})
	}
}

func TestCheckoutPreflight(t *testing.T) {
	tests := []struct {
		name       string
		origin     string
		method     string
		headers    string
		wantStatus int
	}{
		{name: "allowed", origin: checkoutOrigin, method: http.MethodPost, headers: "content-type, idempotency-key", wantStatus: http.StatusNoContent},
		{name: "foreign origin", origin: "https://example.com", method: http.MethodPost, headers: "content-type, idempotency-key", wantStatus: http.StatusForbidden},
		{name: "wrong method", origin: checkoutOrigin, method: http.MethodGet, headers: "content-type, idempotency-key", wantStatus: http.StatusForbidden},
		{name: "extra header", origin: checkoutOrigin, method: http.MethodPost, headers: "content-type, idempotency-key, authorization", wantStatus: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checkouts := &fakeCheckoutService{}
			request := httptest.NewRequest(http.MethodOptions, "/v1/checkout-sessions", nil)
			request.Header.Set("Origin", test.origin)
			request.Header.Set("Access-Control-Request-Method", test.method)
			request.Header.Set("Access-Control-Request-Headers", test.headers)
			response := httptest.NewRecorder()

			NewWithCheckout(&fakeDatabase{}, nil, checkouts, discardLogger()).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if checkouts.calls != 0 {
				t.Errorf("Checkout calls = %d, want 0", checkouts.calls)
			}
			if test.wantStatus == http.StatusNoContent {
				if response.Header().Get("Access-Control-Allow-Origin") != checkoutOrigin ||
					response.Header().Get("Access-Control-Allow-Methods") != http.MethodPost ||
					response.Header().Get("Access-Control-Allow-Headers") != "Content-Type, Idempotency-Key" {
					t.Errorf("preflight headers = %v", response.Header())
				}
				vary := strings.Join(response.Header().Values("Vary"), ", ")
				for _, name := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
					if !strings.Contains(vary, name) {
						t.Errorf("Vary = %q, want %q", vary, name)
					}
				}
			}
		})
	}
}

func TestCheckoutMapsDomainErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantRetry  string
		retryable  bool
	}{
		{name: "invalid", err: billing.ErrInvalidCheckoutRequest, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "idempotency conflict", err: billing.ErrCheckoutIdempotencyConflict, wantStatus: http.StatusConflict, wantCode: "checkout_idempotency_conflict"},
		{name: "expired", err: billing.ErrCheckoutSessionExpired, wantStatus: http.StatusConflict, wantCode: "checkout_session_expired"},
		{name: "complete", err: billing.ErrCheckoutSessionComplete, wantStatus: http.StatusConflict, wantCode: "checkout_session_complete"},
		{name: "rate limited", err: &billing.CheckoutRateLimitError{RetryAfterSeconds: 42}, wantStatus: http.StatusTooManyRequests, wantCode: "rate_limited", wantRetry: "42", retryable: true},
		{name: "busy", err: billing.ErrCheckoutBusy, wantStatus: http.StatusServiceUnavailable, wantCode: "temporarily_unavailable", wantRetry: "1", retryable: true},
		{name: "Stripe unavailable", err: billing.ErrStripeUnavailable, wantStatus: http.StatusServiceUnavailable, wantCode: "temporarily_unavailable", retryable: true},
		{name: "unexpected", err: errors.New("database unavailable"), wantStatus: http.StatusServiceUnavailable, wantCode: "temporarily_unavailable", retryable: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checkouts := &fakeCheckoutService{err: test.err}
			response := httptest.NewRecorder()

			NewWithCheckout(&fakeDatabase{}, nil, checkouts, discardLogger()).ServeHTTP(response, checkoutHTTPRequest(`{"plan":"monthly"}`))

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if !strings.Contains(response.Body.String(), `"code":"`+test.wantCode+`"`) {
				t.Errorf("body = %q", response.Body.String())
			}
			if got := strings.Contains(response.Body.String(), `"retryable":true`); got != test.retryable {
				t.Errorf("retryable = %t, want %t; body = %q", got, test.retryable, response.Body.String())
			}
			if got := response.Header().Get("Retry-After"); got != test.wantRetry {
				t.Errorf("Retry-After = %q, want %q", got, test.wantRetry)
			}
		})
	}
}

func checkoutHTTPRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/checkout-sessions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23")
	return request
}

type fakeCheckoutService struct {
	response          billing.CheckoutSession
	err               error
	input             billing.CreateCheckoutOrderInput
	calls             int
	deadlineRemaining time.Duration
}

func (f *fakeCheckoutService) CreateCheckoutSession(ctx context.Context, input billing.CreateCheckoutOrderInput) (billing.CheckoutSession, error) {
	f.calls++
	f.input = input
	if deadline, ok := ctx.Deadline(); ok {
		f.deadlineRemaining = time.Until(deadline)
	}
	return f.response, f.err
}
