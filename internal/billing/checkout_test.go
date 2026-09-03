package billing

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v86"
)

func TestStripeAPIVersionIsPinnedToManagedPaymentsPreview(t *testing.T) {
	if StripeAPIVersion != "2026-07-29.preview" {
		t.Fatalf("Stripe API version = %q", StripeAPIVersion)
	}
}

func TestCheckoutClientCreatesServerOwnedSession(t *testing.T) {
	tests := []struct {
		name              string
		plan              Plan
		wantPrice         string
		wantMode          stripe.CheckoutSessionMode
		wantCustomer      bool
		wantPaymentIntent bool
		wantSubscription  bool
	}{
		{
			name:              "perpetual",
			plan:              PlanPerpetualV1,
			wantPrice:         "price_perpetual",
			wantMode:          stripe.CheckoutSessionModePayment,
			wantCustomer:      true,
			wantPaymentIntent: true,
		},
		{
			name:             "monthly",
			plan:             PlanMonthly,
			wantPrice:        "price_monthly",
			wantMode:         stripe.CheckoutSessionModeSubscription,
			wantSubscription: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const orderID = "ord_01K4D8P6WZCP7G9N4N7V0A9T8S"
			backend := &fakeCheckoutSessions{}
			backend.response = checkoutResponse(orderID, test.wantMode, false)
			client := newCheckoutClient(CheckoutConfig{
				PerpetualPriceID: "price_perpetual",
				MonthlyPriceID:   "price_monthly",
			}, backend)

			ctx := context.WithValue(context.Background(), contextKey{}, "request")
			got, err := client.Create(ctx, CreateCheckoutSessionInput{
				OrderID:        orderID,
				Plan:           test.plan,
				IdempotencyKey: "checkout-01K4D8P6WZCP7G9N4N7V0A9T8S",
			})
			if err != nil {
				t.Fatalf("create Checkout Session: %v", err)
			}
			if got.ID != backend.response.ID || got.URL != backend.response.URL || !got.ExpiresAt.Equal(time.Unix(backend.response.ExpiresAt, 0).UTC()) {
				t.Errorf("Checkout Session = %+v", got)
			}
			if backend.context.Value(contextKey{}) != "request" {
				t.Error("request context values were not passed to Stripe")
			}
			if _, ok := backend.context.Deadline(); !ok {
				t.Error("Stripe request has no deadline")
			}
			assertCheckoutParams(t, backend.params, test.plan, orderID, test.wantPrice, test.wantMode)
			if (backend.params.CustomerCreation != nil) != test.wantCustomer {
				t.Errorf("customer creation present = %t", backend.params.CustomerCreation != nil)
			}
			if test.wantCustomer && *backend.params.CustomerCreation != string(stripe.CheckoutSessionCustomerCreationAlways) {
				t.Errorf("customer creation = %q", *backend.params.CustomerCreation)
			}
			if (backend.params.PaymentIntentData != nil) != test.wantPaymentIntent {
				t.Errorf("payment intent data present = %t", backend.params.PaymentIntentData != nil)
			}
			if test.wantPaymentIntent {
				assertMetadata(t, backend.params.PaymentIntentData.Metadata, test.plan, orderID)
			}
			if (backend.params.SubscriptionData != nil) != test.wantSubscription {
				t.Errorf("subscription data present = %t", backend.params.SubscriptionData != nil)
			}
			if test.wantSubscription {
				assertMetadata(t, backend.params.SubscriptionData.Metadata, test.plan, orderID)
			}
		})
	}
}

func TestCheckoutClientRejectsInvalidInputBeforeCallingStripe(t *testing.T) {
	tests := []CreateCheckoutSessionInput{
		{Plan: PlanMonthly, IdempotencyKey: "key"},
		{OrderID: "order", Plan: Plan("annual"), IdempotencyKey: "key"},
		{OrderID: "order", Plan: PlanMonthly},
		{OrderID: "order", Plan: PlanMonthly, IdempotencyKey: " key "},
		{OrderID: "order", Plan: PlanMonthly, IdempotencyKey: strings.Repeat("a", 256)},
	}

	for _, input := range tests {
		backend := &fakeCheckoutSessions{}
		client := newCheckoutClient(CheckoutConfig{
			PerpetualPriceID: "price_perpetual",
			MonthlyPriceID:   "price_monthly",
		}, backend)
		if _, err := client.Create(context.Background(), input); err == nil {
			t.Errorf("Create(%+v) succeeded", input)
		}
		if backend.calls != 0 {
			t.Errorf("Stripe calls = %d, want 0", backend.calls)
		}
	}
}

func TestCheckoutClientRejectsInvalidStripeResponse(t *testing.T) {
	const orderID = "order"
	tests := []struct {
		name   string
		mutate func(*stripe.CheckoutSession)
	}{
		{name: "nil managed payments", mutate: func(session *stripe.CheckoutSession) { session.ManagedPayments = nil }},
		{name: "managed payments disabled", mutate: func(session *stripe.CheckoutSession) { session.ManagedPayments.Enabled = false }},
		{name: "wrong environment", mutate: func(session *stripe.CheckoutSession) { session.Livemode = true }},
		{name: "wrong mode", mutate: func(session *stripe.CheckoutSession) { session.Mode = stripe.CheckoutSessionModePayment }},
		{name: "wrong order", mutate: func(session *stripe.CheckoutSession) { session.ClientReferenceID = "other" }},
		{name: "closed", mutate: func(session *stripe.CheckoutSession) { session.Status = stripe.CheckoutSessionStatusComplete }},
		{name: "untrusted URL", mutate: func(session *stripe.CheckoutSession) { session.URL = "https://example.com/session" }},
		{name: "missing ID", mutate: func(session *stripe.CheckoutSession) { session.ID = "" }},
		{name: "missing expiry", mutate: func(session *stripe.CheckoutSession) { session.ExpiresAt = 0 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := checkoutResponse(orderID, stripe.CheckoutSessionModeSubscription, false)
			test.mutate(response)
			backend := &fakeCheckoutSessions{response: response}
			client := newCheckoutClient(CheckoutConfig{MonthlyPriceID: "price_monthly"}, backend)

			_, err := client.Create(context.Background(), CreateCheckoutSessionInput{
				OrderID:        orderID,
				Plan:           PlanMonthly,
				IdempotencyKey: "key",
			})
			if !errors.Is(err, ErrInvalidCheckoutSession) {
				t.Fatalf("error = %v, want ErrInvalidCheckoutSession", err)
			}
		})
	}
}

func TestCheckoutClientSanitizesStripeError(t *testing.T) {
	backend := &fakeCheckoutSessions{err: &stripe.Error{
		HTTPStatusCode: http.StatusTooManyRequests,
		Code:           stripe.ErrorCodeRateLimit,
		RequestID:      "req_example",
		Msg:            "sensitive upstream message",
	}}
	client := newCheckoutClient(CheckoutConfig{MonthlyPriceID: "price_monthly"}, backend)

	_, err := client.Create(context.Background(), CreateCheckoutSessionInput{
		OrderID:        "order",
		Plan:           PlanMonthly,
		IdempotencyKey: "key",
	})
	var requestError *StripeRequestError
	if !errors.As(err, &requestError) {
		t.Fatalf("error = %v, want StripeRequestError", err)
	}
	if requestError.HTTPStatusCode != http.StatusTooManyRequests || requestError.Code != string(stripe.ErrorCodeRateLimit) || requestError.RequestID != "req_example" {
		t.Errorf("Stripe request error = %+v", requestError)
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Errorf("error disclosed Stripe response: %v", err)
	}
}

func TestCheckoutClientSanitizesUnexpectedError(t *testing.T) {
	backend := &fakeCheckoutSessions{err: errors.New("sensitive malformed response")}
	client := newCheckoutClient(CheckoutConfig{MonthlyPriceID: "price_monthly"}, backend)

	_, err := client.Create(context.Background(), CreateCheckoutSessionInput{
		OrderID:        "order",
		Plan:           PlanMonthly,
		IdempotencyKey: "key",
	})
	if !errors.Is(err, ErrStripeUnavailable) {
		t.Fatalf("error = %v, want ErrStripeUnavailable", err)
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Errorf("error disclosed Stripe response: %v", err)
	}
}

func TestNewCheckoutClientRejectsIncompleteConfig(t *testing.T) {
	tests := []CheckoutConfig{
		{},
		{SecretKey: "sk_test_secret"},
		{SecretKey: "sk_test_secret", PerpetualPriceID: "price_perpetual"},
	}
	for _, config := range tests {
		if _, err := NewCheckoutClient(config); err == nil {
			t.Error("NewCheckoutClient succeeded with incomplete configuration")
		}
	}
}

func TestStripeResponseLimit(t *testing.T) {
	transport := responseLimitTransport{next: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("a", stripeResponseLimit+1))),
		}, nil
	})}

	response, err := transport.RoundTrip(&http.Request{})
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer response.Body.Close()
	_, err = io.ReadAll(response.Body)
	var limitError *http.MaxBytesError
	if !errors.As(err, &limitError) {
		t.Fatalf("read error = %v, want MaxBytesError", err)
	}
}

func assertCheckoutParams(t *testing.T, params *stripe.CheckoutSessionCreateParams, plan Plan, orderID, priceID string, mode stripe.CheckoutSessionMode) {
	t.Helper()
	if params == nil {
		t.Fatal("Stripe parameters are nil")
	}
	if *params.CancelURL != CheckoutCancelURL || *params.SuccessURL != CheckoutSuccessURL {
		t.Errorf("return URLs = %q, %q", *params.SuccessURL, *params.CancelURL)
	}
	if *params.ClientReferenceID != orderID || *params.Mode != string(mode) {
		t.Errorf("client reference and mode = %q, %q", *params.ClientReferenceID, *params.Mode)
	}
	if params.IdempotencyKey == nil || *params.IdempotencyKey != "checkout-01K4D8P6WZCP7G9N4N7V0A9T8S" {
		t.Errorf("idempotency key = %v", params.IdempotencyKey)
	}
	if len(params.LineItems) != 1 || *params.LineItems[0].Price != priceID || *params.LineItems[0].Quantity != 1 {
		t.Errorf("line items = %+v", params.LineItems)
	}
	if params.ManagedPayments == nil || params.ManagedPayments.Enabled == nil || !*params.ManagedPayments.Enabled {
		t.Error("Managed Payments is not enabled")
	}
	if params.ConsentCollection == nil || params.ConsentCollection.TermsOfService == nil ||
		*params.ConsentCollection.TermsOfService != string(stripe.CheckoutSessionConsentCollectionTermsOfServiceRequired) {
		t.Error("terms-of-service consent is not required")
	}
	assertMetadata(t, params.Metadata, plan, orderID)
}

func assertMetadata(t *testing.T, metadata map[string]string, plan Plan, orderID string) {
	t.Helper()
	want := map[string]string{
		"order_id":       orderID,
		"plan":           string(plan),
		"policy_version": PolicyVersion,
	}
	if len(metadata) != len(want) {
		t.Errorf("metadata = %v", metadata)
		return
	}
	for key, value := range want {
		if metadata[key] != value {
			t.Errorf("metadata[%q] = %q, want %q", key, metadata[key], value)
		}
	}
}

func checkoutResponse(orderID string, mode stripe.CheckoutSessionMode, liveMode bool) *stripe.CheckoutSession {
	return &stripe.CheckoutSession{
		ID:                "cs_test_example",
		URL:               "https://checkout.stripe.com/c/pay/example",
		ExpiresAt:         1_800_000_000,
		Status:            stripe.CheckoutSessionStatusOpen,
		Livemode:          liveMode,
		Mode:              mode,
		ClientReferenceID: orderID,
		ManagedPayments:   &stripe.CheckoutSessionManagedPayments{Enabled: true},
	}
}

type fakeCheckoutSessions struct {
	context  context.Context
	params   *stripe.CheckoutSessionCreateParams
	response *stripe.CheckoutSession
	err      error
	calls    int
}

func (f *fakeCheckoutSessions) Create(ctx context.Context, params *stripe.CheckoutSessionCreateParams) (*stripe.CheckoutSession, error) {
	f.calls++
	f.context = ctx
	f.params = params
	return f.response, f.err
}

type contextKey struct{}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
