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
			spec := CheckoutSessionSpec{OrderID: orderID, Plan: test.plan, PolicyVersion: PolicyVersion}
			backend := &fakeCheckoutSessions{}
			backend.response = checkoutResponse(spec, test.wantMode, false)
			client := testCheckoutClient(backend)

			ctx := context.WithValue(context.Background(), contextKey{}, "request")
			got, err := client.Create(ctx, spec, test.wantPrice, "checkout-01K4D8P6WZCP7G9N4N7V0A9T8S")
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
			assertCheckoutParams(t, backend.params, spec, test.wantPrice, test.wantMode)
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
				assertMetadata(t, backend.params.PaymentIntentData.Metadata, spec)
			}
			if (backend.params.SubscriptionData != nil) != test.wantSubscription {
				t.Errorf("subscription data present = %t", backend.params.SubscriptionData != nil)
			}
			if test.wantSubscription {
				assertMetadata(t, backend.params.SubscriptionData.Metadata, spec)
			}
		})
	}
}

func TestCheckoutClientRejectsInvalidInputBeforeCallingStripe(t *testing.T) {
	validSpec := CheckoutSessionSpec{OrderID: "order", Plan: PlanMonthly, PolicyVersion: PolicyVersion}
	tests := []struct {
		spec    CheckoutSessionSpec
		priceID string
		key     string
	}{
		{spec: CheckoutSessionSpec{Plan: PlanMonthly, PolicyVersion: PolicyVersion}, priceID: "price_monthly", key: "key"},
		{spec: CheckoutSessionSpec{OrderID: strings.Repeat("a", 201), Plan: PlanMonthly, PolicyVersion: PolicyVersion}, priceID: "price_monthly", key: "key"},
		{spec: CheckoutSessionSpec{OrderID: "order", Plan: Plan("annual"), PolicyVersion: PolicyVersion}, priceID: "price_monthly", key: "key"},
		{spec: validSpec, priceID: "invalid", key: "key"},
		{spec: CheckoutSessionSpec{OrderID: "order", Plan: PlanMonthly}, priceID: "price_monthly", key: "key"},
		{spec: validSpec, priceID: "price_monthly"},
		{spec: validSpec, priceID: "price_monthly", key: " key "},
		{spec: validSpec, priceID: "price_monthly", key: strings.Repeat("a", 256)},
	}

	for _, test := range tests {
		backend := &fakeCheckoutSessions{}
		client := testCheckoutClient(backend)
		if _, err := client.Create(context.Background(), test.spec, test.priceID, test.key); err == nil {
			t.Errorf("Create(%+v) succeeded", test.spec)
		}
		if backend.calls != 0 {
			t.Errorf("Stripe calls = %d, want 0", backend.calls)
		}
	}
}

func TestCheckoutClientRejectsInvalidStripeResponse(t *testing.T) {
	spec := CheckoutSessionSpec{OrderID: "order", Plan: PlanMonthly, PolicyVersion: PolicyVersion}
	tests := []struct {
		name    string
		mutate  func(*stripe.CheckoutSession)
		wantErr error
	}{
		{name: "nil managed payments", mutate: func(session *stripe.CheckoutSession) { session.ManagedPayments = nil }, wantErr: ErrInvalidCheckoutSession},
		{name: "managed payments disabled", mutate: func(session *stripe.CheckoutSession) { session.ManagedPayments.Enabled = false }, wantErr: ErrInvalidCheckoutSession},
		{name: "wrong environment", mutate: func(session *stripe.CheckoutSession) { session.Livemode = true }, wantErr: ErrInvalidCheckoutSession},
		{name: "wrong mode", mutate: func(session *stripe.CheckoutSession) { session.Mode = stripe.CheckoutSessionModePayment }, wantErr: ErrInvalidCheckoutSession},
		{name: "wrong order", mutate: func(session *stripe.CheckoutSession) { session.ClientReferenceID = "other" }, wantErr: ErrInvalidCheckoutSession},
		{name: "wrong metadata", mutate: func(session *stripe.CheckoutSession) { session.Metadata["order_id"] = "other" }, wantErr: ErrInvalidCheckoutSession},
		{name: "unknown status", mutate: func(session *stripe.CheckoutSession) { session.Status = "unknown" }, wantErr: ErrInvalidCheckoutSession},
		{name: "untrusted URL", mutate: func(session *stripe.CheckoutSession) { session.URL = "https://example.com/session" }, wantErr: ErrInvalidCheckoutSession},
		{name: "missing ID", mutate: func(session *stripe.CheckoutSession) { session.ID = "" }, wantErr: ErrInvalidCheckoutSession},
		{name: "missing expiry", mutate: func(session *stripe.CheckoutSession) { session.ExpiresAt = 0 }, wantErr: ErrInvalidCheckoutSession},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := checkoutResponse(spec, stripe.CheckoutSessionModeSubscription, false)
			test.mutate(response)
			backend := &fakeCheckoutSessions{response: response}
			client := testCheckoutClient(backend)

			_, err := client.Create(context.Background(), spec, "price_monthly", "key")
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestCheckoutClientModelsStripeSessionStates(t *testing.T) {
	spec := CheckoutSessionSpec{OrderID: "order", Plan: PlanMonthly, PolicyVersion: PolicyVersion}
	tests := []struct {
		name   string
		mutate func(*stripe.CheckoutSession)
		want   CheckoutSessionState
	}{
		{name: "open", mutate: func(*stripe.CheckoutSession) {}, want: CheckoutSessionOpen},
		{name: "expired status", mutate: func(session *stripe.CheckoutSession) {
			session.Status = stripe.CheckoutSessionStatusExpired
			session.URL = ""
		}, want: CheckoutSessionExpired},
		{name: "complete status", mutate: func(session *stripe.CheckoutSession) {
			session.Status = stripe.CheckoutSessionStatusComplete
			session.URL = ""
		}, want: CheckoutSessionComplete},
		{name: "open past expiry", mutate: func(session *stripe.CheckoutSession) {
			session.ExpiresAt = time.Now().Add(-time.Minute).Unix()
		}, want: CheckoutSessionExpired},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := checkoutResponse(spec, stripe.CheckoutSessionModeSubscription, false)
			test.mutate(response)
			client := testCheckoutClient(&fakeCheckoutSessions{response: response})

			got, err := client.Create(context.Background(), spec, "price_monthly", "key")
			if err != nil {
				t.Fatalf("create Checkout Session: %v", err)
			}
			if got.State != test.want {
				t.Errorf("state = %q, want %q", got.State, test.want)
			}
		})
	}
}

func TestCheckoutClientRetrievesExpectedSession(t *testing.T) {
	spec := CheckoutSessionSpec{OrderID: "order", Plan: PlanMonthly, PolicyVersion: PolicyVersion}
	backend := &fakeCheckoutSessions{response: checkoutResponse(spec, stripe.CheckoutSessionModeSubscription, false)}
	client := testCheckoutClient(backend)

	got, err := client.Retrieve(context.Background(), backend.response.ID, spec)
	if err != nil {
		t.Fatalf("retrieve Checkout Session: %v", err)
	}
	if got.ID != backend.response.ID || backend.retrievedID != backend.response.ID {
		t.Errorf("retrieved session = %+v, requested ID %q", got, backend.retrievedID)
	}
	backend.response.ID = "cs_test_other"
	if _, err := client.Retrieve(context.Background(), "cs_test_expected", spec); !errors.Is(err, ErrInvalidCheckoutSession) {
		t.Fatalf("mismatched ID error = %v, want ErrInvalidCheckoutSession", err)
	}
}

func TestCheckoutClientSanitizesStripeError(t *testing.T) {
	backend := &fakeCheckoutSessions{err: &stripe.Error{
		HTTPStatusCode: http.StatusTooManyRequests,
		Code:           stripe.ErrorCodeRateLimit,
		RequestID:      "req_example",
		Msg:            "sensitive upstream message",
	}}
	client := testCheckoutClient(backend)

	_, err := client.Create(context.Background(), testCheckoutSpec(), "price_monthly", "key")
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
	client := testCheckoutClient(backend)

	_, err := client.Create(context.Background(), testCheckoutSpec(), "price_monthly", "key")
	if !errors.Is(err, ErrStripeUnavailable) {
		t.Fatalf("error = %v, want ErrStripeUnavailable", err)
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Errorf("error disclosed Stripe response: %v", err)
	}
}

func TestNewCheckoutClientRejectsIncompleteConfig(t *testing.T) {
	for _, key := range []string{"", "invalid", " sk_test_secret"} {
		if _, err := NewCheckoutClient(key); err == nil {
			t.Errorf("NewCheckoutClient(%q) succeeded", key)
		}
	}
}

func TestNewCheckoutClientDerivesModeFromAPIKey(t *testing.T) {
	tests := []struct {
		key      string
		liveMode bool
	}{
		{key: "sk_test_secret"},
		{key: "rk_test_secret"},
		{key: "sk_live_secret", liveMode: true},
		{key: "rk_live_secret", liveMode: true},
	}

	for _, test := range tests {
		client, err := NewCheckoutClient(test.key)
		if err != nil {
			t.Fatalf("create Checkout client: %v", err)
		}
		if client.liveMode != test.liveMode {
			t.Errorf("key prefix %q produced live mode %t", test.key[:7], client.liveMode)
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

func assertCheckoutParams(t *testing.T, params *stripe.CheckoutSessionCreateParams, spec CheckoutSessionSpec, priceID string, mode stripe.CheckoutSessionMode) {
	t.Helper()
	if params == nil {
		t.Fatal("Stripe parameters are nil")
	}
	if *params.CancelURL != CheckoutCancelURL || *params.SuccessURL != CheckoutSuccessURL {
		t.Errorf("return URLs = %q, %q", *params.SuccessURL, *params.CancelURL)
	}
	if *params.ClientReferenceID != spec.OrderID || *params.Mode != string(mode) {
		t.Errorf("client reference and mode = %q, %q", *params.ClientReferenceID, *params.Mode)
	}
	if params.Currency == nil || *params.Currency != string(stripe.CurrencyEUR) {
		t.Errorf("currency = %v, want %q", params.Currency, stripe.CurrencyEUR)
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
	assertMetadata(t, params.Metadata, spec)
}

func assertMetadata(t *testing.T, metadata map[string]string, spec CheckoutSessionSpec) {
	t.Helper()
	want := map[string]string{
		"order_id":       spec.OrderID,
		"plan":           string(spec.Plan),
		"policy_version": spec.PolicyVersion,
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

func checkoutResponse(spec CheckoutSessionSpec, mode stripe.CheckoutSessionMode, liveMode bool) *stripe.CheckoutSession {
	return &stripe.CheckoutSession{
		ID:                "cs_test_example",
		URL:               "https://checkout.stripe.com/c/pay/example",
		ExpiresAt:         1_800_000_000,
		Status:            stripe.CheckoutSessionStatusOpen,
		Livemode:          liveMode,
		Mode:              mode,
		ClientReferenceID: spec.OrderID,
		ManagedPayments:   &stripe.CheckoutSessionManagedPayments{Enabled: true},
		Metadata: map[string]string{
			"order_id":       spec.OrderID,
			"plan":           string(spec.Plan),
			"policy_version": spec.PolicyVersion,
		},
	}
}

func testCheckoutSpec() CheckoutSessionSpec {
	return CheckoutSessionSpec{OrderID: "order", Plan: PlanMonthly, PolicyVersion: PolicyVersion}
}

func testCheckoutClient(sessions checkoutSessionBackend) *CheckoutClient {
	return &CheckoutClient{sessions: sessions}
}

type fakeCheckoutSessions struct {
	context     context.Context
	params      *stripe.CheckoutSessionCreateParams
	response    *stripe.CheckoutSession
	err         error
	calls       int
	retrievedID string
}

func (f *fakeCheckoutSessions) Retrieve(ctx context.Context, id string, _ *stripe.CheckoutSessionRetrieveParams) (*stripe.CheckoutSession, error) {
	f.calls++
	f.context = ctx
	f.retrievedID = id
	return f.response, f.err
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
