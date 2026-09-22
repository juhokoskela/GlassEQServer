package billing

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stripe/stripe-go/v86"
)

func adjustmentHTTPClient(t *testing.T, respond func(*http.Request) (int, string)) *CheckoutClient {
	t.Helper()
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("Stripe request has no deadline")
		}
		if r.Header.Get("Stripe-Version") != StripeAPIVersion {
			t.Error("incorrect Stripe API version")
		}
		status, body := respond(r)
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	backends := stripe.NewBackendsWithConfig(&stripe.BackendConfig{HTTPClient: &http.Client{Transport: responseLimitTransport{next: transport}}, MaxNetworkRetries: stripe.Int64(0), EnableTelemetry: stripe.Bool(false), LeveledLogger: &stripe.LeveledLogger{Level: stripe.LevelNull}})
	client := stripe.NewClient("sk_test_fake", stripe.WithBackends(backends))
	return &CheckoutClient{sessions: client.V1CheckoutSessions, sessionList: client.V1CheckoutSessions, refunds: client.V1Refunds, disputes: client.V1Disputes, charges: client.V1Charges, invoicePayments: client.V1InvoicePayments, subscriptionCancel: client.V1Subscriptions}
}

func TestAdjustmentStripeRequests(t *testing.T) {
	client := adjustmentHTTPClient(t, func(r *http.Request) (int, string) {
		q := r.URL.Query()
		switch r.URL.Path {
		case "/v1/refunds/re_purchase":
			return 200, `{"id":"re_purchase","object":"refund"}`
		case "/v1/disputes/du_purchase":
			return 200, `{"id":"du_purchase","object":"dispute","livemode":false}`
		case "/v1/charges/ch_purchase":
			if q.Get("expand[0]") != "payment_intent" {
				t.Errorf("charge query=%v", q)
			}
			return 200, `{"id":"ch_purchase","object":"charge","livemode":false}`
		case "/v1/invoice_payments":
			if q.Get("payment[type]") != "payment_intent" || q.Get("payment[payment_intent]") != "pi_purchase" || q.Get("limit") != "2" {
				t.Errorf("invoice query=%v", q)
			}
			return 200, `{"object":"list","has_more":false,"data":[{"id":"inpay_purchase","object":"invoice_payment","livemode":false,"payment":{"type":"payment_intent","payment_intent":"pi_purchase"}}]}`
		case "/v1/checkout/sessions":
			if q.Get("limit") != "2" || (q.Get("payment_intent") != "pi_purchase" && q.Get("subscription") != "sub_purchase") {
				t.Errorf("session query=%v", q)
			}
			return 200, `{"object":"list","has_more":false,"data":[{"id":"cs_purchase","object":"checkout.session"}]}`
		case "/v1/checkout/sessions/cs_purchase":
			body, err := json.Marshal(paidPurchase())
			if err != nil {
				t.Fatal(err)
			}
			return 200, string(body)
		case "/v1/subscriptions/sub_purchase":
			if r.Method != http.MethodDelete || q.Get("invoice_now") != "false" || q.Get("prorate") != "false" {
				t.Errorf("cancel=%s %v", r.Method, q)
			}
			return 200, `{"id":"sub_purchase","object":"subscription","livemode":false,"status":"canceled"}`
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
			return 500, ""
		}
	})
	if _, err := client.RetrieveRefund(t.Context(), "re_purchase"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RetrieveDispute(t.Context(), "du_purchase"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RetrieveCharge(t.Context(), "ch_purchase"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.FindInvoicePayment(t.Context(), "pi_purchase"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.FindPurchase(t.Context(), "pi_purchase", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.FindPurchase(t.Context(), "", "sub_purchase"); err != nil {
		t.Fatal(err)
	}
	if err := client.CancelSubscription(t.Context(), "sub_purchase"); err != nil {
		t.Fatal(err)
	}
}

func TestAdjustmentStripeRejectsAmbiguousAndForeignResponses(t *testing.T) {
	for _, body := range []string{
		`{"object":"list","has_more":true,"data":[]}`,
		`{"object":"list","has_more":false,"data":[{},{}]}`,
		`{"object":"list","has_more":false,"data":[{"object":"invoice_payment","livemode":true,"payment":{"type":"payment_intent","payment_intent":"pi_purchase"}}]}`,
		`{"object":"list","has_more":false,"data":[{"object":"invoice_payment","livemode":false,"payment":{"type":"payment_intent","payment_intent":"pi_other"}}]}`,
	} {
		calls := 0
		client := adjustmentHTTPClient(t, func(*http.Request) (int, string) { calls++; return 200, body })
		if _, err := client.FindInvoicePayment(t.Context(), "pi_purchase"); !errors.Is(err, ErrInvalidAdjustment) {
			t.Fatalf("error=%v", err)
		}
		if calls != 1 {
			t.Fatalf("unbounded pagination: %d", calls)
		}
	}
	client := adjustmentHTTPClient(t, func(*http.Request) (int, string) {
		return 400, `{"error":{"type":"invalid_request_error","message":"private customer data"}}`
	})
	if err := client.CancelSubscription(t.Context(), "sub_purchase"); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("unsanitized error=%v", err)
	}
}
