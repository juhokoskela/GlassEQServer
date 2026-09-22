package billing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stripe/stripe-go/v86"
)

var testDestination = EventDestination{Source: "aws.partner/stripe.com/ed_test", Account: "123456789012", Region: "eu-north-1"}

func eventBody(t testing.TB, id, eventType string) []byte {
	t.Helper()
	body := map[string]any{
		"version": "0", "source": testDestination.Source, "account": testDestination.Account,
		"region": testDestination.Region, "detail-type": eventType,
		"detail": map[string]any{
			"id": id, "object": "event", "api_version": StripeAPIVersion,
			"type": eventType, "livemode": false, "created": testCheckoutNow.Unix(),
			"data": map[string]any{"object": map[string]any{"id": "cs_purchase", "object": "checkout.session"}},
		},
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func FuzzDecodeBillingEvent(f *testing.F) {
	f.Add(eventBody(f, "evt_purchase", "checkout.session.completed"))
	f.Add([]byte(`{"detail":null}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = decodeBillingEvent(body, testDestination, testCheckoutNow)
	})
}

func TestBillingEventBoundary(t *testing.T) {
	valid := string(eventBody(t, "evt_purchase", "checkout.session.completed"))
	if _, err := decodeBillingEvent([]byte(valid), testDestination, testCheckoutNow); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"malformed": "{", "oversized": strings.Repeat(" ", maximumBillingEventBytes+1),
		"wrong source":  strings.ReplaceAll(valid, testDestination.Source, "aws.partner/stripe.com/foreign"),
		"wrong account": strings.ReplaceAll(valid, testDestination.Account, "999999999999"),
		"wrong region":  strings.ReplaceAll(valid, "eu-north-1", "us-east-1"),
		"wrong mode":    strings.ReplaceAll(valid, `"livemode":false`, `"livemode":true`),
		"missing mode":  strings.ReplaceAll(valid, `"livemode":false,`, ""),
		"wrong API":     strings.ReplaceAll(valid, StripeAPIVersion, "2020-01-01"),
		"unknown event": strings.ReplaceAll(valid, "checkout.session.completed", "invoice.paid"),
		"future time":   strings.ReplaceAll(valid, `"created":1788523200`, `"created":9999999999`),
		"wrong object":  strings.ReplaceAll(valid, `"object":"checkout.session"`, `"object":"invoice"`),
		"trailing JSON": valid + "{}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeBillingEvent([]byte(body), testDestination, testCheckoutNow); !errors.Is(err, ErrInvalidBillingEvent) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func paidPurchase() *stripe.CheckoutSession {
	metadata := map[string]string{"order_id": testCheckoutOrderID, "plan": string(PlanPerpetualV1), "policy_version": PolicyVersion}
	return &stripe.CheckoutSession{
		ID: "cs_purchase", Object: "checkout.session", Mode: stripe.CheckoutSessionModePayment,
		Status: stripe.CheckoutSessionStatusComplete, PaymentStatus: stripe.CheckoutSessionPaymentStatusPaid,
		ClientReferenceID: testCheckoutOrderID, Metadata: metadata,
		ManagedPayments: &stripe.CheckoutSessionManagedPayments{Enabled: true},
		Consent:         &stripe.CheckoutSessionConsent{TermsOfService: stripe.CheckoutSessionConsentTermsOfServiceAccepted},
		Customer:        &stripe.Customer{ID: "cus_buyer"}, CustomerDetails: &stripe.CheckoutSessionCustomerDetails{Email: "Buyer@Example.com"},
		LineItems: &stripe.LineItemList{Data: []*stripe.LineItem{{Quantity: 1, Price: &stripe.Price{
			ID: "price_perpetual", Product: &stripe.Product{ID: "prod_perpetual", Object: "product"},
		}}}},
		PaymentIntent: &stripe.PaymentIntent{
			ID: "pi_purchase", Object: "payment_intent", Status: stripe.PaymentIntentStatusSucceeded,
			Metadata: metadata, LatestCharge: &stripe.Charge{ID: "ch_purchase", Paid: true},
		},
	}
}

func TestPerpetualPurchaseValidation(t *testing.T) {
	order := checkoutOrder{id: testCheckoutOrderID, plan: PlanPerpetualV1, policyVersion: PolicyVersion,
		priceID: "price_perpetual", sessionID: sql.NullString{String: "cs_purchase", Valid: true}}
	for name, mutate := range map[string]func(*stripe.CheckoutSession){
		"another order":      func(s *stripe.CheckoutSession) { s.ClientReferenceID = "ord_other" },
		"another session":    func(s *stripe.CheckoutSession) { s.ID = "cs_other" },
		"wrong plan":         func(s *stripe.CheckoutSession) { s.Metadata["plan"] = "monthly" },
		"wrong policy":       func(s *stripe.CheckoutSession) { s.Metadata["policy_version"] = "other" },
		"not managed":        func(s *stripe.CheckoutSession) { s.ManagedPayments.Enabled = false },
		"missing consent":    func(s *stripe.CheckoutSession) { s.Consent = nil },
		"missing email":      func(s *stripe.CheckoutSession) { s.CustomerDetails = nil },
		"wrong price":        func(s *stripe.CheckoutSession) { s.LineItems.Data[0].Price.ID = "price_other" },
		"wrong product":      func(s *stripe.CheckoutSession) { s.LineItems.Data[0].Price.Product.ID = "prod_other" },
		"wrong product mode": func(s *stripe.CheckoutSession) { s.LineItems.Data[0].Price.Product.Livemode = true },
		"missing expansion":  func(s *stripe.CheckoutSession) { s.LineItems.Data[0].Price.Product.Object = "" },
		"wrong quantity":     func(s *stripe.CheckoutSession) { s.LineItems.Data[0].Quantity = 2 },
		"extra items":        func(s *stripe.CheckoutSession) { s.LineItems.HasMore = true },
		"no payment required": func(s *stripe.CheckoutSession) {
			s.PaymentStatus = stripe.CheckoutSessionPaymentStatusNoPaymentRequired
		},
		"not complete":             func(s *stripe.CheckoutSession) { s.Status = stripe.CheckoutSessionStatusOpen },
		"refunded":                 func(s *stripe.CheckoutSession) { s.PaymentIntent.LatestCharge.Refunded = true },
		"disputed":                 func(s *stripe.CheckoutSession) { s.PaymentIntent.LatestCharge.Disputed = true },
		"wrong intent mode":        func(s *stripe.CheckoutSession) { s.PaymentIntent.Livemode = true },
		"missing intent expansion": func(s *stripe.CheckoutSession) { s.PaymentIntent.Object = "" },
	} {
		t.Run(name, func(t *testing.T) {
			session := paidPurchase()
			mutate(session)
			if err := validatePerpetualPurchase(session, order, "prod_perpetual"); !errors.Is(err, ErrInvalidCheckoutSession) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	session := paidPurchase()
	session.Currency = stripe.CurrencyUSD
	if err := validatePerpetualPurchase(session, order, "prod_perpetual"); err != nil {
		t.Fatalf("local currency purchase rejected: %v", err)
	}
	session.PaymentStatus = stripe.CheckoutSessionPaymentStatusUnpaid
	session.PaymentIntent = nil
	if err := validatePerpetualPurchase(session, order, "prod_perpetual"); err != nil {
		t.Fatalf("delayed payment rejected: %v", err)
	}
	order.plan = PlanMonthly
	if err := validatePerpetualPurchase(session, order, "prod_perpetual"); !errors.Is(err, ErrUnsupportedPurchase) {
		t.Fatalf("monthly purchase error = %v", err)
	}
}

func TestRetrievePurchaseUsesHydratedSession(t *testing.T) {
	backend := &purchaseBackend{session: paidPurchase()}
	client := &CheckoutClient{sessions: backend}
	if _, err := client.RetrievePurchase(context.Background(), "cs_purchase"); err != nil {
		t.Fatal(err)
	}
	if len(backend.params.Expand) != 2 || *backend.params.Expand[0] != "line_items.data.price.product" ||
		*backend.params.Expand[1] != "payment_intent.latest_charge" {
		t.Fatalf("missing fulfillment expansions: %+v", backend.params.Expand)
	}
	if _, ok := backend.ctx.Deadline(); !ok {
		t.Fatal("Stripe request has no deadline")
	}
	backend.session.Livemode = true
	if _, err := client.RetrievePurchase(context.Background(), "cs_purchase"); !errors.Is(err, ErrInvalidCheckoutSession) {
		t.Fatalf("wrong environment error = %v", err)
	}
}

type purchaseBackend struct {
	session *stripe.CheckoutSession
	params  *stripe.CheckoutSessionRetrieveParams
	ctx     context.Context
}

func (b *purchaseBackend) Create(context.Context, *stripe.CheckoutSessionCreateParams) (*stripe.CheckoutSession, error) {
	return nil, errors.New("unexpected create")
}

func (b *purchaseBackend) Retrieve(ctx context.Context, _ string, params *stripe.CheckoutSessionRetrieveParams) (*stripe.CheckoutSession, error) {
	b.ctx, b.params = ctx, params
	return b.session, nil
}
