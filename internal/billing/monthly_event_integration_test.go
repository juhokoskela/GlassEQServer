package billing

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
	"github.com/stripe/stripe-go/v86"
)

type monthlyRetriever struct {
	session            *stripe.CheckoutSession
	subscription       *stripe.Subscription
	invoices           map[string]*stripe.Invoice
	database           *sql.DB
	beforeSubscription func(context.Context) error
}

func (f *monthlyRetriever) RetrievePurchase(ctx context.Context, _ string) (*stripe.CheckoutSession, error) {
	if err := f.database.PingContext(ctx); err != nil {
		return nil, err
	}
	return f.session, nil
}
func (f *monthlyRetriever) RetrieveSubscription(ctx context.Context, _ string) (*stripe.Subscription, error) {
	if err := f.database.PingContext(ctx); err != nil {
		return nil, err
	}
	if f.beforeSubscription != nil {
		if err := f.beforeSubscription(ctx); err != nil {
			return nil, err
		}
	}
	return f.subscription, nil
}
func (f *monthlyRetriever) RetrieveInvoice(ctx context.Context, id string) (*stripe.Invoice, error) {
	if err := f.database.PingContext(ctx); err != nil {
		return nil, err
	}
	return f.invoices[id], nil
}

func monthlyFixture(t *testing.T) (*EventProcessor, *activation.Service, *monthlyRetriever) {
	t.Helper()
	p, service, _ := purchaseFixture(t)
	if _, err := p.database.Exec(`UPDATE checkout_orders SET plan = 'monthly', stripe_price_id = 'price_monthly'`); err != nil {
		t.Fatal(err)
	}
	session, subscription, invoice := monthlyPurchase()
	checkout := &monthlyRetriever{session: session, subscription: subscription, invoices: map[string]*stripe.Invoice{invoice.ID: invoice}, database: p.database}
	p.checkout = checkout
	return p, service, checkout
}

func monthlyEvent(t *testing.T, p *EventProcessor, id, kind, objectID string) {
	t.Helper()
	body := eventBody(t, id, kind)
	if strings.HasPrefix(kind, "invoice.") {
		body = []byte(strings.ReplaceAll(string(body), "in_initial", objectID))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Process(ctx, body); err != nil {
		t.Fatal(err)
	}
}

func assertSubscription(t *testing.T, database *sql.DB, state, invoice string, end, recovery time.Time) {
	t.Helper()
	var got subscriptionProjection
	if err := database.QueryRow(`SELECT state, last_paid_invoice_id, billing_period_end, recovery_until FROM subscriptions`).Scan(&got.state, &got.lastPaidInvoice, &got.periodEnd, &got.recoveryUntil); err != nil {
		t.Fatal(err)
	}
	if got.state != state || got.lastPaidInvoice != invoice || !got.periodEnd.Equal(end) || !got.recoveryUntil.Equal(recovery) {
		t.Fatalf("subscription=%+v want %s %s %s %s", got, state, invoice, end, recovery)
	}
}

func TestMonthlyFulfillmentAndEntitlementWithPostgreSQL(t *testing.T) {
	p, service, _ := monthlyFixture(t)
	p.database.SetMaxOpenConns(1)
	monthlyEvent(t, p, "evt_initial", "checkout.session.completed", "")
	monthlyEvent(t, p, "evt_initial", "checkout.session.completed", "")
	monthlyEvent(t, p, "evt_invoice_initial", "invoice.paid", "in_initial")
	end := testCheckoutNow.AddDate(0, 1, 0)
	assertSubscription(t, p.database, "active", "in_initial", end, end.Add(14*24*time.Hour))
	assertFulfillmentCounts(t, p.database, 1, 2)
	var plan, subID string
	if err := p.database.QueryRow(`SELECT plan, stripe_subscription_id FROM licenses`).Scan(&plan, &subID); err != nil || plan != "monthly" || subID != "sub_purchase" {
		t.Fatalf("license=%s %s, %v", plan, subID, err)
	}
	result, err := service.Activate(context.Background(), activation.Input{LicenseKey: deliveredKey(t, p.database),
		InstallationID: "b5c3a3a1-5bb7-4801-882f-05ccf2c0ae66", IdempotencyKey: "5870ddf6-7d70-4bf5-8236-f4c350aa7c57", ClientIP: netip.MustParseAddr("192.0.2.1")})
	if err != nil || result.Status != 201 {
		t.Fatalf("activation=%+v error=%v", result, err)
	}
	var response struct {
		Entitlement string `json:"entitlement"`
	}
	if err := json.Unmarshal(result.Body, &response); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(response.Entitlement, ".")
	if len(parts) != 3 {
		t.Fatal("invalid signed entitlement")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Plan     string `json:"plan"`
		State    string `json:"billing_state"`
		Period   int64  `json:"billing_period_end"`
		Recovery int64  `json:"recovery_until"`
		Expiry   int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Plan != "monthly" || claims.State != "active" || claims.Period != end.Unix() || claims.Recovery != end.Add(14*24*time.Hour).Unix() || claims.Expiry != end.Add(21*24*time.Hour).Unix() {
		t.Fatalf("claims=%+v", claims)
	}
}

func TestMonthlyRenewalRecoveryAndCancellationWithPostgreSQL(t *testing.T) {
	p, _, checkout := monthlyFixture(t)
	monthlyEvent(t, p, "evt_initial", "checkout.session.completed", "")
	end := testCheckoutNow.AddDate(0, 1, 0)
	renewalEnd := end.AddDate(0, 1, 0)
	renewal := paidMonthlyInvoice("in_renewal", end, renewalEnd)
	renewal.Status = stripe.InvoiceStatusOpen
	checkout.invoices[renewal.ID] = renewal
	checkout.subscription.LatestInvoice = &stripe.Invoice{ID: renewal.ID}
	checkout.subscription.Status = stripe.SubscriptionStatusPastDue
	checkout.subscription.Items.Data[0].CurrentPeriodEnd = renewalEnd.Unix()
	p.now = func() time.Time { return end.Add(time.Hour) }
	monthlyEvent(t, p, "evt_failure", "invoice.payment_failed", renewal.ID)
	assertSubscription(t, p.database, "recovering", "in_initial", end, end.Add(14*24*time.Hour))
	checkout.subscription.Status = stripe.SubscriptionStatusCanceled
	checkout.subscription.CancellationDetails = &stripe.SubscriptionCancellationDetails{Reason: stripe.SubscriptionCancellationDetailsReasonPaymentFailed}
	monthlyEvent(t, p, "evt_exhausted", "customer.subscription.deleted", "")
	assertSubscription(t, p.database, "lapsed", "in_initial", end, end.Add(14*24*time.Hour))
	checkout.subscription.Status = stripe.SubscriptionStatusActive
	renewal.Status = stripe.InvoiceStatusPaid
	monthlyEvent(t, p, "evt_recovered", "invoice.paid", renewal.ID)
	assertSubscription(t, p.database, "active", renewal.ID, renewalEnd, renewalEnd.Add(14*24*time.Hour))
	// A late failure notification uses today's paid invoice and subscription state.
	monthlyEvent(t, p, "evt_late_failure", "invoice.payment_failed", "in_initial")
	assertSubscription(t, p.database, "active", renewal.ID, renewalEnd, renewalEnd.Add(14*24*time.Hour))
	checkout.subscription.CancelAtPeriodEnd = true
	monthlyEvent(t, p, "evt_ending", "customer.subscription.updated", "")
	assertSubscription(t, p.database, "ending", renewal.ID, renewalEnd, renewalEnd)
	checkout.subscription.CancelAtPeriodEnd = false
	monthlyEvent(t, p, "evt_cancel_removed", "customer.subscription.updated", "")
	assertSubscription(t, p.database, "active", renewal.ID, renewalEnd, renewalEnd.Add(14*24*time.Hour))
	checkout.subscription.Status = stripe.SubscriptionStatusCanceled
	checkout.subscription.CancellationDetails.Reason = stripe.SubscriptionCancellationDetailsReasonCancellationRequested
	monthlyEvent(t, p, "evt_canceled", "customer.subscription.deleted", "")
	assertSubscription(t, p.database, "lapsed", renewal.ID, renewalEnd, renewalEnd)
	assertFulfillmentCounts(t, p.database, 1, 8)
}

func TestMonthlyInitialPaymentAndAttachmentRaceWithPostgreSQL(t *testing.T) {
	p, _, checkout := monthlyFixture(t)
	body := eventBody(t, "evt_invoice_first", "invoice.paid")
	if err := p.Process(context.Background(), body); !errors.Is(err, errBillingSnapshotChanged) {
		t.Fatalf("unattached invoice: %v", err)
	}
	assertFulfillmentCounts(t, p.database, 0, 0)
	checkout.session.PaymentStatus = stripe.CheckoutSessionPaymentStatusUnpaid
	checkout.invoices["in_initial"].Status = stripe.InvoiceStatusOpen
	checkout.subscription.Status = stripe.SubscriptionStatusIncomplete
	monthlyEvent(t, p, "evt_pending", "checkout.session.completed", "")
	assertFulfillmentCounts(t, p.database, 0, 1)
	checkout.session.PaymentStatus = stripe.CheckoutSessionPaymentStatusPaid
	checkout.invoices["in_initial"].Status = stripe.InvoiceStatusPaid
	checkout.subscription.Status = stripe.SubscriptionStatusActive
	if err := p.Process(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	assertFulfillmentCounts(t, p.database, 1, 2)
}

func TestMonthlyTerminalLicenseCannotBeRestoredWithPostgreSQL(t *testing.T) {
	for _, state := range []string{"refunded", "charged_back", "revoked"} {
		t.Run(state, func(t *testing.T) {
			p, _, checkout := monthlyFixture(t)
			monthlyEvent(t, p, "evt_initial", "checkout.session.completed", "")
			if _, err := p.database.Exec(`UPDATE licenses SET state = $1`, state); err != nil {
				t.Fatal(err)
			}
			end := testCheckoutNow.AddDate(0, 1, 0)
			renewal := paidMonthlyInvoice("in_renewal", end, end.AddDate(0, 1, 0))
			checkout.invoices[renewal.ID] = renewal
			checkout.subscription.LatestInvoice = &stripe.Invoice{ID: renewal.ID}
			monthlyEvent(t, p, "evt_renewal", "invoice.paid", renewal.ID)
			assertSubscription(t, p.database, "active", "in_initial", end, end.Add(14*24*time.Hour))
			var got string
			if err := p.database.QueryRow(`SELECT state FROM licenses`).Scan(&got); err != nil || got != state {
				t.Fatalf("terminal state=%s, %v", got, err)
			}
		})
	}
}

func TestMonthlyConcurrentSnapshotMustRetryWithPostgreSQL(t *testing.T) {
	p, _, checkout := monthlyFixture(t)
	monthlyEvent(t, p, "evt_initial", "checkout.session.completed", "")
	stale := *p
	session, subscription, invoice := monthlyPurchase()
	loaded, release := make(chan struct{}), make(chan struct{})
	stale.checkout = &monthlyRetriever{session: session, subscription: subscription, invoices: map[string]*stripe.Invoice{invoice.ID: invoice}, database: p.database,
		beforeSubscription: func(ctx context.Context) error {
			close(loaded)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	body := eventBody(t, "evt_stale_paid", "checkout.session.completed")
	go func() { result <- stale.Process(ctx, body) }()
	select {
	case <-loaded:
	case <-ctx.Done():
		t.Fatal("hydration did not start")
	}
	checkout.subscription.CancelAtPeriodEnd = true
	monthlyEvent(t, p, "evt_cancel", "customer.subscription.updated", "")
	close(release)
	if err := <-result; !errors.Is(err, errBillingSnapshotChanged) {
		t.Fatalf("stale result=%v", err)
	}
	assertFulfillmentCounts(t, p.database, 1, 2)
	if err := p.Process(ctx, body); err != nil {
		t.Fatal(err)
	}
	end := testCheckoutNow.AddDate(0, 1, 0)
	assertSubscription(t, p.database, "ending", "in_initial", end, end)
	assertFulfillmentCounts(t, p.database, 1, 3)
}

func TestMonthlyRollbackAfterProjectionWriteWithPostgreSQL(t *testing.T) {
	p, _, _ := monthlyFixture(t)
	// Fail the last event write, after the license, projection, order, and outbox.
	if _, err := p.database.Exec(`ALTER TABLE stripe_events ADD CONSTRAINT test_monthly_outcome CHECK (outcome IS NULL OR outcome <> 'fulfilled')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = p.database.Exec(`ALTER TABLE stripe_events DROP CONSTRAINT IF EXISTS test_monthly_outcome`)
	})
	body := eventBody(t, "evt_rollback", "checkout.session.completed")
	if err := p.Process(context.Background(), body); err == nil {
		t.Fatal("injected commit boundary failure was lost")
	}
	assertFulfillmentCounts(t, p.database, 0, 0)
	var count int
	if err := p.database.QueryRow(`SELECT count(*) FROM subscriptions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial projection: %d, %v", count, err)
	}
	if _, err := p.database.Exec(`ALTER TABLE stripe_events DROP CONSTRAINT test_monthly_outcome`); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	assertFulfillmentCounts(t, p.database, 1, 1)
}

func TestMonthlyUnpaidAndTerminalInitialStatesWithPostgreSQL(t *testing.T) {
	for _, status := range []stripe.SubscriptionStatus{stripe.SubscriptionStatusIncomplete, stripe.SubscriptionStatusTrialing,
		stripe.SubscriptionStatusPaused, stripe.SubscriptionStatusIncompleteExpired, stripe.SubscriptionStatusCanceled, stripe.SubscriptionStatusUnpaid} {
		t.Run(string(status), func(t *testing.T) {
			p, _, checkout := monthlyFixture(t)
			checkout.subscription.Status = status
			checkout.session.PaymentStatus = stripe.CheckoutSessionPaymentStatusUnpaid
			checkout.invoices["in_initial"].Status = stripe.InvoiceStatusOpen
			monthlyEvent(t, p, "evt_unpaid", "checkout.session.completed", "")
			assertFulfillmentCounts(t, p.database, 0, 1)
			want := "pending"
			if status == stripe.SubscriptionStatusIncompleteExpired || status == stripe.SubscriptionStatusCanceled || status == stripe.SubscriptionStatusUnpaid {
				want = "failed"
			}
			var got string
			if err := p.database.QueryRow(`SELECT state FROM checkout_orders`).Scan(&got); err != nil || got != want {
				t.Fatalf("state=%s want=%s error=%v", got, want, err)
			}
		})
	}
}

func TestMonthlyOwnedMismatchAndUnownedEventsWithPostgreSQL(t *testing.T) {
	for _, kind := range []string{"metadata", "customer", "price", "invoice", "stored_subscription", "conflicting_order"} {
		t.Run(kind, func(t *testing.T) {
			p, _, checkout := monthlyFixture(t)
			switch kind {
			case "metadata":
				checkout.subscription.Metadata = map[string]string{"order_id": testCheckoutOrderID, "plan": "monthly", "policy_version": "other"}
			case "customer":
				checkout.subscription.Customer = &stripe.Customer{ID: "cus_other"}
			case "price":
				checkout.invoices["in_initial"].Lines.Data[0].Pricing.PriceDetails.Price.ID = "price_other"
			case "invoice":
				checkout.invoices["in_initial"].Parent.SubscriptionDetails.Subscription.ID = "sub_other"
			case "stored_subscription":
				if _, err := p.database.Exec(`UPDATE checkout_orders SET stripe_checkout_session_id = 'cs_purchase', stripe_subscription_id = 'sub_other'`); err != nil {
					t.Fatal(err)
				}
			case "conflicting_order":
				if _, err := p.database.Exec(`INSERT INTO checkout_orders (id, request_id, plan, policy_version, stripe_price_id, state, created_at)
					VALUES ('ord_other', '124fdc57-3793-448f-a0c5-11fed7e77e99', 'monthly', 'v1', 'price_monthly', 'pending', $1)`, testCheckoutNow); err != nil {
					t.Fatal(err)
				}
				checkout.session.Metadata["order_id"] = "ord_other"
			}
			if err := p.Process(context.Background(), eventBody(t, "evt_invalid", "checkout.session.completed")); err == nil {
				t.Fatal("owned mismatch acknowledged")
			}
			assertFulfillmentCounts(t, p.database, 0, 0)
		})
	}
	p, _, checkout := monthlyFixture(t)
	checkout.subscription.Metadata["order_id"] = "ord_unknown"
	monthlyEvent(t, p, "evt_foreign_sub", "customer.subscription.updated", "")
	checkout.invoices["in_initial"].Parent = nil
	monthlyEvent(t, p, "evt_foreign_invoice", "invoice.paid", "in_initial")
	assertFulfillmentCounts(t, p.database, 0, 2)
}

func TestMonthlyOlderInvoicePaymentDoesNotGrantUnpaidPeriodWithPostgreSQL(t *testing.T) {
	p, _, checkout := monthlyFixture(t)
	monthlyEvent(t, p, "evt_initial", "checkout.session.completed", "")
	end := testCheckoutNow.AddDate(0, 1, 0)
	paid := paidMonthlyInvoice("in_recovered", end, end.AddDate(0, 1, 0))
	unpaid := paidMonthlyInvoice("in_due", end.AddDate(0, 1, 0), end.AddDate(0, 2, 0))
	unpaid.Status = stripe.InvoiceStatusOpen
	checkout.invoices[paid.ID], checkout.invoices[unpaid.ID] = paid, unpaid
	checkout.subscription.LatestInvoice = &stripe.Invoice{ID: unpaid.ID}
	checkout.subscription.Status = stripe.SubscriptionStatusPastDue
	monthlyEvent(t, p, "evt_recovered_old", "invoice.paid", paid.ID)
	assertSubscription(t, p.database, "recovering", paid.ID, end.AddDate(0, 1, 0), end.AddDate(0, 1, 0).Add(14*24*time.Hour))
}
