package billing

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v86"
)

type listPaymentLinkSessionsFunc func(context.Context, string, string) ([]*stripe.CheckoutSession, bool, error)

func (f listPaymentLinkSessionsFunc) ListPaymentLinkSessions(ctx context.Context, linkID, after string) ([]*stripe.CheckoutSession, bool, error) {
	return f(ctx, linkID, after)
}

func TestReconciliationRecoversMissingPerpetualPurchaseWithPostgreSQL(t *testing.T) {
	p, _, checkout := purchaseFixture(t)
	list := listPaymentLinkSessionsFunc(func(_ context.Context, linkID, after string) ([]*stripe.CheckoutSession, bool, error) {
		if after != "" {
			t.Fatalf("unexpected cursor %q", after)
		}
		if linkID == "plink_perpetual" {
			return []*stripe.CheckoutSession{checkout.session}, false, nil
		}
		return nil, false, nil
	})
	r, err := NewReconciler(p, list)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := r.Run(t.Context(), testCheckoutNow)
	if err != nil || recovered != 1 {
		t.Fatalf("recovered=%d error=%v", recovered, err)
	}
	assertFulfillmentCounts(t, p.database, 1, 1)
	var eventType string
	if err := p.database.QueryRow(`SELECT event_type FROM stripe_events WHERE stripe_event_id = $1`, "reconcile_20260904_cs_purchase").Scan(&eventType); err != nil || eventType != "reconciliation.checkout_session" {
		t.Fatalf("reconciliation record=%q error=%v", eventType, err)
	}
	recovered, err = r.Run(t.Context(), testCheckoutNow)
	if err != nil || recovered != 0 {
		t.Fatalf("repeat recovered=%d error=%v", recovered, err)
	}
	assertFulfillmentCounts(t, p.database, 1, 1)
}

func TestReconciliationRecoversMissingMonthlyPurchaseWithPostgreSQL(t *testing.T) {
	p, _, checkout := monthlyFixture(t)
	list := listPaymentLinkSessionsFunc(func(_ context.Context, linkID, _ string) ([]*stripe.CheckoutSession, bool, error) {
		if linkID == "plink_monthly" {
			return []*stripe.CheckoutSession{checkout.session}, false, nil
		}
		return nil, false, nil
	})
	r, err := NewReconciler(p, list)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := r.Run(t.Context(), testCheckoutNow)
	if err != nil || recovered != 1 {
		t.Fatalf("recovered=%d error=%v", recovered, err)
	}
	assertFulfillmentCounts(t, p.database, 1, 1)
	checkout.subscription.Status = stripe.SubscriptionStatusCanceled
	checkout.subscription.CancellationDetails = &stripe.SubscriptionCancellationDetails{Reason: stripe.SubscriptionCancellationDetailsReasonCancellationRequested}
	p.now = func() time.Time { return testCheckoutNow.Add(24 * time.Hour) }
	recovered, err = r.Run(t.Context(), testCheckoutNow.Add(24*time.Hour))
	if err != nil || recovered != 0 {
		t.Fatalf("monthly refresh recovered=%d error=%v", recovered, err)
	}
	end := testCheckoutNow.AddDate(0, 1, 0)
	assertSubscription(t, p.database, "lapsed", "in_initial", end, end)
	assertFulfillmentCounts(t, p.database, 1, 2)
}

func TestReconciliationRecoversCanceledPaidMonthlyPurchaseWithPostgreSQL(t *testing.T) {
	p, _, checkout := monthlyFixture(t)
	checkout.subscription.Status = stripe.SubscriptionStatusCanceled
	checkout.subscription.CancellationDetails = &stripe.SubscriptionCancellationDetails{Reason: stripe.SubscriptionCancellationDetailsReasonCancellationRequested}
	p.now = func() time.Time { return testCheckoutNow.Add(24 * time.Hour) }
	list := listPaymentLinkSessionsFunc(func(_ context.Context, linkID, _ string) ([]*stripe.CheckoutSession, bool, error) {
		if linkID == "plink_monthly" {
			return []*stripe.CheckoutSession{checkout.session}, false, nil
		}
		return nil, false, nil
	})
	r, err := NewReconciler(p, list)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := r.Run(t.Context(), testCheckoutNow.Add(24*time.Hour))
	if err != nil || recovered != 1 {
		t.Fatalf("recovered=%d error=%v", recovered, err)
	}
	end := testCheckoutNow.AddDate(0, 1, 0)
	assertSubscription(t, p.database, "lapsed", "in_initial", end, end)
	assertFulfillmentCounts(t, p.database, 1, 1)
}

func TestReconciliationRetriesUnfulfilledPurchaseNextDayWithPostgreSQL(t *testing.T) {
	p, _, checkout := purchaseFixture(t)
	listed := *checkout.session
	checkout.session.PaymentStatus = stripe.CheckoutSessionPaymentStatusUnpaid
	list := listPaymentLinkSessionsFunc(func(_ context.Context, linkID, _ string) ([]*stripe.CheckoutSession, bool, error) {
		if linkID == "plink_perpetual" {
			return []*stripe.CheckoutSession{&listed}, false, nil
		}
		return nil, false, nil
	})
	r, err := NewReconciler(p, list)
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := r.Run(t.Context(), testCheckoutNow); recovered != 0 || err == nil {
		t.Fatalf("unpaid hydration recovered=%d error=%v", recovered, err)
	}
	checkout.session.PaymentStatus = stripe.CheckoutSessionPaymentStatusPaid
	if recovered, err := r.Run(t.Context(), testCheckoutNow.Add(24*time.Hour)); recovered != 1 || err != nil {
		t.Fatalf("next day recovered=%d error=%v", recovered, err)
	}
	assertFulfillmentCounts(t, p.database, 1, 2)
}

func TestReconciliationListUsesPaymentLinkAndCursor(t *testing.T) {
	client := adjustmentHTTPClient(t, func(r *http.Request) (int, string) {
		query := r.URL.Query()
		if r.URL.Path != "/v1/checkout/sessions" || query.Get("payment_link") != "plink_perpetual" ||
			query.Get("status") != "complete" || query.Get("limit") != "100" || query.Get("starting_after") != "cs_previous" {
			t.Errorf("unexpected reconciliation request: %s %v", r.URL.Path, query)
		}
		return 200, `{"object":"list","has_more":false,"data":[{"id":"cs_purchase","object":"checkout.session"}]}`
	})
	sessions, more, err := client.ListPaymentLinkSessions(t.Context(), "plink_perpetual", "cs_previous")
	if err != nil || more || len(sessions) != 1 || sessions[0].ID != "cs_purchase" {
		t.Fatalf("sessions=%v more=%t error=%v", sessions, more, err)
	}
	if _, _, err := client.ListPaymentLinkSessions(t.Context(), "plink_perpetual", "invalid"); !errors.Is(err, ErrInvalidCheckoutSession) {
		t.Fatalf("invalid cursor error=%v", err)
	}
}
