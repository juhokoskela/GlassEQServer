package billing

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v86"
)

type fakeAdjustments struct {
	database     *sql.DB
	checkout     purchaseRetriever
	session      *stripe.CheckoutSession
	subscription *stripe.Subscription
	charge       *stripe.Charge
	refund       *stripe.Refund
	disputes     map[string]*stripe.Dispute
	payment      *stripe.InvoicePayment
	cancelCalls  int
	cancelError  error
	beforeCancel func(context.Context) error
	now          time.Time
}

func (f *fakeAdjustments) RetrieveRefund(ctx context.Context, _ string) (*stripe.Refund, error) {
	if err := f.database.PingContext(ctx); err != nil {
		return nil, err
	}
	return f.refund, nil
}
func (f *fakeAdjustments) RetrieveDispute(ctx context.Context, id string) (*stripe.Dispute, error) {
	if err := f.database.PingContext(ctx); err != nil {
		return nil, err
	}
	return f.disputes[id], nil
}
func (f *fakeAdjustments) RetrieveCharge(ctx context.Context, _ string) (*stripe.Charge, error) {
	if err := f.database.PingContext(ctx); err != nil {
		return nil, err
	}
	return f.charge, nil
}
func (f *fakeAdjustments) FindInvoicePayment(ctx context.Context, _ string) (*stripe.InvoicePayment, error) {
	if err := f.database.PingContext(ctx); err != nil {
		return nil, err
	}
	return f.payment, nil
}
func (f *fakeAdjustments) FindPurchase(ctx context.Context, _, _ string) (*stripe.CheckoutSession, error) {
	if err := f.database.PingContext(ctx); err != nil {
		return nil, err
	}
	return f.session, nil
}
func (f *fakeAdjustments) CancelSubscription(ctx context.Context, _ string) error {
	if err := f.database.PingContext(ctx); err != nil {
		return err
	}
	f.cancelCalls++
	if f.beforeCancel != nil {
		if err := f.beforeCancel(ctx); err != nil {
			return err
		}
	}
	f.subscription.Status = stripe.SubscriptionStatusCanceled
	f.subscription.CancellationDetails = &stripe.SubscriptionCancellationDetails{Reason: stripe.SubscriptionCancellationDetailsReasonCancellationRequested}
	return f.cancelError
}

func adjustmentFixture(t *testing.T, plan Plan, fulfilled bool) (*EventProcessor, *fakeAdjustments) {
	t.Helper()
	var p *EventProcessor
	var session *stripe.CheckoutSession
	var subscription *stripe.Subscription
	now := time.Now().UTC().Truncate(time.Second)
	amount := int64(2999)
	if plan == PlanMonthly {
		var checkout *monthlyRetriever
		p, _, checkout = monthlyFixture(t)
		session, subscription = checkout.session, checkout.subscription
		checkout.invoices["in_initial"] = paidMonthlyInvoice("in_initial", now, now.AddDate(0, 1, 0))
		amount = 299
		checkout.invoices["in_initial"].AmountPaid = amount
		checkout.invoices["in_initial"].Currency = stripe.CurrencyEUR
	} else {
		var checkout *fakePurchaseRetriever
		p, _, checkout = purchaseFixture(t)
		session = checkout.session
	}
	p.now = func() time.Time { return now }
	intent := &stripe.PaymentIntent{ID: "pi_purchase", Object: "payment_intent", Status: stripe.PaymentIntentStatusSucceeded, Customer: session.Customer,
		LatestCharge: &stripe.Charge{ID: "ch_purchase"}, Metadata: session.Metadata}
	charge := &stripe.Charge{ID: "ch_purchase", Object: "charge", Amount: amount, AmountCaptured: amount, Paid: true, Captured: true, Status: stripe.ChargeStatusSucceeded,
		Currency: stripe.CurrencyEUR, Customer: session.Customer, PaymentIntent: intent}
	f := &fakeAdjustments{database: p.database, checkout: p.checkout, session: session, subscription: subscription, charge: charge, now: now,
		refund:   &stripe.Refund{ID: "re_purchase", Object: "refund", Amount: amount, Created: now.Unix(), Currency: stripe.CurrencyEUR, Status: stripe.RefundStatusSucceeded, Charge: &stripe.Charge{ID: charge.ID}, PaymentIntent: &stripe.PaymentIntent{ID: intent.ID}},
		disputes: map[string]*stripe.Dispute{"du_purchase": {ID: "du_purchase", Object: "dispute", Amount: amount, Created: now.Unix(), Currency: stripe.CurrencyEUR, Status: stripe.DisputeStatusNeedsResponse, Charge: &stripe.Charge{ID: charge.ID}, PaymentIntent: &stripe.PaymentIntent{ID: intent.ID}}},
	}
	if plan == PlanMonthly {
		intent.Metadata = nil
		f.payment = &stripe.InvoicePayment{ID: "inpay_purchase", Object: "invoice_payment", Status: "paid", AmountPaid: amount, Currency: stripe.CurrencyEUR,
			Invoice: &stripe.Invoice{ID: "in_initial"}, Payment: &stripe.InvoicePaymentPayment{Type: stripe.InvoicePaymentPaymentTypePaymentIntent, PaymentIntent: &stripe.PaymentIntent{ID: intent.ID}}}
	} else {
		session.PaymentIntent.LatestCharge = charge
	}
	p.adjustments = f
	if fulfilled {
		monthlyEvent(t, p, "evt_checkout", "checkout.session.completed", "")
	}
	return p, f
}

func (f *fakeAdjustments) fullRefund() {
	f.charge.Refunded = true
	f.charge.AmountRefunded = f.charge.Amount
}

func assertLicenseState(t *testing.T, p *EventProcessor, state string, terminal time.Time) {
	t.Helper()
	var got string
	var gotTerminal sql.NullTime
	if err := p.database.QueryRow(`SELECT l.state, s.terminal_at FROM licenses l LEFT JOIN subscriptions s ON s.license_id = l.id`).Scan(&got, &gotTerminal); err != nil {
		t.Fatal(err)
	}
	if got != state || gotTerminal.Valid != !terminal.IsZero() || (gotTerminal.Valid && !gotTerminal.Time.Equal(terminal)) {
		t.Fatalf("license=%s terminal=%v want=%s %v", got, gotTerminal, state, terminal)
	}
}

func TestRefundRevokesOnlyFullSuccessfulPaymentsWithPostgreSQL(t *testing.T) {
	for _, plan := range []Plan{PlanPerpetualV1, PlanMonthly} {
		t.Run(string(plan), func(t *testing.T) {
			p, f := adjustmentFixture(t, plan, true)
			p.database.SetMaxOpenConns(1)
			for _, status := range []stripe.RefundStatus{stripe.RefundStatusPending, stripe.RefundStatusRequiresAction, stripe.RefundStatusFailed, stripe.RefundStatusCanceled} {
				f.refund.Status = status
				monthlyEvent(t, p, "evt_"+string(status), "refund.updated", "")
				assertLicenseState(t, p, "active", time.Time{})
			}
			f.refund.Status = stripe.RefundStatusSucceeded
			f.refund.Amount--
			monthlyEvent(t, p, "evt_partial", "refund.created", "")
			assertLicenseState(t, p, "active", time.Time{})
			if f.cancelCalls != 0 {
				t.Fatal("partial/failed refund canceled subscription")
			}
			f.refund.Amount++
			f.fullRefund()
			monthlyEvent(t, p, "evt_refunded", "refund.updated", "")
			var terminal time.Time
			if plan == PlanMonthly {
				terminal = f.now
			}
			assertLicenseState(t, p, "refunded", terminal)
			monthlyEvent(t, p, "evt_refunded", "refund.updated", "")
			monthlyEvent(t, p, "evt_refund_duplicate", "refund.created", "")
			monthlyEvent(t, p, "evt_late_checkout", "checkout.session.completed", "")
			assertLicenseState(t, p, "refunded", terminal)
			if plan == PlanMonthly && f.cancelCalls != 1 {
				t.Fatalf("cancellations=%d", f.cancelCalls)
			}
		})
	}
}

func TestMonthlyRefundLostCancellationResponseWithPostgreSQL(t *testing.T) {
	p, f := adjustmentFixture(t, PlanMonthly, true)
	f.fullRefund()
	p.database.SetMaxOpenConns(1)
	f.cancelError = errors.New("lost cancellation response")
	f.beforeCancel = func(ctx context.Context) error {
		var pending bool
		if err := p.database.QueryRowContext(ctx, `SELECT pending AND cancel_required FROM billing_adjustments`).Scan(&pending); err != nil {
			return err
		}
		if !pending {
			return errors.New("cancellation not durably prepared")
		}
		return nil
	}
	body := eventBody(t, "evt_refund", "refund.created")
	if err := p.Process(t.Context(), body); err == nil {
		t.Fatal("lost response acknowledged")
	}
	assertLicenseState(t, p, "active", time.Time{})
	if err := p.Process(t.Context(), eventBody(t, "evt_renewal_race", "customer.subscription.updated")); !errors.Is(err, errBillingSnapshotChanged) {
		t.Fatalf("pending cancellation did not hold reconciliation: %v", err)
	}
	f.cancelError = nil
	if err := p.Process(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	assertLicenseState(t, p, "refunded", f.now)
	if f.cancelCalls != 1 {
		t.Fatalf("retried confirmed cancellation %d times", f.cancelCalls)
	}
	if err := p.Process(t.Context(), eventBody(t, "evt_renewal_race", "customer.subscription.updated")); err != nil {
		t.Fatal(err)
	}
}

func TestDisputeRestorationPreservesOtherRestrictionsWithPostgreSQL(t *testing.T) {
	for _, plan := range []Plan{PlanPerpetualV1, PlanMonthly} {
		t.Run(string(plan), func(t *testing.T) {
			p, f := adjustmentFixture(t, plan, true)
			f.charge.Disputed = true
			monthlyEvent(t, p, "evt_disputed", "charge.dispute.created", "")
			var terminal time.Time
			if plan == PlanMonthly {
				terminal = f.now
			}
			assertLicenseState(t, p, "charged_back", terminal)
			second := *f.disputes["du_purchase"]
			second.ID = "du_second"
			f.disputes[second.ID] = &second
			body := []byte(strings.ReplaceAll(string(eventBody(t, "evt_second", "charge.dispute.created")), "du_purchase", second.ID))
			if err := p.Process(t.Context(), body); err != nil {
				t.Fatal(err)
			}
			f.disputes["du_purchase"].Status = stripe.DisputeStatusWon
			monthlyEvent(t, p, "evt_won_first", "charge.dispute.closed", "")
			assertLicenseState(t, p, "charged_back", terminal)
			second.Status = stripe.DisputeStatusWon
			body = []byte(strings.ReplaceAll(string(eventBody(t, "evt_won_second", "charge.dispute.closed")), "du_purchase", second.ID))
			if err := p.Process(t.Context(), body); err != nil {
				t.Fatal(err)
			}
			assertLicenseState(t, p, "active", time.Time{})
			if plan == PlanMonthly {
				end := f.now.AddDate(0, 1, 0)
				assertSubscription(t, p.database, "lapsed", "in_initial", end, end)
				if f.subscription.Status != stripe.SubscriptionStatusCanceled || f.cancelCalls != 1 {
					t.Fatal("restoration restarted billing")
				}
			}
		})
	}
}

func TestDisputeCannotRestoreRefundOrManualRevocationWithPostgreSQL(t *testing.T) {
	for _, state := range []string{"refunded", "revoked"} {
		t.Run(state, func(t *testing.T) {
			p, f := adjustmentFixture(t, PlanMonthly, true)
			monthlyEvent(t, p, "evt_dispute", "charge.dispute.created", "")
			if state == "refunded" {
				f.fullRefund()
				monthlyEvent(t, p, "evt_refund", "refund.created", "")
			} else {
				if _, err := p.database.Exec(`UPDATE licenses SET state = 'revoked'`); err != nil {
					t.Fatal(err)
				}
			}
			f.disputes["du_purchase"].Status = stripe.DisputeStatusWon
			monthlyEvent(t, p, "evt_won", "charge.dispute.closed", "")
			assertLicenseState(t, p, state, f.now)
		})
	}
}

func TestTerminalEventsBeforeFulfillmentWithPostgreSQL(t *testing.T) {
	for _, plan := range []Plan{PlanPerpetualV1, PlanMonthly} {
		for _, kind := range []string{"refund", "dispute"} {
			t.Run(string(plan)+"/"+kind, func(t *testing.T) {
				p, f := adjustmentFixture(t, plan, false)
				eventType := "charge.dispute.created"
				if kind == "refund" {
					f.fullRefund()
					eventType = "refund.created"
				}
				monthlyEvent(t, p, "evt_terminal", eventType, "")
				assertFulfillmentCounts(t, p.database, 0, 1)
				monthlyEvent(t, p, "evt_checkout", "checkout.session.completed", "")
				assertFulfillmentCounts(t, p.database, 0, 2)
				if kind == "dispute" {
					f.disputes["du_purchase"].Status = stripe.DisputeStatusWon
					monthlyEvent(t, p, "evt_won", "charge.dispute.closed", "")
					assertFulfillmentCounts(t, p.database, 1, 3)
					assertLicenseState(t, p, "active", time.Time{})
				}
			})
		}
	}
}

func TestDisputeResolvedDuringCancellationWithPostgreSQL(t *testing.T) {
	p, f := adjustmentFixture(t, PlanMonthly, true)
	f.beforeCancel = func(context.Context) error {
		f.disputes["du_purchase"].Status = stripe.DisputeStatusWon
		return nil
	}
	monthlyEvent(t, p, "evt_dispute", "charge.dispute.created", "")
	assertLicenseState(t, p, "active", time.Time{})
	end := f.now.AddDate(0, 1, 0)
	assertSubscription(t, p.database, "lapsed", "in_initial", end, end)
	if f.cancelCalls != 1 {
		t.Fatalf("cancellations=%d", f.cancelCalls)
	}
}

func TestMonthlyRenewalRefundAndExpiredDisputeWithPostgreSQL(t *testing.T) {
	t.Run("renewal refund", func(t *testing.T) {
		p, f := adjustmentFixture(t, PlanMonthly, true)
		checkout := p.checkout.(*monthlyRetriever)
		end := f.now.AddDate(0, 1, 0)
		invoice := paidMonthlyInvoice("in_renewal", end, end.AddDate(0, 1, 0))
		invoice.BillingReason = stripe.InvoiceBillingReasonSubscriptionCycle
		invoice.AmountPaid, invoice.Currency = f.charge.Amount, f.charge.Currency
		checkout.invoices[invoice.ID] = invoice
		f.payment.Invoice.ID = invoice.ID
		f.subscription.LatestInvoice = &stripe.Invoice{ID: invoice.ID}
		f.fullRefund()
		monthlyEvent(t, p, "evt_refund", "refund.updated", "")
		assertLicenseState(t, p, "refunded", f.now)
		f.disputes["du_purchase"].Created = f.now.Add(time.Hour).Unix()
		p.now = func() time.Time { return f.now.Add(time.Hour) }
		monthlyEvent(t, p, "evt_dispute", "charge.dispute.created", "")
		assertLicenseState(t, p, "refunded", f.now)
	})
	t.Run("expired restoration", func(t *testing.T) {
		p, f := adjustmentFixture(t, PlanMonthly, true)
		monthlyEvent(t, p, "evt_dispute", "charge.dispute.created", "")
		p.now = func() time.Time { return f.now.AddDate(0, 2, 0) }
		f.disputes["du_purchase"].Status = stripe.DisputeStatusWon
		monthlyEvent(t, p, "evt_won", "charge.dispute.closed", "")
		assertLicenseState(t, p, "charged_back", f.now)
	})
}

func TestAdjustmentBindingsBeforeCancellationWithPostgreSQL(t *testing.T) {
	for _, mismatch := range []string{"environment", "customer", "invoice payment", "price", "order metadata"} {
		t.Run(mismatch, func(t *testing.T) {
			p, f := adjustmentFixture(t, PlanMonthly, true)
			f.fullRefund()
			switch mismatch {
			case "environment":
				f.charge.Livemode = true
			case "customer":
				f.charge.Customer = &stripe.Customer{ID: "cus_other"}
			case "invoice payment":
				f.payment.AmountPaid--
			case "price":
				f.subscription.Items.Data[0].Price.ID = "price_other"
			case "order metadata":
				f.subscription.Metadata = map[string]string{"order_id": "other"}
			}
			if err := p.Process(t.Context(), eventBody(t, "evt_refund", "refund.created")); err == nil {
				t.Fatal("invalid adjustment acknowledged")
			}
			if f.cancelCalls != 0 {
				t.Fatal("invalid adjustment canceled billing")
			}
			assertLicenseState(t, p, "active", time.Time{})
		})
	}
}

func TestAdjustmentCommitFailureAfterCancellationWithPostgreSQL(t *testing.T) {
	p, f := adjustmentFixture(t, PlanMonthly, true)
	f.fullRefund()
	// A constraint failure occurs after cancellation, inside the final transaction.
	if _, err := p.database.Exec(`ALTER TABLE licenses ADD CONSTRAINT test_no_refund CHECK (state <> 'refunded')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = p.database.Exec(`ALTER TABLE licenses DROP CONSTRAINT IF EXISTS test_no_refund`) })
	body := eventBody(t, "evt_refund", "refund.updated")
	if err := p.Process(t.Context(), body); err == nil {
		t.Fatal("failed commit acknowledged")
	}
	assertLicenseState(t, p, "active", time.Time{})
	var pending bool
	if err := p.database.QueryRow(`SELECT pending AND cancel_required FROM billing_adjustments`).Scan(&pending); err != nil || !pending {
		t.Fatalf("lost intent: %v %v", pending, err)
	}
	if _, err := p.database.Exec(`ALTER TABLE licenses DROP CONSTRAINT test_no_refund`); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	assertLicenseState(t, p, "refunded", f.now)
	if f.cancelCalls != 1 {
		t.Fatalf("cancellations=%d", f.cancelCalls)
	}
}

func TestDisputeStatusesAndUnownedAdjustmentsWithPostgreSQL(t *testing.T) {
	for _, status := range []stripe.DisputeStatus{stripe.DisputeStatusWarningNeedsResponse, stripe.DisputeStatusWarningUnderReview, stripe.DisputeStatusWarningClosed, stripe.DisputeStatusPrevented, stripe.DisputeStatusLost} {
		t.Run(string(status), func(t *testing.T) {
			p, f := adjustmentFixture(t, PlanMonthly, true)
			f.disputes["du_purchase"].Status = status
			monthlyEvent(t, p, "evt_dispute", "charge.dispute.closed", "")
			if status == stripe.DisputeStatusLost {
				assertLicenseState(t, p, "charged_back", f.now)
			} else {
				assertLicenseState(t, p, "active", time.Time{})
				if f.cancelCalls != 0 {
					t.Fatal("nonblocking dispute canceled billing")
				}
			}
		})
	}
	for _, plan := range []Plan{PlanMonthly, PlanPerpetualV1} {
		t.Run("unowned/"+string(plan), func(t *testing.T) {
			p, f := adjustmentFixture(t, plan, false)
			if _, err := p.database.Exec(`DELETE FROM checkout_orders`); err != nil {
				t.Fatal(err)
			}
			f.fullRefund()
			monthlyEvent(t, p, "evt_refund", "refund.created", "")
			var outcome string
			if err := p.database.QueryRow(`SELECT outcome FROM stripe_events`).Scan(&outcome); err != nil {
				t.Fatal(err)
			}
			if outcome != "ignored_unowned" || f.cancelCalls != 0 {
				t.Fatalf("outcome=%s cancellations=%d", outcome, f.cancelCalls)
			}
		})
	}
}

func TestRefundWinsOverStaleRenewalSnapshotWithPostgreSQL(t *testing.T) {
	p, f := adjustmentFixture(t, PlanMonthly, true)
	stale := *p
	session, subscription, invoice := monthlyPurchase()
	stale.checkout = &monthlyRetriever{database: p.database, session: session, subscription: subscription, invoices: map[string]*stripe.Invoice{invoice.ID: invoice},
		beforeSubscription: func(ctx context.Context) error {
			f.fullRefund()
			return p.Process(ctx, eventBody(t, "evt_refund", "refund.updated"))
		},
	}
	body := eventBody(t, "evt_stale_renewal", "checkout.session.completed")
	if err := stale.Process(t.Context(), body); !errors.Is(err, errBillingSnapshotChanged) {
		t.Fatalf("stale snapshot result=%v", err)
	}
	assertLicenseState(t, p, "refunded", f.now)
	if err := p.Process(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	assertLicenseState(t, p, "refunded", f.now)
}
