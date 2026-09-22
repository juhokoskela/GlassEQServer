package billing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v86"
)

func monthlyPurchase() (*stripe.CheckoutSession, *stripe.Subscription, *stripe.Invoice) {
	session := paidPurchase()
	session.Mode = stripe.CheckoutSessionModeSubscription
	session.Metadata["plan"] = string(PlanMonthly)
	session.PaymentIntent = nil
	session.Subscription = &stripe.Subscription{ID: "sub_purchase"}
	session.Invoice = &stripe.Invoice{ID: "in_initial"}
	price := &stripe.Price{ID: "price_monthly", Product: &stripe.Product{ID: "prod_monthly", Object: "product"}}
	session.LineItems.Data[0].Price = price
	subscription := &stripe.Subscription{
		ID: "sub_purchase", Object: "subscription", Metadata: session.Metadata, Customer: session.Customer,
		Status: stripe.SubscriptionStatusActive, LatestInvoice: &stripe.Invoice{ID: "in_initial"},
		Items: &stripe.SubscriptionItemList{Data: []*stripe.SubscriptionItem{{ID: "si_monthly", Subscription: "sub_purchase", Quantity: 1, Price: price}}},
	}
	return session, subscription, paidMonthlyInvoice("in_initial", testCheckoutNow, testCheckoutNow.AddDate(0, 1, 0))
}

func paidMonthlyInvoice(id string, start, end time.Time) *stripe.Invoice {
	reason := stripe.InvoiceBillingReasonSubscriptionCycle
	if id == "in_initial" {
		reason = stripe.InvoiceBillingReasonSubscriptionCreate
	}
	return &stripe.Invoice{
		ID: id, Object: "invoice", Status: stripe.InvoiceStatusPaid, Customer: &stripe.Customer{ID: "cus_buyer"}, BillingReason: reason,
		Parent: &stripe.InvoiceParent{Type: stripe.InvoiceParentTypeSubscriptionDetails,
			SubscriptionDetails: &stripe.InvoiceParentSubscriptionDetails{Subscription: &stripe.Subscription{ID: "sub_purchase"}}},
		Lines: &stripe.InvoiceLineItemList{Data: []*stripe.InvoiceLineItem{{
			Quantity: 1, Period: &stripe.Period{Start: start.Unix(), End: end.Unix()},
			Parent: &stripe.InvoiceLineItemParent{Type: stripe.InvoiceLineItemParentTypeSubscriptionItemDetails,
				SubscriptionItemDetails: &stripe.InvoiceLineItemParentSubscriptionItemDetails{Subscription: "sub_purchase", SubscriptionItem: "si_monthly"}},
			Pricing: &stripe.InvoiceLineItemPricing{Type: stripe.InvoiceLineItemPricingTypePriceDetails,
				PriceDetails: &stripe.InvoiceLineItemPricingPriceDetails{Price: &stripe.Price{ID: "price_monthly"}, Product: "prod_monthly"}},
		}}},
	}
}

func TestMonthlyPurchaseValidation(t *testing.T) {
	order := purchaseOrder{checkoutOrder: checkoutOrder{id: testCheckoutOrderID, plan: PlanMonthly, policyVersion: PolicyVersion, priceID: "price_monthly"}}
	for name, change := range map[string]func(*stripe.CheckoutSession, *stripe.Subscription, *stripe.Invoice){
		"consent": func(s *stripe.CheckoutSession, _ *stripe.Subscription, _ *stripe.Invoice) { s.Consent = nil },
		"email": func(s *stripe.CheckoutSession, _ *stripe.Subscription, _ *stripe.Invoice) {
			s.CustomerDetails.Email = ""
		},
		"managed payments": func(s *stripe.CheckoutSession, _ *stripe.Subscription, _ *stripe.Invoice) {
			s.ManagedPayments.Enabled = false
		},
		"plan": func(s *stripe.CheckoutSession, _ *stripe.Subscription, _ *stripe.Invoice) {
			s.Metadata["plan"] = "perpetual_v1"
		},
		"subscription price": func(_ *stripe.CheckoutSession, s *stripe.Subscription, _ *stripe.Invoice) {
			s.Items.Data[0].Price.ID = "price_other"
		},
		"subscription customer": func(_ *stripe.CheckoutSession, s *stripe.Subscription, _ *stripe.Invoice) {
			s.Customer = &stripe.Customer{ID: "cus_other"}
		},
		"subscription mode": func(_ *stripe.CheckoutSession, s *stripe.Subscription, _ *stripe.Invoice) { s.Livemode = true },
		"paused collection": func(_ *stripe.CheckoutSession, s *stripe.Subscription, _ *stripe.Invoice) {
			s.PauseCollection = &stripe.SubscriptionPauseCollection{}
		},
		"invoice customer": func(_ *stripe.CheckoutSession, _ *stripe.Subscription, i *stripe.Invoice) {
			i.Customer.ID = "cus_other"
		},
		"invoice subscription": func(_ *stripe.CheckoutSession, _ *stripe.Subscription, i *stripe.Invoice) {
			i.Parent.SubscriptionDetails.Subscription.ID = "sub_other"
		},
		"invoice price": func(_ *stripe.CheckoutSession, _ *stripe.Subscription, i *stripe.Invoice) {
			i.Lines.Data[0].Pricing.PriceDetails.Price.ID = "price_other"
		},
		"invoice product": func(_ *stripe.CheckoutSession, _ *stripe.Subscription, i *stripe.Invoice) {
			i.Lines.Data[0].Pricing.PriceDetails.Product = "prod_other"
		},
		"proration": func(_ *stripe.CheckoutSession, _ *stripe.Subscription, i *stripe.Invoice) {
			i.Lines.Data[0].Parent.SubscriptionItemDetails.Proration = true
		},
		"truncated invoice": func(_ *stripe.CheckoutSession, _ *stripe.Subscription, i *stripe.Invoice) { i.Lines.HasMore = true },
		"invalid period": func(_ *stripe.CheckoutSession, _ *stripe.Subscription, i *stripe.Invoice) {
			i.Lines.Data[0].Period.End = i.Lines.Data[0].Period.Start
		},
		"manual invoice": func(_ *stripe.CheckoutSession, _ *stripe.Subscription, i *stripe.Invoice) {
			i.BillingReason = stripe.InvoiceBillingReasonManual
		},
	} {
		t.Run(name, func(t *testing.T) {
			session, subscription, invoice := monthlyPurchase()
			if err := validateMonthlySession(session, order, "prod_monthly"); err != nil {
				t.Fatal(err)
			}
			if err := validateMonthlySubscription(subscription, session, order, "prod_monthly"); err != nil {
				t.Fatal(err)
			}
			if _, err := monthlyInvoicePeriod(invoice, subscription, order, "prod_monthly"); err != nil {
				t.Fatal(err)
			}
			change(session, subscription, invoice)
			err := validateMonthlySession(session, order, "prod_monthly")
			if err == nil {
				err = validateMonthlySubscription(subscription, session, order, "prod_monthly")
			}
			if err == nil {
				_, err = monthlyInvoicePeriod(invoice, subscription, order, "prod_monthly")
			}
			if !errors.Is(err, ErrInvalidSubscription) {
				t.Fatalf("invalid purchase accepted: %v", err)
			}
		})
	}
}

func TestSubscriptionRecoveryDeadlines(t *testing.T) {
	end := testCheckoutNow.AddDate(0, 1, 0)
	previous := subscriptionProjection{state: "active", periodEnd: end, recoveryUntil: end.Add(14 * 24 * time.Hour), lastPaidInvoice: "in_initial"}
	for _, test := range []struct {
		name         string
		status       stripe.SubscriptionStatus
		cancel       bool
		reason       stripe.SubscriptionCancellationDetailsReason
		paid         bool
		wantState    string
		wantRecovery time.Time
	}{
		{"paid replay", stripe.SubscriptionStatusActive, false, "", true, "active", previous.recoveryUntil},
		{"failed renewal", stripe.SubscriptionStatusPastDue, false, "", false, "recovering", previous.recoveryUntil},
		{"scheduled cancellation", stripe.SubscriptionStatusActive, true, "", true, "ending", end},
		{"failed canceled renewal", stripe.SubscriptionStatusPastDue, true, "", false, "ending", end},
		{"immediate cancellation", stripe.SubscriptionStatusCanceled, false, stripe.SubscriptionCancellationDetailsReasonCancellationRequested, true, "lapsed", end},
		{"retry exhaustion", stripe.SubscriptionStatusCanceled, false, stripe.SubscriptionCancellationDetailsReasonPaymentFailed, false, "lapsed", previous.recoveryUntil},
		{"unpaid", stripe.SubscriptionStatusUnpaid, false, "", false, "lapsed", previous.recoveryUntil},
	} {
		t.Run(test.name, func(t *testing.T) {
			subscription := &stripe.Subscription{Status: test.status, CancelAtPeriodEnd: test.cancel, CancellationDetails: &stripe.SubscriptionCancellationDetails{Reason: test.reason}}
			var paidEnd time.Time
			if test.paid {
				paidEnd = end
			}
			got, err := reconcileSubscription(previous, subscription, "in_initial", paidEnd, testCheckoutNow)
			if err != nil || got.state != test.wantState || !got.recoveryUntil.Equal(test.wantRecovery) || got.periodEnd != end {
				t.Fatalf("projection=%+v error=%v", got, err)
			}
		})
	}
	// The same invoice cannot move the period even if a later response changes its line.
	got, err := reconcileSubscription(previous, &stripe.Subscription{Status: stripe.SubscriptionStatusActive}, "in_initial", end.AddDate(0, 1, 0), testCheckoutNow)
	if err != nil || got.periodEnd != end || got.recoveryUntil != previous.recoveryUntil {
		t.Fatalf("invoice replay extended access: %+v, %v", got, err)
	}
}

type subscriptionBackend struct {
	subscription *stripe.Subscription
	expanded     bool
}

func (b *subscriptionBackend) Retrieve(ctx context.Context, _ string, params *stripe.SubscriptionRetrieveParams) (*stripe.Subscription, error) {
	_, deadline := ctx.Deadline()
	b.expanded = deadline && len(params.Expand) == 1 && *params.Expand[0] == "items.data.price.product"
	return b.subscription, nil
}

type invoiceBackend struct {
	invoice  *stripe.Invoice
	deadline bool
}

func (b *invoiceBackend) Retrieve(ctx context.Context, _ string, _ *stripe.InvoiceRetrieveParams) (*stripe.Invoice, error) {
	_, b.deadline = ctx.Deadline()
	return b.invoice, nil
}

func TestSubscriptionHydration(t *testing.T) {
	_, subscription, invoice := monthlyPurchase()
	subBackend, inBackend := &subscriptionBackend{subscription: subscription}, &invoiceBackend{invoice: invoice}
	client := &CheckoutClient{subscriptions: subBackend, invoices: inBackend}
	if _, err := client.RetrieveSubscription(context.Background(), subscription.ID); err != nil || !subBackend.expanded {
		t.Fatalf("subscription hydration: %v", err)
	}
	if _, err := client.RetrieveInvoice(context.Background(), invoice.ID); err != nil || !inBackend.deadline {
		t.Fatalf("invoice hydration: %v", err)
	}
	subscription.Livemode, invoice.Livemode = true, true
	if _, err := client.RetrieveSubscription(context.Background(), subscription.ID); !errors.Is(err, ErrInvalidSubscription) {
		t.Fatalf("foreign subscription: %v", err)
	}
	if _, err := client.RetrieveInvoice(context.Background(), invoice.ID); !errors.Is(err, ErrInvalidSubscription) {
		t.Fatalf("foreign invoice: %v", err)
	}
}

func TestScheduledCancellationExpiresAtPaidEnd(t *testing.T) {
	end := testCheckoutNow.AddDate(0, 1, 0)
	previous := subscriptionProjection{state: "ending", periodEnd: end, recoveryUntil: end, lastPaidInvoice: "in_initial"}
	got, err := reconcileSubscription(previous, &stripe.Subscription{Status: stripe.SubscriptionStatusActive, CancelAtPeriodEnd: true}, "in_initial", end, end)
	if err != nil || got.state != "lapsed" || got.recoveryUntil != end {
		t.Fatalf("expired cancellation: %+v %v", got, err)
	}
}
