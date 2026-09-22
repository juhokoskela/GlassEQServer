package billing

import (
	"context"
	"errors"
	"time"

	"github.com/stripe/stripe-go/v86"
)

var ErrInvalidSubscription = errors.New("Stripe returned an invalid subscription purchase")

type stripeSubscriptionBackend interface {
	Retrieve(context.Context, string, *stripe.SubscriptionRetrieveParams) (*stripe.Subscription, error)
}

type stripeInvoiceBackend interface {
	Retrieve(context.Context, string, *stripe.InvoiceRetrieveParams) (*stripe.Invoice, error)
}

func (c *CheckoutClient) RetrieveSubscription(ctx context.Context, id string) (*stripe.Subscription, error) {
	if !validStripeID(id, "sub_") {
		return nil, ErrInvalidSubscription
	}
	params := &stripe.SubscriptionRetrieveParams{}
	params.AddExpand("items.data.price.product")
	requestCtx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	subscription, err := c.subscriptions.Retrieve(requestCtx, id, params)
	if err != nil {
		return nil, sanitizeStripeError(requestCtx, err)
	}
	if subscription == nil || subscription.ID != id || subscription.Object != "subscription" || subscription.Livemode != c.liveMode {
		return nil, ErrInvalidSubscription
	}
	return subscription, nil
}

func (c *CheckoutClient) RetrieveInvoice(ctx context.Context, id string) (*stripe.Invoice, error) {
	if !validStripeID(id, "in_") {
		return nil, ErrInvalidSubscription
	}
	requestCtx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	invoice, err := c.invoices.Retrieve(requestCtx, id, &stripe.InvoiceRetrieveParams{})
	if err != nil {
		return nil, sanitizeStripeError(requestCtx, err)
	}
	if invoice == nil || invoice.ID != id || invoice.Object != "invoice" || invoice.Livemode != c.liveMode {
		return nil, ErrInvalidSubscription
	}
	return invoice, nil
}

func invoiceSubscriptionID(invoice *stripe.Invoice) string {
	if invoice.Parent == nil || invoice.Parent.Type != stripe.InvoiceParentTypeSubscriptionDetails ||
		invoice.Parent.SubscriptionDetails == nil || invoice.Parent.SubscriptionDetails.Subscription == nil {
		return ""
	}
	return invoice.Parent.SubscriptionDetails.Subscription.ID
}

func validateMonthlySession(session *stripe.CheckoutSession, order purchaseOrder, productID string) error {
	if order.plan != PlanMonthly || session.Object != "checkout.session" || session.Mode != stripe.CheckoutSessionModeSubscription ||
		session.ClientReferenceID != order.id || !matchingOrderMetadata(session.Metadata, order.checkoutOrder) ||
		(order.sessionID.Valid && order.sessionID.String != session.ID) ||
		session.ManagedPayments == nil || !session.ManagedPayments.Enabled ||
		session.LineItems == nil || session.LineItems.HasMore || len(session.LineItems.Data) != 1 {
		return ErrInvalidSubscription
	}
	item := session.LineItems.Data[0]
	if item == nil || item.Quantity != 1 || !matchingMonthlyPrice(item.Price, order.priceID, productID, session.Livemode) {
		return ErrInvalidSubscription
	}
	if session.PaymentStatus != stripe.CheckoutSessionPaymentStatusPaid && session.PaymentStatus != stripe.CheckoutSessionPaymentStatusUnpaid {
		return ErrInvalidSubscription
	}
	if order.subscriptionID.Valid && (session.Subscription == nil || session.Subscription.ID != order.subscriptionID.String) {
		return ErrInvalidSubscription
	}
	switch session.Status {
	case stripe.CheckoutSessionStatusOpen, stripe.CheckoutSessionStatusExpired:
		if session.PaymentStatus == stripe.CheckoutSessionPaymentStatusPaid {
			return ErrInvalidSubscription
		}
	case stripe.CheckoutSessionStatusComplete:
		if session.Consent == nil || session.Consent.TermsOfService != stripe.CheckoutSessionConsentTermsOfServiceAccepted ||
			session.CustomerDetails == nil || session.CustomerDetails.Email == "" || session.Customer == nil ||
			!validStripeID(session.Customer.ID, "cus_") || session.Subscription == nil || !validStripeID(session.Subscription.ID, "sub_") {
			return ErrInvalidSubscription
		}
	default:
		return ErrInvalidSubscription
	}
	return nil
}

func matchingOrderMetadata(metadata map[string]string, order checkoutOrder) bool {
	return metadata["order_id"] == order.id && metadata["plan"] == string(order.plan) && metadata["policy_version"] == order.policyVersion
}

func matchingMonthlyPrice(price *stripe.Price, priceID, productID string, liveMode bool) bool {
	return price != nil && price.ID == priceID && price.Product != nil && price.Product.ID == productID &&
		price.Product.Object == "product" && price.Product.Livemode == liveMode
}

func validateMonthlySubscription(subscription *stripe.Subscription, session *stripe.CheckoutSession, order purchaseOrder, productID string) error {
	if subscription == nil || subscription.ID != session.Subscription.ID || subscription.Object != "subscription" ||
		subscription.Livemode != session.Livemode || !matchingOrderMetadata(subscription.Metadata, order.checkoutOrder) ||
		subscription.Customer == nil || subscription.Customer.ID != session.Customer.ID ||
		subscription.Items == nil || subscription.Items.HasMore || len(subscription.Items.Data) != 1 || subscription.PauseCollection != nil {
		return ErrInvalidSubscription
	}
	item := subscription.Items.Data[0]
	if item == nil || !validStripeID(item.ID, "si_") || item.Subscription != subscription.ID || item.Quantity != 1 ||
		!matchingMonthlyPrice(item.Price, order.priceID, productID, session.Livemode) {
		return ErrInvalidSubscription
	}
	switch subscription.Status {
	case stripe.SubscriptionStatusActive, stripe.SubscriptionStatusPastDue, stripe.SubscriptionStatusUnpaid,
		stripe.SubscriptionStatusCanceled, stripe.SubscriptionStatusIncomplete, stripe.SubscriptionStatusIncompleteExpired,
		stripe.SubscriptionStatusTrialing, stripe.SubscriptionStatusPaused:
		return nil
	default:
		return ErrInvalidSubscription
	}
}

// Invoice line periods describe paid service. The Subscription's current period
// can already describe the next, unpaid renewal and must not grant access.
func monthlyInvoicePeriod(invoice *stripe.Invoice, subscription *stripe.Subscription, order purchaseOrder, productID string) (time.Time, error) {
	if invoice == nil || !validStripeID(invoice.ID, "in_") || invoice.Object != "invoice" || invoice.Livemode != subscription.Livemode ||
		invoiceSubscriptionID(invoice) != subscription.ID || invoice.Customer == nil || invoice.Customer.ID != subscription.Customer.ID ||
		(invoice.BillingReason != stripe.InvoiceBillingReasonSubscriptionCreate && invoice.BillingReason != stripe.InvoiceBillingReasonSubscriptionCycle) ||
		invoice.Lines == nil || invoice.Lines.HasMore || len(invoice.Lines.Data) != 1 {
		return time.Time{}, ErrInvalidSubscription
	}
	line := invoice.Lines.Data[0]
	if line == nil || line.Quantity != 1 || line.Parent == nil || line.Parent.Type != stripe.InvoiceLineItemParentTypeSubscriptionItemDetails ||
		line.Parent.SubscriptionItemDetails == nil || line.Parent.SubscriptionItemDetails.Proration ||
		line.Parent.SubscriptionItemDetails.Subscription != subscription.ID ||
		line.Parent.SubscriptionItemDetails.SubscriptionItem != subscription.Items.Data[0].ID ||
		line.Pricing == nil || line.Pricing.Type != stripe.InvoiceLineItemPricingTypePriceDetails || line.Pricing.PriceDetails == nil ||
		line.Pricing.PriceDetails.Price == nil || line.Pricing.PriceDetails.Price.ID != order.priceID || line.Pricing.PriceDetails.Product != productID ||
		line.Period == nil || line.Period.Start <= 0 || line.Period.End <= line.Period.Start {
		return time.Time{}, ErrInvalidSubscription
	}
	switch invoice.Status {
	case stripe.InvoiceStatusPaid:
		return time.Unix(line.Period.End, 0).UTC(), nil
	case stripe.InvoiceStatusDraft, stripe.InvoiceStatusOpen, stripe.InvoiceStatusVoid, stripe.InvoiceStatusUncollectible:
		return time.Time{}, nil
	default:
		return time.Time{}, ErrInvalidSubscription
	}
}

type subscriptionProjection struct {
	state           string
	periodEnd       time.Time
	recoveryUntil   time.Time
	lastPaidInvoice string
}

func reconcileSubscription(previous subscriptionProjection, subscription *stripe.Subscription, invoiceID string, paidEnd, now time.Time) (subscriptionProjection, error) {
	next := previous
	if paidEnd.After(previous.periodEnd) && invoiceID != previous.lastPaidInvoice {
		next.periodEnd, next.lastPaidInvoice = paidEnd, invoiceID
		next.recoveryUntil = paidEnd.Add(14 * 24 * time.Hour)
	}
	switch subscription.Status {
	case stripe.SubscriptionStatusActive:
		if subscription.CancelAtPeriodEnd {
			next.state, next.recoveryUntil = "ending", next.periodEnd
		} else if now.Before(next.periodEnd) {
			next.state, next.recoveryUntil = "active", next.periodEnd.Add(14*24*time.Hour)
		} else {
			// A finalized renewal can precede Stripe's past_due transition.
			next.state = "recovering"
			next.recoveryUntil = maxRecoveryDeadline(next.recoveryUntil, next.periodEnd.Add(14*24*time.Hour))
		}
	case stripe.SubscriptionStatusPastDue:
		if subscription.CancelAtPeriodEnd {
			next.state, next.recoveryUntil = "ending", next.periodEnd
		} else {
			next.state = "recovering"
			next.recoveryUntil = maxRecoveryDeadline(next.recoveryUntil, next.periodEnd.Add(14*24*time.Hour))
		}
	case stripe.SubscriptionStatusUnpaid:
		next.state = "lapsed"
	case stripe.SubscriptionStatusCanceled:
		if subscription.CancellationDetails == nil {
			return next, ErrInvalidSubscription
		}
		next.state = "lapsed"
		switch subscription.CancellationDetails.Reason {
		case stripe.SubscriptionCancellationDetailsReasonCancellationRequested:
			next.recoveryUntil = next.periodEnd
		case stripe.SubscriptionCancellationDetailsReasonPaymentFailed, stripe.SubscriptionCancellationDetailsReasonPaymentDisputed:
			// Terminal license state is owned by refund/dispute processing.
		default:
			return next, ErrInvalidSubscription
		}
	default:
		return next, ErrInvalidSubscription
	}
	if next.state == "ending" && !now.Before(next.periodEnd) {
		next.state = "lapsed"
	}
	return next, nil
}

func maxRecoveryDeadline(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
