package billing

import (
	"context"
	"time"

	"github.com/stripe/stripe-go/v86"
)

type billingAdjustment struct {
	id, kind, state, chargeID string
	effectiveAt               time.Time
	charge                    *stripe.Charge
}

type adjustmentSnapshot struct {
	adjustment      billingAdjustment
	order           purchaseOrder
	session         *stripe.CheckoutSession
	subscription    *stripe.Subscription
	invoice         *stripe.Invoice
	initial, latest *stripe.Invoice
}

func (p *EventProcessor) retrieveAdjustment(ctx context.Context, event billingEvent, now time.Time) (billingAdjustment, error) {
	a := billingAdjustment{id: event.Data.Object.ID, kind: event.Data.Object.Object}
	var created, amount int64
	var currency stripe.Currency
	var paymentID string
	var refund *stripe.Refund
	if a.kind == "refund" {
		var err error
		refund, err = p.adjustments.RetrieveRefund(ctx, a.id)
		if err != nil {
			return a, err
		}
		if refund == nil || refund.ID != a.id || refund.Object != "refund" || refund.Charge == nil {
			return a, ErrInvalidAdjustment
		}
		a.chargeID, created, amount, currency = refund.Charge.ID, refund.Created, refund.Amount, refund.Currency
		if refund.PaymentIntent != nil {
			paymentID = refund.PaymentIntent.ID
		}
		switch refund.Status {
		case stripe.RefundStatusSucceeded:
			a.state = "blocking"
		case stripe.RefundStatusPending, stripe.RefundStatusRequiresAction, stripe.RefundStatusFailed, stripe.RefundStatusCanceled:
		default:
			return a, ErrInvalidAdjustment
		}
	} else {
		dispute, err := p.adjustments.RetrieveDispute(ctx, a.id)
		if err != nil {
			return a, err
		}
		if dispute == nil || dispute.ID != a.id || dispute.Object != "dispute" || dispute.Livemode != p.destination.LiveMode || dispute.Charge == nil {
			return a, ErrInvalidAdjustment
		}
		a.chargeID, created, amount, currency = dispute.Charge.ID, dispute.Created, dispute.Amount, dispute.Currency
		if dispute.PaymentIntent != nil {
			paymentID = dispute.PaymentIntent.ID
		}
		switch dispute.Status {
		case stripe.DisputeStatusNeedsResponse, stripe.DisputeStatusUnderReview, stripe.DisputeStatusLost:
			a.state = "blocking"
		case stripe.DisputeStatusWon, stripe.DisputeStatusWarningClosed, stripe.DisputeStatusPrevented:
			a.state = "resolved"
		case stripe.DisputeStatusWarningNeedsResponse, stripe.DisputeStatusWarningUnderReview:
		default:
			return a, ErrInvalidAdjustment
		}
	}
	if !validStripeID(a.chargeID, "ch_") || amount <= 0 || created <= 0 || created > now.Add(5*time.Minute).Unix() {
		return a, ErrInvalidAdjustment
	}
	a.effectiveAt = time.Unix(created, 0).UTC()
	charge, err := p.adjustments.RetrieveCharge(ctx, a.chargeID)
	if err != nil {
		return a, err
	}
	if charge == nil || charge.ID != a.chargeID || charge.Object != "charge" || charge.Livemode != p.destination.LiveMode || charge.Amount <= 0 || charge.Currency != currency ||
		(paymentID != "" && (charge.PaymentIntent == nil || charge.PaymentIntent.ID != paymentID)) {
		return a, ErrInvalidAdjustment
	}
	a.charge = charge
	if refund != nil {
		if amount > charge.Amount {
			return a, ErrInvalidAdjustment
		}
		// Partial refunds do not automatically revoke access. A full refund must
		// itself have succeeded; amount_refunded alone can include pending work.
		if amount < charge.Amount {
			a.state = ""
		}
		if a.state == "blocking" && (!charge.Refunded || charge.AmountRefunded < amount) {
			return a, ErrInvalidAdjustment
		}
	}
	return a, nil
}

func (p *EventProcessor) adjustmentIdentity(ctx context.Context, a billingAdjustment) (purchaseIdentity, *stripe.Invoice, *stripe.Subscription, error) {
	var identity purchaseIdentity
	intent := a.charge.PaymentIntent
	if intent == nil {
		return identity, nil, nil, nil
	}
	if !validStripeID(intent.ID, "pi_") || intent.Object != "payment_intent" || intent.Livemode != p.destination.LiveMode {
		return identity, nil, nil, ErrInvalidAdjustment
	}
	identity.paymentID, identity.referenceID = intent.ID, intent.Metadata["order_id"]
	payment, err := p.adjustments.FindInvoicePayment(ctx, intent.ID)
	if err != nil {
		return identity, nil, nil, err
	}
	if payment == nil {
		return identity, nil, nil, nil
	}
	if payment.Invoice == nil || !validStripeID(payment.Invoice.ID, "in_") || payment.Object != "invoice_payment" || payment.Livemode != p.destination.LiveMode ||
		payment.Status != "paid" || payment.Payment == nil || payment.Payment.Type != stripe.InvoicePaymentPaymentTypePaymentIntent || payment.Payment.PaymentIntent == nil || payment.Payment.PaymentIntent.ID != intent.ID {
		return identity, nil, nil, ErrInvalidAdjustment
	}
	invoice, err := p.checkout.RetrieveInvoice(ctx, payment.Invoice.ID)
	if err != nil {
		return identity, nil, nil, err
	}
	if invoice == nil || invoice.ID != payment.Invoice.ID || invoice.Object != "invoice" || invoice.Livemode != p.destination.LiveMode ||
		invoice.Status != stripe.InvoiceStatusPaid || invoice.AmountPaid != a.charge.Amount || payment.AmountPaid != invoice.AmountPaid ||
		invoice.Currency != a.charge.Currency || payment.Currency != invoice.Currency {
		return identity, nil, nil, ErrInvalidAdjustment
	}
	identity.subscriptionID = invoiceSubscriptionID(invoice)
	if identity.subscriptionID == "" {
		return identity, invoice, nil, nil
	}
	subscription, err := p.checkout.RetrieveSubscription(ctx, identity.subscriptionID)
	if err != nil {
		return identity, nil, nil, err
	}
	if subscription == nil || subscription.ID != identity.subscriptionID || subscription.Object != "subscription" || subscription.Livemode != p.destination.LiveMode {
		return identity, nil, nil, ErrInvalidAdjustment
	}
	identity.metadataID = subscription.Metadata["order_id"]
	return identity, invoice, subscription, nil
}

func (p *EventProcessor) hydrateAdjustment(ctx context.Context, event billingEvent, order purchaseOrder, now time.Time) (adjustmentSnapshot, error) {
	view := adjustmentSnapshot{order: order}
	a, err := p.retrieveAdjustment(ctx, event, now)
	if err != nil {
		return view, err
	}
	view.adjustment = a
	_, invoice, subscription, err := p.adjustmentIdentity(ctx, a)
	if err != nil {
		return view, err
	}
	view.invoice, view.subscription = invoice, subscription
	intent := a.charge.PaymentIntent
	if intent == nil || intent.Status != stripe.PaymentIntentStatusSucceeded || !a.charge.Paid || a.charge.Customer == nil || intent.Customer == nil || intent.Customer.ID != a.charge.Customer.ID {
		return view, ErrInvalidAdjustment
	}
	if order.sessionID.Valid {
		view.session, err = p.checkout.RetrievePurchase(ctx, order.sessionID.String)
	} else if order.plan == PlanPerpetualV1 {
		view.session, err = p.adjustments.FindPurchase(ctx, intent.ID, "")
	} else {
		if subscription == nil {
			return view, ErrInvalidAdjustment
		}
		view.session, err = p.adjustments.FindPurchase(ctx, "", subscription.ID)
	}
	if err != nil {
		return view, err
	}
	session := view.session
	if session == nil || session.Object != "checkout.session" || session.Livemode != p.destination.LiveMode || session.Status != stripe.CheckoutSessionStatusComplete ||
		session.Customer == nil || session.Customer.ID != a.charge.Customer.ID {
		return view, ErrInvalidAdjustment
	}
	if order.plan == PlanPerpetualV1 {
		if invoice != nil || session.PaymentIntent == nil || session.PaymentIntent.ID != intent.ID ||
			session.PaymentIntent.LatestCharge == nil || session.PaymentIntent.LatestCharge.ID != a.chargeID {
			return view, ErrInvalidAdjustment
		}
		if err := validatePerpetualPayment(session, order.checkoutOrder, p.products.PerpetualV1); err != nil {
			return view, err
		}
		if session.PaymentStatus != stripe.CheckoutSessionPaymentStatusPaid {
			return view, ErrInvalidAdjustment
		}
	} else {
		if invoice == nil || subscription == nil {
			return view, ErrInvalidAdjustment
		}
		if err := validateMonthlySession(session, order, p.products.Monthly); err != nil {
			return view, err
		}
		if err := validateMonthlySubscription(subscription, session, order, p.products.Monthly); err != nil {
			return view, err
		}
		if _, err := monthlyInvoicePeriod(invoice, subscription, order, p.products.Monthly); err != nil {
			return view, err
		}
		if a.state == "resolved" {
			if session.Invoice == nil || subscription.LatestInvoice == nil {
				return view, ErrInvalidAdjustment
			}
			view.initial, err = p.checkout.RetrieveInvoice(ctx, session.Invoice.ID)
			if err != nil {
				return view, err
			}
			view.latest, err = p.checkout.RetrieveInvoice(ctx, subscription.LatestInvoice.ID)
			if err != nil {
				return view, err
			}
			if view.initial == nil || view.initial.ID != session.Invoice.ID || view.initial.BillingReason != stripe.InvoiceBillingReasonSubscriptionCreate ||
				view.latest == nil || view.latest.ID != subscription.LatestInvoice.ID {
				return view, ErrInvalidAdjustment
			}
			if _, err := monthlyInvoicePeriod(view.initial, subscription, order, p.products.Monthly); err != nil {
				return view, err
			}
			if _, err := monthlyInvoicePeriod(view.latest, subscription, order, p.products.Monthly); err != nil {
				return view, err
			}
		}
	}
	return view, nil
}
