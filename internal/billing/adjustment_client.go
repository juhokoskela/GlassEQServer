package billing

import (
	"context"
	"errors"

	"github.com/stripe/stripe-go/v86"
)

var ErrInvalidAdjustment = errors.New("Stripe returned an invalid billing adjustment")

type adjustmentClient interface {
	RetrieveRefund(context.Context, string) (*stripe.Refund, error)
	RetrieveDispute(context.Context, string) (*stripe.Dispute, error)
	RetrieveCharge(context.Context, string) (*stripe.Charge, error)
	FindInvoicePayment(context.Context, string) (*stripe.InvoicePayment, error)
	FindPurchase(context.Context, string, string) (*stripe.CheckoutSession, error)
	CancelSubscription(context.Context, string) error
}

type billingClient interface {
	purchaseRetriever
	adjustmentClient
}

type stripeRefundBackend interface {
	Retrieve(context.Context, string, *stripe.RefundRetrieveParams) (*stripe.Refund, error)
}
type stripeDisputeBackend interface {
	Retrieve(context.Context, string, *stripe.DisputeRetrieveParams) (*stripe.Dispute, error)
}
type stripeChargeBackend interface {
	Retrieve(context.Context, string, *stripe.ChargeRetrieveParams) (*stripe.Charge, error)
}
type stripeInvoicePaymentBackend interface {
	List(context.Context, *stripe.InvoicePaymentListParams) *stripe.V1List[*stripe.InvoicePayment]
}
type stripeSessionListBackend interface {
	List(context.Context, *stripe.CheckoutSessionListParams) *stripe.V1List[*stripe.CheckoutSession]
}
type stripeSubscriptionCancelBackend interface {
	Cancel(context.Context, string, *stripe.SubscriptionCancelParams) (*stripe.Subscription, error)
}

func (c *CheckoutClient) RetrieveRefund(ctx context.Context, id string) (*stripe.Refund, error) {
	if !validStripeID(id, "re_") {
		return nil, ErrInvalidAdjustment
	}
	ctx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	refund, err := c.refunds.Retrieve(ctx, id, &stripe.RefundRetrieveParams{})
	if err != nil {
		return nil, sanitizeStripeError(ctx, err)
	}
	// Refund has no livemode field; its hydrated Charge binds the environment.
	if refund == nil || refund.ID != id || refund.Object != "refund" {
		return nil, ErrInvalidAdjustment
	}
	return refund, nil
}

func (c *CheckoutClient) RetrieveDispute(ctx context.Context, id string) (*stripe.Dispute, error) {
	if !validStripeID(id, "du_") {
		return nil, ErrInvalidAdjustment
	}
	ctx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	dispute, err := c.disputes.Retrieve(ctx, id, &stripe.DisputeRetrieveParams{})
	if err != nil {
		return nil, sanitizeStripeError(ctx, err)
	}
	if dispute == nil || dispute.ID != id || dispute.Object != "dispute" || dispute.Livemode != c.liveMode {
		return nil, ErrInvalidAdjustment
	}
	return dispute, nil
}

func (c *CheckoutClient) RetrieveCharge(ctx context.Context, id string) (*stripe.Charge, error) {
	if !validStripeID(id, "ch_") {
		return nil, ErrInvalidAdjustment
	}
	ctx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	params := &stripe.ChargeRetrieveParams{}
	params.AddExpand("payment_intent")
	charge, err := c.charges.Retrieve(ctx, id, params)
	if err != nil {
		return nil, sanitizeStripeError(ctx, err)
	}
	if charge == nil || charge.ID != id || charge.Object != "charge" || charge.Livemode != c.liveMode {
		return nil, ErrInvalidAdjustment
	}
	return charge, nil
}

func (c *CheckoutClient) FindInvoicePayment(ctx context.Context, paymentID string) (*stripe.InvoicePayment, error) {
	if !validStripeID(paymentID, "pi_") {
		return nil, ErrInvalidAdjustment
	}
	ctx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	params := &stripe.InvoicePaymentListParams{Payment: &stripe.InvoicePaymentListPaymentParams{Type: stripe.String("payment_intent"), PaymentIntent: stripe.String(paymentID)}}
	params.Limit = stripe.Int64(2)
	list := c.invoicePayments.List(ctx, params)
	if list == nil {
		return nil, ErrInvalidAdjustment
	}
	if err := list.Err(); err != nil {
		return nil, sanitizeStripeError(ctx, err)
	}
	if list.Meta().HasMore || len(list.Data()) > 1 {
		return nil, ErrInvalidAdjustment
	}
	if len(list.Data()) == 0 {
		return nil, nil
	}
	payment := list.Data()[0]
	if payment == nil || payment.Object != "invoice_payment" || payment.Livemode != c.liveMode || payment.Payment == nil ||
		payment.Payment.Type != stripe.InvoicePaymentPaymentTypePaymentIntent || payment.Payment.PaymentIntent == nil || payment.Payment.PaymentIntent.ID != paymentID {
		return nil, ErrInvalidAdjustment
	}
	return payment, nil
}

func (c *CheckoutClient) FindPurchase(ctx context.Context, paymentID, subscriptionID string) (*stripe.CheckoutSession, error) {
	if (paymentID == "") == (subscriptionID == "") {
		return nil, ErrInvalidAdjustment
	}
	ctx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	params := &stripe.CheckoutSessionListParams{}
	if paymentID != "" {
		if !validStripeID(paymentID, "pi_") {
			return nil, ErrInvalidAdjustment
		}
		params.PaymentIntent = stripe.String(paymentID)
	} else {
		if !validStripeID(subscriptionID, "sub_") {
			return nil, ErrInvalidAdjustment
		}
		params.Subscription = stripe.String(subscriptionID)
	}
	params.Limit = stripe.Int64(2)
	list := c.sessionList.List(ctx, params)
	if list == nil {
		return nil, ErrInvalidAdjustment
	}
	if err := list.Err(); err != nil {
		return nil, sanitizeStripeError(ctx, err)
	}
	if list.Meta().HasMore || len(list.Data()) != 1 || list.Data()[0] == nil {
		return nil, ErrInvalidAdjustment
	}
	return c.RetrievePurchase(ctx, list.Data()[0].ID)
}

func (c *CheckoutClient) CancelSubscription(ctx context.Context, id string) error {
	if !validStripeID(id, "sub_") {
		return ErrInvalidAdjustment
	}
	ctx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	params := &stripe.SubscriptionCancelParams{InvoiceNow: stripe.Bool(false), Prorate: stripe.Bool(false)}
	subscription, err := c.subscriptionCancel.Cancel(ctx, id, params)
	if err != nil {
		return sanitizeStripeError(ctx, err)
	}
	if subscription == nil || subscription.ID != id || subscription.Object != "subscription" || subscription.Livemode != c.liveMode || subscription.Status != stripe.SubscriptionStatusCanceled {
		return ErrInvalidAdjustment
	}
	return nil
}
