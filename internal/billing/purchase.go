package billing

import (
	"context"
	"errors"

	"github.com/stripe/stripe-go/v86"
)

var ErrUnsupportedPurchase = errors.New("billing event requires an unsupported purchase lifecycle")

func (c *CheckoutClient) RetrievePurchase(ctx context.Context, sessionID string) (*stripe.CheckoutSession, error) {
	if !validStripeID(sessionID, "cs_") {
		return nil, ErrInvalidCheckoutSession
	}
	params := &stripe.CheckoutSessionRetrieveParams{}
	params.AddExpand("line_items.data.price.product")
	params.AddExpand("payment_intent.latest_charge")
	requestCtx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	session, err := c.sessions.Retrieve(requestCtx, sessionID, params)
	if err != nil {
		return nil, sanitizeStripeError(requestCtx, err)
	}
	if session == nil || session.ID != sessionID || session.Object != "checkout.session" || session.Livemode != c.liveMode {
		return nil, ErrInvalidCheckoutSession
	}
	return session, nil
}

func validatePerpetualPurchase(session *stripe.CheckoutSession, order checkoutOrder, productID string) error {
	if err := validatePerpetualPayment(session, order, productID); err != nil {
		return err
	}
	if session.PaymentStatus == stripe.CheckoutSessionPaymentStatusPaid && (session.PaymentIntent.LatestCharge.Refunded || session.PaymentIntent.LatestCharge.Disputed) {
		return ErrInvalidCheckoutSession
	}
	return nil
}

func validatePerpetualPayment(session *stripe.CheckoutSession, order checkoutOrder, productID string) error {
	if order.plan != PlanPerpetualV1 {
		return ErrUnsupportedPurchase
	}
	if session.Mode != stripe.CheckoutSessionModePayment || session.ClientReferenceID != order.id ||
		session.Metadata["order_id"] != order.id || session.Metadata["plan"] != string(order.plan) ||
		session.Metadata["policy_version"] != order.policyVersion ||
		(order.sessionID.Valid && order.sessionID.String != session.ID) ||
		session.ManagedPayments == nil || !session.ManagedPayments.Enabled {
		return ErrInvalidCheckoutSession
	}
	if order.paymentID.Valid && (session.PaymentIntent == nil || session.PaymentIntent.ID != order.paymentID.String) {
		return ErrInvalidCheckoutSession
	}
	if session.LineItems == nil || session.LineItems.HasMore || len(session.LineItems.Data) != 1 {
		return ErrInvalidCheckoutSession
	}
	item := session.LineItems.Data[0]
	if item == nil || item.Quantity != 1 || item.Price == nil || item.Price.ID != order.priceID ||
		item.Price.Product == nil || item.Price.Product.ID != productID || item.Price.Product.Object != "product" ||
		item.Price.Product.Livemode != session.Livemode {
		return ErrInvalidCheckoutSession
	}
	// The catalog is denominated in EUR. Adaptive Pricing can present and charge
	// another currency; fulfillment binds to the purchased Price, not an FX amount.
	if session.PaymentStatus != stripe.CheckoutSessionPaymentStatusPaid {
		if session.PaymentStatus != stripe.CheckoutSessionPaymentStatusUnpaid {
			return ErrInvalidCheckoutSession
		}
		return nil
	}
	if session.Status != stripe.CheckoutSessionStatusComplete || session.Consent == nil ||
		session.Consent.TermsOfService != stripe.CheckoutSessionConsentTermsOfServiceAccepted ||
		session.CustomerDetails == nil || session.CustomerDetails.Email == "" ||
		session.Customer == nil || !validStripeID(session.Customer.ID, "cus_") || session.PaymentIntent == nil {
		return ErrInvalidCheckoutSession
	}
	intent := session.PaymentIntent
	if !validStripeID(intent.ID, "pi_") || intent.Object != "payment_intent" || intent.Livemode != session.Livemode ||
		intent.Status != stripe.PaymentIntentStatusSucceeded || intent.Metadata["order_id"] != order.id ||
		intent.Metadata["plan"] != string(order.plan) || intent.Metadata["policy_version"] != order.policyVersion ||
		intent.LatestCharge == nil || !intent.LatestCharge.Paid {
		return ErrInvalidCheckoutSession
	}
	return nil
}
