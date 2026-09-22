package billing

import (
	"context"

	"github.com/stripe/stripe-go/v86"
)

type unsupportedAdjustments struct{}

func (unsupportedAdjustments) RetrieveRefund(context.Context, string) (*stripe.Refund, error) {
	return nil, ErrUnsupportedPurchase
}
func (unsupportedAdjustments) RetrieveDispute(context.Context, string) (*stripe.Dispute, error) {
	return nil, ErrUnsupportedPurchase
}
func (unsupportedAdjustments) RetrieveCharge(context.Context, string) (*stripe.Charge, error) {
	return nil, ErrUnsupportedPurchase
}
func (unsupportedAdjustments) FindInvoicePayment(context.Context, string) (*stripe.InvoicePayment, error) {
	return nil, ErrUnsupportedPurchase
}
func (unsupportedAdjustments) FindPurchase(context.Context, string, string) (*stripe.CheckoutSession, error) {
	return nil, ErrUnsupportedPurchase
}
func (unsupportedAdjustments) CancelSubscription(context.Context, string) error {
	return ErrUnsupportedPurchase
}
