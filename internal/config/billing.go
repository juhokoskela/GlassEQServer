package config

import (
	"errors"
	"strings"
)

type BillingConfig struct {
	WebhookSecret      string
	PerpetualLinkID    string
	MonthlyLinkID      string
	PerpetualProductID string
	MonthlyProductID   string
}

func loadBilling(lookup func(string) (string, bool), stripe *StripeConfig) (*BillingConfig, error) {
	if !anyConfigured(lookup, "GLASSEQ_STRIPE_WEBHOOK_SECRET", "GLASSEQ_STRIPE_PERPETUAL_LINK_ID", "GLASSEQ_STRIPE_MONTHLY_LINK_ID") {
		return nil, nil
	}
	if stripe == nil {
		return nil, errors.New("billing webhook requires Stripe API configuration")
	}
	secret, err := required(lookup, "GLASSEQ_STRIPE_WEBHOOK_SECRET")
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(secret, "whsec_") || len(secret) <= len("whsec_") || strings.ContainsAny(secret, " \t\r\n") {
		return nil, errors.New("invalid Stripe webhook signing secret")
	}
	perpetualLink, err := stripeID(lookup, "GLASSEQ_STRIPE_PERPETUAL_LINK_ID", "plink_")
	if err != nil {
		return nil, err
	}
	monthlyLink, err := stripeID(lookup, "GLASSEQ_STRIPE_MONTHLY_LINK_ID", "plink_")
	if err != nil {
		return nil, err
	}
	product, err := stripeID(lookup, "GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID", "prod_")
	if err != nil {
		return nil, err
	}
	monthlyProduct, err := stripeID(lookup, "GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID", "prod_")
	if err != nil {
		return nil, err
	}
	if perpetualLink == monthlyLink || product == monthlyProduct || stripe.PerpetualPriceID == stripe.MonthlyPriceID {
		return nil, errors.New("Stripe plans must use distinct links, products, and prices")
	}
	return &BillingConfig{WebhookSecret: secret, PerpetualLinkID: perpetualLink, MonthlyLinkID: monthlyLink,
		PerpetualProductID: product, MonthlyProductID: monthlyProduct}, nil
}
