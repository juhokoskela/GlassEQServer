package config

import (
	"errors"
	"net/url"
	"strings"
)

type BillingConfig struct {
	QueueURL           string
	EventSource        string
	AccountID          string
	PerpetualProductID string
	MonthlyProductID   string
}

func loadBilling(lookup func(string) (string, bool), stripe *StripeConfig) (*BillingConfig, error) {
	if !anyConfigured(lookup, "GLASSEQ_BILLING_QUEUE_URL", "GLASSEQ_STRIPE_EVENT_SOURCE") {
		return nil, nil
	}
	if stripe == nil {
		return nil, errors.New("billing event processing requires Stripe Checkout configuration")
	}
	queueURL, err := required(lookup, "GLASSEQ_BILLING_QUEUE_URL")
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(queueURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "sqs.eu-north-1.amazonaws.com" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return nil, errors.New("billing queue must be an SQS HTTPS URL in eu-north-1")
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) != 2 || len(parts[0]) != 12 || len(parts[1]) == 0 || len(parts[1]) > 80 {
		return nil, errors.New("invalid billing queue account or name")
	}
	for _, digit := range parts[0] {
		if digit < '0' || digit > '9' {
			return nil, errors.New("invalid billing queue account")
		}
	}
	for _, character := range parts[1] {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_') {
			return nil, errors.New("billing queue must be a Standard queue")
		}
	}
	source, err := required(lookup, "GLASSEQ_STRIPE_EVENT_SOURCE")
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(source, "aws.partner/stripe.com/") || len(source) <= len("aws.partner/stripe.com/") || len(source) > 256 {
		return nil, errors.New("invalid Stripe EventBridge source")
	}
	product, err := stripeID(lookup, "GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID", "prod_")
	if err != nil {
		return nil, err
	}
	monthlyProduct, err := stripeID(lookup, "GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID", "prod_")
	if err != nil {
		return nil, err
	}
	return &BillingConfig{QueueURL: queueURL, EventSource: source, AccountID: parts[0], PerpetualProductID: product, MonthlyProductID: monthlyProduct}, nil
}
