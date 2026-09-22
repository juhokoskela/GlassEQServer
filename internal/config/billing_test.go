package config

import "testing"

func TestBillingConfiguration(t *testing.T) {
	values := validValues()
	values["GLASSEQ_STRIPE_SECRET_KEY"] = "sk_test_secret"
	values["GLASSEQ_STRIPE_PERPETUAL_PRICE_ID"] = "price_perpetual"
	values["GLASSEQ_STRIPE_MONTHLY_PRICE_ID"] = "price_monthly"
	values["GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID"] = "prod_perpetual"
	values["GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID"] = "prod_monthly"
	got, err := load(mapLookup(values))
	if err != nil || got.Billing != nil {
		t.Fatalf("unexpected billing worker: %+v, %v", got.Billing, err)
	}
	values["GLASSEQ_BILLING_QUEUE_URL"] = "https://sqs.eu-north-1.amazonaws.com/123456789012/billing"
	values["GLASSEQ_STRIPE_EVENT_SOURCE"] = "aws.partner/stripe.com/ed_test"
	got, err = load(mapLookup(values))
	if err != nil || got.Billing == nil || got.Billing.AccountID != "123456789012" || got.Billing.PerpetualProductID != "prod_perpetual" || got.Billing.MonthlyProductID != "prod_monthly" {
		t.Fatalf("billing configuration: %+v, %v", got.Billing, err)
	}
	for _, key := range []string{"GLASSEQ_STRIPE_SECRET_KEY", "GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID", "GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID", "GLASSEQ_STRIPE_EVENT_SOURCE", "GLASSEQ_BILLING_QUEUE_URL"} {
		t.Run(key, func(t *testing.T) {
			original := values[key]
			delete(values, key)
			defer func() { values[key] = original }()
			if _, err := load(mapLookup(values)); err == nil {
				t.Fatal("incomplete billing configuration accepted")
			}
		})
	}
	for _, queue := range []string{
		"http://sqs.eu-north-1.amazonaws.com/123456789012/billing",
		"https://sqs.us-east-1.amazonaws.com/123456789012/billing",
		"https://sqs.eu-north-1.amazonaws.com/abcdefghijkl/billing",
		"https://sqs.eu-north-1.amazonaws.com/123456789012/billing.fifo",
		"https://sqs.eu-north-1.amazonaws.com/123456789012/billing?token=x",
		"https://user@sqs.eu-north-1.amazonaws.com/123456789012/billing",
	} {
		values["GLASSEQ_BILLING_QUEUE_URL"] = queue
		if _, err := load(mapLookup(values)); err == nil {
			t.Errorf("invalid queue accepted: %s", queue)
		}
	}
}
