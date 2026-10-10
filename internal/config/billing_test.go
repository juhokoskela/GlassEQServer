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
	values["GLASSEQ_STRIPE_WEBHOOK_SECRET"] = "whsec_test"
	values["GLASSEQ_STRIPE_PERPETUAL_LINK_ID"] = "plink_perpetual"
	values["GLASSEQ_STRIPE_MONTHLY_LINK_ID"] = "plink_monthly"
	got, err = load(mapLookup(values))
	if err != nil || got.Billing == nil || got.Billing.PerpetualLinkID != "plink_perpetual" || got.Billing.MonthlyLinkID != "plink_monthly" || got.Billing.PerpetualProductID != "prod_perpetual" || got.Billing.MonthlyProductID != "prod_monthly" {
		t.Fatalf("billing configuration: %+v, %v", got.Billing, err)
	}
	for _, key := range []string{"GLASSEQ_STRIPE_SECRET_KEY", "GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID", "GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID", "GLASSEQ_STRIPE_WEBHOOK_SECRET", "GLASSEQ_STRIPE_PERPETUAL_LINK_ID", "GLASSEQ_STRIPE_MONTHLY_LINK_ID"} {
		t.Run(key, func(t *testing.T) {
			original := values[key]
			delete(values, key)
			defer func() { values[key] = original }()
			if _, err := load(mapLookup(values)); err == nil {
				t.Fatal("incomplete billing configuration accepted")
			}
		})
	}
	for _, secret := range []string{
		"bad", "whsec_", "whsec_ with spaces",
	} {
		values["GLASSEQ_STRIPE_WEBHOOK_SECRET"] = secret
		if _, err := load(mapLookup(values)); err == nil {
			t.Errorf("invalid webhook secret accepted: %s", secret)
		}
	}
}
