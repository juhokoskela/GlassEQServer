package billing

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stripe/stripe-go/v86"
)

func TestCheckoutClientChecksCatalog(t *testing.T) {
	catalog := testCatalogSpec()
	prices := &fakeStripePrices{responses: map[string]*stripe.Price{
		catalog.Perpetual.PriceID: testCatalogPrice(catalog.Perpetual, perpetualPriceAmount, false),
		catalog.Monthly.PriceID:   testCatalogPrice(catalog.Monthly, monthlyPriceAmount, true),
	}}
	client := &CheckoutClient{prices: prices}

	if err := client.CheckCatalog(context.Background(), catalog); err != nil {
		t.Fatalf("check catalog: %v", err)
	}
	if strings.Join(prices.ids, ",") != catalog.Perpetual.PriceID+","+catalog.Monthly.PriceID {
		t.Errorf("retrieved Price IDs = %v", prices.ids)
	}
	if !prices.hasDeadline {
		t.Error("Stripe catalog requests have no deadline")
	}
}

func TestCheckoutClientRejectsInvalidCatalogBeforeStripe(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CatalogSpec)
	}{
		{name: "perpetual Price", mutate: func(catalog *CatalogSpec) { catalog.Perpetual.PriceID = "invalid" }},
		{name: "perpetual Product", mutate: func(catalog *CatalogSpec) { catalog.Perpetual.ProductID = "invalid" }},
		{name: "monthly Price", mutate: func(catalog *CatalogSpec) { catalog.Monthly.PriceID = "invalid" }},
		{name: "monthly Product", mutate: func(catalog *CatalogSpec) { catalog.Monthly.ProductID = "invalid" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := testCatalogSpec()
			test.mutate(&catalog)
			prices := &fakeStripePrices{}
			client := &CheckoutClient{prices: prices}

			if err := client.CheckCatalog(context.Background(), catalog); err == nil {
				t.Fatal("catalog check succeeded")
			}
			if len(prices.ids) != 0 {
				t.Errorf("Stripe calls = %d, want 0", len(prices.ids))
			}
		})
	}
}

func TestCatalogPriceValidation(t *testing.T) {
	configured := CatalogPrice{PriceID: "price_monthly", ProductID: "prod_monthly"}
	expected := catalogPriceExpectation{plan: PlanMonthly, configured: configured, amount: monthlyPriceAmount, recurring: true}
	tests := []struct {
		name     string
		mutate   func(*stripe.Price)
		empty    bool
		liveMode bool
	}{
		{name: "empty response", empty: true},
		{name: "wrong ID", mutate: func(price *stripe.Price) { price.ID = "price_other" }},
		{name: "wrong object", mutate: func(price *stripe.Price) { price.Object = "plan" }},
		{name: "deleted", mutate: func(price *stripe.Price) { price.Deleted = true }},
		{name: "inactive", mutate: func(price *stripe.Price) { price.Active = false }},
		{name: "wrong environment", liveMode: true},
		{name: "wrong currency", mutate: func(price *stripe.Price) { price.Currency = stripe.CurrencyUSD }},
		{name: "tiered", mutate: func(price *stripe.Price) { price.BillingScheme = stripe.PriceBillingSchemeTiered }},
		{name: "custom amount", mutate: func(price *stripe.Price) { price.CustomUnitAmount = &stripe.PriceCustomUnitAmount{} }},
		{name: "wrong amount", mutate: func(price *stripe.Price) { price.UnitAmount++ }},
		{name: "inclusive tax", mutate: func(price *stripe.Price) { price.TaxBehavior = stripe.PriceTaxBehaviorInclusive }},
		{name: "wrong Product", mutate: func(price *stripe.Price) { price.Product.ID = "prod_other" }},
		{name: "one-time", mutate: func(price *stripe.Price) { price.Type = stripe.PriceTypeOneTime; price.Recurring = nil }},
		{name: "wrong interval", mutate: func(price *stripe.Price) { price.Recurring.Interval = stripe.PriceRecurringIntervalYear }},
		{name: "wrong interval count", mutate: func(price *stripe.Price) { price.Recurring.IntervalCount = 2 }},
		{name: "metered", mutate: func(price *stripe.Price) { price.Recurring.UsageType = stripe.PriceRecurringUsageTypeMetered }},
		{name: "trial", mutate: func(price *stripe.Price) { price.Recurring.TrialPeriodDays = 7 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			price := testCatalogPrice(configured, monthlyPriceAmount, true)
			if test.empty {
				price = nil
			}
			if test.mutate != nil {
				test.mutate(price)
			}
			if err := validateCatalogPrice(price, expected, test.liveMode); err == nil {
				t.Fatal("Price validation succeeded")
			}
		})
	}
}

func TestCatalogPriceValidationAcceptsPerpetualPrice(t *testing.T) {
	configured := CatalogPrice{PriceID: "price_perpetual", ProductID: "prod_perpetual"}
	expected := catalogPriceExpectation{plan: PlanPerpetualV1, configured: configured, amount: perpetualPriceAmount}

	if err := validateCatalogPrice(testCatalogPrice(configured, perpetualPriceAmount, false), expected, false); err != nil {
		t.Fatalf("validate perpetual Price: %v", err)
	}
}

func TestCheckoutClientSanitizesCatalogStripeError(t *testing.T) {
	prices := &fakeStripePrices{err: &stripe.Error{
		HTTPStatusCode: http.StatusForbidden,
		Code:           stripe.ErrorCodeAPIKeyExpired,
		RequestID:      "req_example",
		Msg:            "sensitive upstream message",
	}}
	client := &CheckoutClient{prices: prices}

	err := client.CheckCatalog(context.Background(), testCatalogSpec())
	var requestError *StripeRequestError
	if !errors.As(err, &requestError) {
		t.Fatalf("error = %v, want StripeRequestError", err)
	}
	if requestError.HTTPStatusCode != http.StatusForbidden || requestError.Code != string(stripe.ErrorCodeAPIKeyExpired) || requestError.RequestID != "req_example" {
		t.Errorf("Stripe request error = %+v", requestError)
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Errorf("error disclosed Stripe response: %v", err)
	}
}

func testCatalogSpec() CatalogSpec {
	return CatalogSpec{
		Perpetual: CatalogPrice{PriceID: "price_perpetual", ProductID: "prod_perpetual"},
		Monthly:   CatalogPrice{PriceID: "price_monthly", ProductID: "prod_monthly"},
	}
}

func testCatalogPrice(configured CatalogPrice, amount int64, recurring bool) *stripe.Price {
	price := &stripe.Price{
		Active:        true,
		BillingScheme: stripe.PriceBillingSchemePerUnit,
		Currency:      stripe.CurrencyEUR,
		ID:            configured.PriceID,
		Object:        "price",
		Product:       &stripe.Product{ID: configured.ProductID},
		TaxBehavior:   stripe.PriceTaxBehaviorExclusive,
		Type:          stripe.PriceTypeOneTime,
		UnitAmount:    amount,
	}
	if recurring {
		price.Type = stripe.PriceTypeRecurring
		price.Recurring = &stripe.PriceRecurring{
			Interval:      stripe.PriceRecurringIntervalMonth,
			IntervalCount: 1,
			UsageType:     stripe.PriceRecurringUsageTypeLicensed,
		}
	}
	return price
}

type fakeStripePrices struct {
	responses   map[string]*stripe.Price
	err         error
	ids         []string
	hasDeadline bool
}

func (f *fakeStripePrices) Retrieve(ctx context.Context, id string, _ *stripe.PriceRetrieveParams) (*stripe.Price, error) {
	f.ids = append(f.ids, id)
	_, f.hasDeadline = ctx.Deadline()
	return f.responses[id], f.err
}
