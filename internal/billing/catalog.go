package billing

import (
	"context"
	"errors"
	"fmt"

	"github.com/stripe/stripe-go/v86"
)

const (
	perpetualPriceAmount = 2_999
	monthlyPriceAmount   = 299
	glassEQTaxCode       = "txcd_10202001"
)

type CatalogSpec struct {
	Perpetual CatalogPrice
	Monthly   CatalogPrice
}

type CatalogPrice struct {
	PriceID   string
	ProductID string
}

type catalogPriceExpectation struct {
	plan       Plan
	configured CatalogPrice
	amount     int64
}

func (c *CheckoutClient) CheckCatalog(ctx context.Context, catalog CatalogSpec) error {
	expectations := []catalogPriceExpectation{
		{plan: PlanPerpetualV1, configured: catalog.Perpetual, amount: perpetualPriceAmount},
		{plan: PlanMonthly, configured: catalog.Monthly, amount: monthlyPriceAmount},
	}
	for _, expected := range expectations {
		if !validPriceID(expected.configured.PriceID) {
			return fmt.Errorf("%s Stripe Price ID must start with price_", expected.plan)
		}
		if !validProductID(expected.configured.ProductID) {
			return fmt.Errorf("%s Stripe Product ID must start with prod_", expected.plan)
		}
	}

	requestCtx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	params := &stripe.PriceRetrieveParams{}
	params.AddExpand("product")
	for _, expected := range expectations {
		price, err := c.prices.Retrieve(requestCtx, expected.configured.PriceID, params)
		if err != nil {
			return fmt.Errorf("retrieve %s Stripe Price: %w", expected.plan, sanitizeStripeError(requestCtx, err))
		}
		if err := validateCatalogPrice(price, expected, c.liveMode); err != nil {
			return err
		}
	}
	return nil
}

func validateCatalogPrice(price *stripe.Price, expected catalogPriceExpectation, liveMode bool) error {
	name := fmt.Sprintf("%s Stripe Price", expected.plan)
	if price == nil {
		return errors.New(name + " response is empty")
	}
	if price.ID != expected.configured.PriceID {
		return fmt.Errorf("%s ID is %q, want %q", name, price.ID, expected.configured.PriceID)
	}
	if price.Object != "price" || price.Deleted {
		return errors.New(name + " response is not a Price")
	}
	if !price.Active {
		return errors.New(name + " is inactive")
	}
	if price.Livemode != liveMode {
		return errors.New(name + " belongs to the wrong Stripe environment")
	}
	if price.Currency != stripe.CurrencyEUR {
		return fmt.Errorf("%s currency is %q, want %q", name, price.Currency, stripe.CurrencyEUR)
	}
	if price.BillingScheme != stripe.PriceBillingSchemePerUnit || price.CustomUnitAmount != nil || price.TransformQuantity != nil {
		return errors.New(name + " must use a fixed per-unit amount")
	}
	if price.UnitAmount != expected.amount {
		return fmt.Errorf("%s amount is %d, want %d", name, price.UnitAmount, expected.amount)
	}
	if price.TaxBehavior != stripe.PriceTaxBehaviorExclusive {
		return errors.New(name + " must add tax on top of its amount")
	}
	if price.Product == nil || price.Product.ID != expected.configured.ProductID {
		return fmt.Errorf("%s Product does not match %q", name, expected.configured.ProductID)
	}
	if price.Product.Object != "product" || price.Product.Deleted {
		return errors.New(name + " Product response is not a Product")
	}
	if !price.Product.Active {
		return errors.New(name + " Product is inactive")
	}
	if price.Product.Livemode != liveMode {
		return errors.New(name + " Product belongs to the wrong Stripe environment")
	}
	if price.Product.TaxCode == nil || price.Product.TaxCode.ID != glassEQTaxCode {
		return fmt.Errorf("%s Product tax code must be %s", name, glassEQTaxCode)
	}

	switch expected.plan {
	case PlanPerpetualV1:
		if price.Type != stripe.PriceTypeOneTime || price.Recurring != nil {
			return errors.New(name + " must be one-time")
		}
		return nil
	case PlanMonthly:
		if price.Type != stripe.PriceTypeRecurring || price.Recurring == nil {
			return errors.New(name + " must be recurring")
		}
		if price.Recurring.Interval != stripe.PriceRecurringIntervalMonth || price.Recurring.IntervalCount != 1 ||
			price.Recurring.UsageType != stripe.PriceRecurringUsageTypeLicensed || price.Recurring.TrialPeriodDays != 0 {
			return errors.New(name + " must bill one licensed unit monthly without a trial")
		}
		return nil
	default:
		return fmt.Errorf("unsupported catalog plan %q", expected.plan)
	}
}
