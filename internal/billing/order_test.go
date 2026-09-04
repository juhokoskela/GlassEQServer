package billing

import (
	"database/sql"
	"net/netip"
	"testing"
)

func TestPrepareCheckoutOrderRejectsInvalidInput(t *testing.T) {
	tests := []CreateCheckoutOrderInput{
		{RequestID: "6ba7b810-9dad-11d1-80b4-00c04fd430c8", Plan: PlanMonthly, ClientIP: netip.MustParseAddr("192.0.2.1")},
		{RequestID: "2B1BC1BA-407A-49F2-AD2E-A260A56BCF23", Plan: PlanMonthly, ClientIP: netip.MustParseAddr("192.0.2.1")},
		{RequestID: "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23", Plan: Plan("annual"), ClientIP: netip.MustParseAddr("192.0.2.1")},
		{RequestID: "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23", Plan: PlanMonthly},
	}

	for _, input := range tests {
		if _, err := prepareCheckoutOrder(input); err == nil {
			t.Errorf("prepareCheckoutOrder(%+v) succeeded", input)
		}
	}
}

func TestNewOrderServiceRejectsInvalidConfiguration(t *testing.T) {
	validPrices := PriceCatalog{PerpetualV1: "price_perpetual", Monthly: "price_monthly"}
	validKey := make([]byte, 32)
	database := new(sql.DB)
	checkout := newFakeOrderCheckout()
	tests := []struct {
		prices PriceCatalog
		key    []byte
	}{
		{prices: PriceCatalog{PerpetualV1: "invalid", Monthly: "price_monthly"}, key: validKey},
		{prices: PriceCatalog{PerpetualV1: "price_perpetual", Monthly: "invalid"}, key: validKey},
		{prices: validPrices, key: make([]byte, 31)},
	}

	for _, test := range tests {
		if _, err := NewOrderService(database, checkout, test.prices, test.key); err == nil {
			t.Errorf("NewOrderService(%+v) succeeded", test.prices)
		}
	}
}
