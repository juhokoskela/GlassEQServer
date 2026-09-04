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

func TestPrepareCheckoutOrderNormalizesClientIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "192.0.2.1", want: "192.0.2.1"},
		{input: "::ffff:192.0.2.1", want: "192.0.2.1"},
		{input: "2001:db8:1234:5678:1111:2222:3333:4444", want: "2001:db8:1234:5678::"},
	}

	for _, test := range tests {
		input := CreateCheckoutOrderInput{
			RequestID: "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23",
			Plan:      PlanMonthly,
			ClientIP:  netip.MustParseAddr(test.input),
		}
		prepared, err := prepareCheckoutOrder(input)
		if err != nil {
			t.Fatalf("prepareCheckoutOrder(%q): %v", test.input, err)
		}
		if got := prepared.clientIP.String(); got != test.want {
			t.Errorf("prepareCheckoutOrder(%q) IP = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestPrepareCheckoutOrderGroupsIPv6By64BitPrefix(t *testing.T) {
	prepare := func(address string) netip.Addr {
		t.Helper()
		prepared, err := prepareCheckoutOrder(CreateCheckoutOrderInput{
			RequestID: "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23",
			Plan:      PlanMonthly,
			ClientIP:  netip.MustParseAddr(address),
		})
		if err != nil {
			t.Fatalf("prepare Checkout order: %v", err)
		}
		return prepared.clientIP
	}

	first := prepare("2001:db8:1234:5678::1")
	if second := prepare("2001:db8:1234:5678:ffff::2"); second != first {
		t.Errorf("same /64 normalized to %s and %s", first, second)
	}
	if other := prepare("2001:db8:1234:5679::1"); other == first {
		t.Errorf("different /64 prefixes both normalized to %s", first)
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
