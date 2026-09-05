package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	values := validValues()
	values["GLASSEQ_ENTITLEMENT_KMS_KEY_ID"] = "arn:aws:kms:eu-north-1:123456789012:key/example"

	got, err := load(mapLookup(values))
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	if got.HTTPAddress != ":8080" {
		t.Errorf("HTTP address = %q, want %q", got.HTTPAddress, ":8080")
	}
	if got.DatabaseURL != values["GLASSEQ_DATABASE_URL"] {
		t.Errorf("database URL = %q", got.DatabaseURL)
	}
	if got.EntitlementKMSKeyID != values["GLASSEQ_ENTITLEMENT_KMS_KEY_ID"] {
		t.Errorf("KMS key ID = %q", got.EntitlementKMSKeyID)
	}
	if got.EntitlementSigningKeyID != values["GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID"] {
		t.Errorf("signing key ID = %q", got.EntitlementSigningKeyID)
	}
	if len(got.IdempotencyKey) != 32 {
		t.Errorf("idempotency key length = %d", len(got.IdempotencyKey))
	}
	if len(got.RateLimitHMACKey) != 32 {
		t.Errorf("rate-limit HMAC key length = %d", len(got.RateLimitHMACKey))
	}
	if len(got.EmailLookupHMACKey) != 32 {
		t.Errorf("email-lookup HMAC key length = %d", len(got.EmailLookupHMACKey))
	}
	if len(got.DatabaseEncryptionKey) != 32 {
		t.Errorf("database encryption key length = %d", len(got.DatabaseEncryptionKey))
	}
	if got.RecoveryQueueURL != values["GLASSEQ_RECOVERY_QUEUE_URL"] {
		t.Errorf("recovery queue URL = %q", got.RecoveryQueueURL)
	}
	if got.Stripe != nil {
		t.Error("Stripe configuration was enabled without Stripe variables")
	}
}

func TestLoadStripeConfiguration(t *testing.T) {
	values := validValues()
	values["GLASSEQ_STRIPE_SECRET_KEY"] = "sk_test_secret"
	values["GLASSEQ_STRIPE_PERPETUAL_PRICE_ID"] = "price_1UBVfNEC4w9ZWN2YlB59OzfZ"
	values["GLASSEQ_STRIPE_MONTHLY_PRICE_ID"] = "price_1UBVdzEC4w9ZWN2Y8pOBCyAE"

	got, err := load(mapLookup(values))
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	if got.Stripe == nil {
		t.Fatal("Stripe configuration is nil")
	}
	if got.Stripe.SecretKey != values["GLASSEQ_STRIPE_SECRET_KEY"] ||
		got.Stripe.PerpetualPriceID != values["GLASSEQ_STRIPE_PERPETUAL_PRICE_ID"] ||
		got.Stripe.MonthlyPriceID != values["GLASSEQ_STRIPE_MONTHLY_PRICE_ID"] {
		t.Error("Stripe configuration was not loaded")
	}
}

func TestLoadStripeCatalog(t *testing.T) {
	values := map[string]string{
		"GLASSEQ_STRIPE_SECRET_KEY":           "sk_test_secret",
		"GLASSEQ_STRIPE_PERPETUAL_PRICE_ID":   "price_perpetual",
		"GLASSEQ_STRIPE_MONTHLY_PRICE_ID":     "price_monthly",
		"GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID": "prod_perpetual",
		"GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID":   "prod_monthly",
	}

	got, err := loadStripeCatalog(mapLookup(values))
	if err != nil {
		t.Fatalf("load Stripe catalog: %v", err)
	}
	if got.SecretKey != values["GLASSEQ_STRIPE_SECRET_KEY"] ||
		got.PerpetualPriceID != values["GLASSEQ_STRIPE_PERPETUAL_PRICE_ID"] ||
		got.MonthlyPriceID != values["GLASSEQ_STRIPE_MONTHLY_PRICE_ID"] ||
		got.PerpetualProductID != values["GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID"] ||
		got.MonthlyProductID != values["GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID"] {
		t.Errorf("Stripe catalog configuration = %+v", got)
	}
}

func TestLoadStripeCatalogRejectsIncompleteConfigurationWithoutEchoingSecret(t *testing.T) {
	values := map[string]string{
		"GLASSEQ_STRIPE_SECRET_KEY":         "sk_test_do-not-echo",
		"GLASSEQ_STRIPE_PERPETUAL_PRICE_ID": "price_perpetual",
		"GLASSEQ_STRIPE_MONTHLY_PRICE_ID":   "price_monthly",
		"GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID": "prod_monthly",
	}

	_, err := loadStripeCatalog(mapLookup(values))
	if err == nil || !strings.Contains(err.Error(), "GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID") {
		t.Fatalf("error = %q, want missing Stripe Product ID", err)
	}
	if strings.Contains(err.Error(), "do-not-echo") {
		t.Fatalf("error disclosed Stripe credentials: %q", err)
	}
}

func TestLoadDoesNotEnableStripeFromCatalogOnlyConfiguration(t *testing.T) {
	values := validValues()
	values["GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID"] = "prod_perpetual"
	values["GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID"] = "prod_monthly"

	got, err := load(mapLookup(values))
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	if got.Stripe != nil {
		t.Error("Stripe configuration was enabled without runtime Price settings")
	}
}

func TestLoadRejectsIncompleteStripeConfigurationWithoutEchoingSecret(t *testing.T) {
	values := validValues()
	values["GLASSEQ_STRIPE_SECRET_KEY"] = "sk_test_do-not-echo"

	_, err := load(mapLookup(values))
	if err == nil || !strings.Contains(err.Error(), "GLASSEQ_STRIPE_PERPETUAL_PRICE_ID") {
		t.Fatalf("error = %q, want missing Stripe Price ID", err)
	}
	if strings.Contains(err.Error(), "do-not-echo") {
		t.Fatalf("error disclosed Stripe credentials: %q", err)
	}
}

func TestLoadRejectsInvalidConfigurationWithoutEchoingDatabaseURL(t *testing.T) {
	const databaseURL = "postgres://glasseq:super-secret@db.example.com/glasseq"
	tests := []struct {
		name        string
		values      map[string]string
		wantMessage string
	}{
		{
			name: "missing database URL",
			values: map[string]string{
				"GLASSEQ_ENTITLEMENT_KMS_KEY_ID":     "kms-key",
				"GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID": "entitlement-2026-01",
			},
			wantMessage: "GLASSEQ_DATABASE_URL is required",
		},
		{
			name: "non-PostgreSQL URL",
			values: map[string]string{
				"GLASSEQ_DATABASE_URL":               "mysql://glasseq:super-secret@db.example.com/glasseq",
				"GLASSEQ_ENTITLEMENT_KMS_KEY_ID":     "kms-key",
				"GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID": "entitlement-2026-01",
			},
			wantMessage: "GLASSEQ_DATABASE_URL must be an absolute postgres URL",
		},
		{
			name: "invalid public key ID",
			values: map[string]string{
				"GLASSEQ_DATABASE_URL":               databaseURL,
				"GLASSEQ_ENTITLEMENT_KMS_KEY_ID":     "kms-key",
				"GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID": "not valid",
			},
			wantMessage: "GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID",
		},
		{
			name: "invalid idempotency key",
			values: map[string]string{
				"GLASSEQ_DATABASE_URL":               databaseURL,
				"GLASSEQ_ENTITLEMENT_KMS_KEY_ID":     "kms-key",
				"GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID": "entitlement-2026-01",
				"GLASSEQ_IDEMPOTENCY_KEY":            "secret-value-that-must-not-be-echoed",
			},
			wantMessage: "GLASSEQ_IDEMPOTENCY_KEY",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := load(mapLookup(test.values))
			if err == nil {
				t.Fatal("load configuration succeeded")
			}
			if !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("error = %q, want text %q", err, test.wantMessage)
			}
			if strings.Contains(err.Error(), "super-secret") {
				t.Fatalf("error disclosed database credentials: %q", err)
			}
		})
	}
}

func testSecretKey(value byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(value), 32)))
}

func validValues() map[string]string {
	return map[string]string{
		"GLASSEQ_DATABASE_URL":               "postgres://glasseq:secret@db.example.com/glasseq",
		"GLASSEQ_ENTITLEMENT_KMS_KEY_ID":     "kms-key",
		"GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID": "entitlement-2026-01",
		"GLASSEQ_IDEMPOTENCY_KEY":            testSecretKey(1),
		"GLASSEQ_RATE_LIMIT_HMAC_KEY":        testSecretKey(2),
		"GLASSEQ_EMAIL_LOOKUP_HMAC_KEY":      testSecretKey(3),
		"GLASSEQ_DATABASE_ENCRYPTION_KEY":    testSecretKey(4),
		"GLASSEQ_RECOVERY_QUEUE_URL":         "https://sqs.eu-north-1.amazonaws.com/123456789012/recovery.fifo",
	}
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}
