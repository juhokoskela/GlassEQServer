package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/juhokoskela/GlassEQServer/internal/entitlement"
)

const defaultHTTPAddress = ":8080"

type Config struct {
	HTTPAddress             string
	DatabaseURL             string
	EntitlementKMSKeyID     string
	EntitlementSigningKeyID string
	IdempotencyKey          []byte
	RateLimitHMACKey        []byte
	EmailLookupHMACKey      []byte
	DatabaseEncryptionKey   []byte
	RecoveryQueueURL        string
	Stripe                  StripeConfig
}

type StripeConfig struct {
	SecretKey          string
	LiveMode           bool
	PerpetualProductID string
	PerpetualPriceID   string
	MonthlyProductID   string
	MonthlyPriceID     string
}

func Load() (Config, error) {
	return load(os.LookupEnv)
}

func load(lookup func(string) (string, bool)) (Config, error) {
	httpAddress := valueOrDefault(lookup, "GLASSEQ_HTTP_ADDRESS", defaultHTTPAddress)
	databaseURL, err := required(lookup, "GLASSEQ_DATABASE_URL")
	if err != nil {
		return Config{}, err
	}
	if err := validateDatabaseURL(databaseURL); err != nil {
		return Config{}, err
	}

	kmsKeyID, err := required(lookup, "GLASSEQ_ENTITLEMENT_KMS_KEY_ID")
	if err != nil {
		return Config{}, err
	}
	signingKeyID, err := required(lookup, "GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID")
	if err != nil {
		return Config{}, err
	}
	if err := entitlement.ValidateKeyID(signingKeyID); err != nil {
		return Config{}, fmt.Errorf("GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID %w", err)
	}
	idempotencyKey, err := secretKey(lookup, "GLASSEQ_IDEMPOTENCY_KEY")
	if err != nil {
		return Config{}, err
	}
	rateLimitHMACKey, err := secretKey(lookup, "GLASSEQ_RATE_LIMIT_HMAC_KEY")
	if err != nil {
		return Config{}, err
	}
	emailLookupHMACKey, err := secretKey(lookup, "GLASSEQ_EMAIL_LOOKUP_HMAC_KEY")
	if err != nil {
		return Config{}, err
	}
	databaseEncryptionKey, err := secretKey(lookup, "GLASSEQ_DATABASE_ENCRYPTION_KEY")
	if err != nil {
		return Config{}, err
	}
	recoveryQueueURL, err := required(lookup, "GLASSEQ_RECOVERY_QUEUE_URL")
	if err != nil {
		return Config{}, err
	}
	stripeConfig, err := loadStripe(lookup)
	if err != nil {
		return Config{}, err
	}

	return Config{
		HTTPAddress:             httpAddress,
		DatabaseURL:             databaseURL,
		EntitlementKMSKeyID:     kmsKeyID,
		EntitlementSigningKeyID: signingKeyID,
		IdempotencyKey:          idempotencyKey,
		RateLimitHMACKey:        rateLimitHMACKey,
		EmailLookupHMACKey:      emailLookupHMACKey,
		DatabaseEncryptionKey:   databaseEncryptionKey,
		RecoveryQueueURL:        recoveryQueueURL,
		Stripe:                  stripeConfig,
	}, nil
}

func loadStripe(lookup func(string) (string, bool)) (StripeConfig, error) {
	secretKey, err := required(lookup, "GLASSEQ_STRIPE_SECRET_KEY")
	if err != nil {
		return StripeConfig{}, err
	}
	mode, err := required(lookup, "GLASSEQ_STRIPE_MODE")
	if err != nil {
		return StripeConfig{}, err
	}
	if mode != "test" && mode != "live" {
		return StripeConfig{}, errors.New("GLASSEQ_STRIPE_MODE must be test or live")
	}
	if !strings.HasPrefix(secretKey, "sk_"+mode+"_") && !strings.HasPrefix(secretKey, "rk_"+mode+"_") {
		return StripeConfig{}, errors.New("GLASSEQ_STRIPE_SECRET_KEY does not match GLASSEQ_STRIPE_MODE")
	}

	perpetualProductID, err := stripeID(lookup, "GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID", "prod_")
	if err != nil {
		return StripeConfig{}, err
	}
	perpetualPriceID, err := stripeID(lookup, "GLASSEQ_STRIPE_PERPETUAL_PRICE_ID", "price_")
	if err != nil {
		return StripeConfig{}, err
	}
	monthlyProductID, err := stripeID(lookup, "GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID", "prod_")
	if err != nil {
		return StripeConfig{}, err
	}
	monthlyPriceID, err := stripeID(lookup, "GLASSEQ_STRIPE_MONTHLY_PRICE_ID", "price_")
	if err != nil {
		return StripeConfig{}, err
	}

	return StripeConfig{
		SecretKey:          secretKey,
		LiveMode:           mode == "live",
		PerpetualProductID: perpetualProductID,
		PerpetualPriceID:   perpetualPriceID,
		MonthlyProductID:   monthlyProductID,
		MonthlyPriceID:     monthlyPriceID,
	}, nil
}

func stripeID(lookup func(string) (string, bool), name, prefix string) (string, error) {
	value, err := required(lookup, name)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return "", fmt.Errorf("%s must start with %s", name, prefix)
	}
	return value, nil
}

func secretKey(lookup func(string) (string, bool), name string) ([]byte, error) {
	encoded, err := required(lookup, name)
	if err != nil {
		return nil, err
	}
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != encoded {
		return nil, fmt.Errorf("%s must be the unpadded Base64URL encoding of 32 bytes", name)
	}
	return key, nil
}

func required(lookup func(string) (string, bool), name string) (string, error) {
	value, ok := lookup(name)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func valueOrDefault(lookup func(string) (string, bool), name, fallback string) string {
	value, ok := lookup(name)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return fallback
	}
	return value
}

func validateDatabaseURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		return errors.New("GLASSEQ_DATABASE_URL must be an absolute postgres URL")
	}
	return nil
}
