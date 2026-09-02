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
	}, nil
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
