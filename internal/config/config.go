package config

import (
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

	return Config{
		HTTPAddress:             httpAddress,
		DatabaseURL:             databaseURL,
		EntitlementKMSKeyID:     kmsKeyID,
		EntitlementSigningKeyID: signingKeyID,
	}, nil
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
