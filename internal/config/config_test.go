package config

import (
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	values := map[string]string{
		"GLASSEQ_DATABASE_URL":               "postgres://glasseq:secret@db.example.com/glasseq",
		"GLASSEQ_ENTITLEMENT_KMS_KEY_ID":     "arn:aws:kms:eu-north-1:123456789012:key/example",
		"GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID": "entitlement-2026-01",
	}

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

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}
