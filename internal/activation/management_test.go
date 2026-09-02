package activation

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
)

func TestManagementTokenHash(t *testing.T) {
	validToken := managementTokenPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "valid", value: validToken, valid: true},
		{name: "activation token", value: activationTokenPrefix + validToken[len(managementTokenPrefix):]},
		{name: "short secret", value: managementTokenPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 31))},
		{name: "padded", value: validToken + "="},
		{name: "invalid base64", value: managementTokenPrefix + "!"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, valid := managementTokenHash(test.value)
			if valid != test.valid {
				t.Errorf("managementTokenHash(%q) valid = %t, want %t", test.value, valid, test.valid)
			}
		})
	}
}

func TestActivationIDValid(t *testing.T) {
	validID := "act_" + base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	for value, want := range map[string]bool{
		validID:                        true,
		"ent_" + validID[len("act_"):]: false,
		"act_" + base64.RawURLEncoding.EncodeToString(make([]byte, 15)): false,
		validID + "=": false,
	} {
		if got := activationIDValid(value); got != want {
			t.Errorf("activationIDValid(%q) = %t, want %t", value, got, want)
		}
	}
}

func TestManagedDeactivationRejectsInvalidActivationID(t *testing.T) {
	token := managementTokenPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	response, err := (&Service{}).DeactivateManaged(context.Background(), ManagedDeactivationInput{
		ManagementToken: token,
		ActivationID:    "act_invalid",
	})
	if err != nil {
		t.Fatalf("reject invalid activation ID: %v", err)
	}
	if response.Status != http.StatusBadRequest || response.ErrorCode != "invalid_request" {
		t.Errorf("response = %+v", response)
	}
}
