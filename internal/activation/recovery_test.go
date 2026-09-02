package activation

import (
	"encoding/base64"
	"testing"
)

func TestRecoveryTokenHash(t *testing.T) {
	validToken := recoveryTokenPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "valid", value: validToken, valid: true},
		{name: "management token", value: managementTokenPrefix + validToken[len(recoveryTokenPrefix):]},
		{name: "short secret", value: recoveryTokenPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 31))},
		{name: "padded", value: validToken + "="},
		{name: "non-zero trailing bits", value: validToken[:len(validToken)-1] + "B"},
		{name: "invalid base64", value: recoveryTokenPrefix + "!"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, valid := recoveryTokenHash(test.value)
			if valid != test.valid {
				t.Errorf("recoveryTokenHash(%q) valid = %t, want %t", test.value, valid, test.valid)
			}
		})
	}
}
