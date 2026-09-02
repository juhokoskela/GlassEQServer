package activation

import (
	"bytes"
	"testing"
)

func TestGenerateLicenseKey(t *testing.T) {
	licenseKey, normalizedKey, err := generateLicenseKey(bytes.NewReader(make([]byte, licenseKeyByteCount)))
	if err != nil {
		t.Fatalf("generate license key: %v", err)
	}
	if licenseKey != "GEQ1-00000-00000-00000-00000-00000-0" {
		t.Errorf("license key = %q", licenseKey)
	}
	if normalizedKey != "GEQ100000000000000000000000000" {
		t.Errorf("normalized key = %q", normalizedKey)
	}
	if normalized, valid := normalizeLicenseKey(licenseKey); !valid || normalized != normalizedKey {
		t.Errorf("normalizeLicenseKey(%q) = %q, %t", licenseKey, normalized, valid)
	}
}

func TestGenerateLicenseKeyChecksRandomFailure(t *testing.T) {
	if _, _, err := generateLicenseKey(bytes.NewReader(make([]byte, licenseKeyByteCount-1))); err == nil {
		t.Fatal("generate license key with short randomness succeeded")
	}
}
