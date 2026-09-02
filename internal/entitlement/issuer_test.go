package entitlement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const testInstallationID = "4E70638A-3AB2-4D21-A4AB-0B2525F80D42"

func TestIssuePerpetualEntitlement(t *testing.T) {
	issuer, publicKey := newTestIssuer(t)
	token, err := issuer.IssuePerpetual(context.Background(), Claims{
		LicenseID:      "lic_01",
		EntitlementID:  "ent_01",
		IssuedAt:       1_000_000,
		ActivationID:   "act_01",
		InstallationID: strings.ToLower(testInstallationID),
		Revision:       7,
	})
	if err != nil {
		t.Fatalf("issue entitlement: %v", err)
	}

	header, payload := verifyAndDecode(t, token, publicKey)
	wantHeader := map[string]any{
		"alg": "EdDSA",
		"kid": "entitlement-2026-01",
		"typ": "glasseq-entitlement+jwt",
	}
	assertJSONObject(t, header, wantHeader)
	assertJSONObject(t, payload, map[string]any{
		"iss":                           IssuerURL,
		"aud":                           Audience,
		"sub":                           "lic_01",
		"jti":                           "ent_01",
		"iat":                           float64(1_000_000),
		"schema":                        float64(1),
		"plan":                          "perpetual_v1",
		"activation_id":                 "act_01",
		"installation_id":               testInstallationID,
		"revision":                      float64(7),
		"release_scope":                 "v1",
		"security_updates_after_expiry": false,
	})
}

func TestIssueMonthlyEntitlement(t *testing.T) {
	issuer, publicKey := newTestIssuer(t)
	token, err := issuer.IssueMonthly(context.Background(), MonthlyClaims{
		Claims: Claims{
			LicenseID:      "lic_01",
			EntitlementID:  "ent_01",
			IssuedAt:       1_000_000,
			ActivationID:   "act_01",
			InstallationID: testInstallationID,
			Revision:       7,
		},
		BillingState:               BillingActive,
		BillingPeriodEnd:           1_864_000,
		RecoveryUntil:              3_073_600,
		RefreshAfter:               1_604_800,
		ExpiresAt:                  3_678_400,
		SecurityUpdatesAfterExpiry: true,
	})
	if err != nil {
		t.Fatalf("issue entitlement: %v", err)
	}

	_, payload := verifyAndDecode(t, token, publicKey)
	if payload["billing_state"] != "active" {
		t.Errorf("billing state = %v", payload["billing_state"])
	}
	if payload["release_scope"] != "current" {
		t.Errorf("release scope = %v", payload["release_scope"])
	}
	if payload["security_updates_after_expiry"] != true {
		t.Errorf("security update eligibility = %v", payload["security_updates_after_expiry"])
	}
	if payload["exp"] != float64(3_678_400) {
		t.Errorf("expiry = %v", payload["exp"])
	}
	if len(payload) != 17 {
		t.Errorf("monthly claim count = %d, want 17", len(payload))
	}
}

func TestIssuePerpetualRejectsInvalidClaimsBeforeSigning(t *testing.T) {
	signer := &countingSigner{}
	issuer, err := NewIssuer("entitlement-2026-01", signer)
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	_, err = issuer.IssuePerpetual(context.Background(), Claims{
		LicenseID: "lic_01", EntitlementID: "ent_01", IssuedAt: 1,
		ActivationID: "act_01", InstallationID: "not-a-uuid", Revision: 1,
	})
	if err == nil {
		t.Fatal("issue entitlement succeeded")
	}
	if signer.calls != 0 {
		t.Errorf("signer calls = %d, want 0", signer.calls)
	}
}

func TestIssueMonthlyRejectsInvalidClaimsBeforeSigning(t *testing.T) {
	signer := &countingSigner{}
	issuer, err := NewIssuer("entitlement-2026-01", signer)
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	_, err = issuer.IssueMonthly(context.Background(), MonthlyClaims{
		Claims: Claims{
			LicenseID: "lic_01", EntitlementID: "ent_01", IssuedAt: 1,
			ActivationID: "act_01", InstallationID: testInstallationID, Revision: 1,
		},
		BillingState: BillingActive, BillingPeriodEnd: 2, RecoveryUntil: 3,
		RefreshAfter: 2, ExpiresAt: 4,
	})
	if err == nil {
		t.Fatal("issue entitlement succeeded")
	}
	if signer.calls != 0 {
		t.Errorf("signer calls = %d, want 0", signer.calls)
	}
}

func TestIssueRejectsOversizedSigningInputBeforeSigning(t *testing.T) {
	signer := &countingSigner{}
	issuer, err := NewIssuer("entitlement-2026-01", signer)
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	_, err = issuer.IssuePerpetual(context.Background(), Claims{
		LicenseID:      strings.Repeat("<", 256),
		EntitlementID:  strings.Repeat("<", 256),
		IssuedAt:       1,
		ActivationID:   strings.Repeat("<", 256),
		InstallationID: testInstallationID,
		Revision:       1,
	})
	if err == nil || !strings.Contains(err.Error(), "4 KiB") {
		t.Fatalf("issue error = %v, want signing-input limit error", err)
	}
	if signer.calls != 0 {
		t.Errorf("signer calls = %d, want 0", signer.calls)
	}
}

func TestIssuePreservesSignerError(t *testing.T) {
	wantErr := errors.New("signing unavailable")
	issuer, err := NewIssuer("entitlement-2026-01", errorSigner{err: wantErr})
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	_, err = issuer.IssuePerpetual(context.Background(), Claims{
		LicenseID:      "lic_01",
		EntitlementID:  "ent_01",
		IssuedAt:       1,
		ActivationID:   "act_01",
		InstallationID: testInstallationID,
		Revision:       1,
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("issue error = %v, want wrapped signer error", err)
	}
}

type ed25519Signer struct {
	privateKey ed25519.PrivateKey
}

func (s ed25519Signer) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, message), nil
}

type countingSigner struct {
	calls int
}

func (s *countingSigner) Sign(_ context.Context, _ []byte) ([]byte, error) {
	s.calls++
	return make([]byte, ed25519.SignatureSize), nil
}

type errorSigner struct {
	err error
}

func (s errorSigner) Sign(_ context.Context, _ []byte) ([]byte, error) {
	return nil, s.err
}

func newTestIssuer(t *testing.T) (*Issuer, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	issuer, err := NewIssuer("entitlement-2026-01", ed25519Signer{privateKey: privateKey})
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	return issuer, publicKey
}

func verifyAndDecode(t *testing.T, token string, publicKey ed25519.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS has %d parts", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("signature verification failed")
	}
	return decodeJSONObject(t, parts[0]), decodeJSONObject(t, parts[1])
}

func decodeJSONObject(t *testing.T, encoded string) map[string]any {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode JWS part: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return value
}

func assertJSONObject(t *testing.T, got, want map[string]any) {
	t.Helper()
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal actual JSON: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal expected JSON: %v", err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("JSON = %s, want %s", gotJSON, wantJSON)
	}
}
