package activation

import (
	"database/sql"
	"net/netip"
	"testing"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/entitlement"
)

func TestNormalizeLicenseKey(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantValid bool
	}{
		{
			name:      "display form",
			input:     "geq1-01234-56789-abcde-fghjk-mnpqr-s",
			want:      "GEQ10123456789ABCDEFGHJKMNPQRS",
			wantValid: true,
		},
		{name: "ambiguous character", input: "GEQ10123456789ABCDEFGHJKMNPQRI", want: "GEQ10123456789ABCDEFGHJKMNPQRI"},
		{name: "wrong prefix", input: "NOPE0123456789ABCDEFGHJKMNPQRS", want: "NOPE0123456789ABCDEFGHJKMNPQRS"},
		{name: "empty", input: "", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, valid := normalizeLicenseKey(test.input)
			if got != test.want || valid != test.wantValid {
				t.Errorf("normalizeLicenseKey(%q) = %q, %t; want %q, %t", test.input, got, valid, test.want, test.wantValid)
			}
		})
	}
}

func TestPrepareCanonicalizesIdentifiersAndIP(t *testing.T) {
	prepared, invalidCode := prepare(Input{
		LicenseKey:     "geq1-01234-56789-abcde-fghjk-mnpqr-s",
		InstallationID: "4e70638a-a75b-4bfb-b4b0-15e959a91465",
		IdempotencyKey: "2B1BC1BA-407A-49F2-AD2E-A260A56BCF23",
		ClientIP:       netip.MustParseAddr("::ffff:192.0.2.1"),
	})
	if invalidCode != "" {
		t.Fatalf("prepare invalid code = %q", invalidCode)
	}
	if prepared.installationID != "4E70638A-A75B-4BFB-B4B0-15E959A91465" {
		t.Errorf("installation ID = %q", prepared.installationID)
	}
	if prepared.idempotencyKey != "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23" {
		t.Errorf("idempotency key = %q", prepared.idempotencyKey)
	}
	if prepared.clientIP != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("client IP = %q", prepared.clientIP)
	}
}

func TestMonthlyEntitlementTerms(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name         string
		license      licenseRecord
		wantEligible bool
		wantState    entitlement.BillingState
		wantRecovery time.Time
	}{
		{
			name:         "active",
			license:      monthlyLicense("active", entitlement.BillingRecovering, now.Add(14*24*time.Hour), sql.NullTime{}),
			wantEligible: true,
			wantState:    entitlement.BillingRecovering,
			wantRecovery: now.Add(14 * 24 * time.Hour),
		},
		{
			name:         "refunded",
			license:      monthlyLicense("refunded", entitlement.BillingActive, now.Add(14*24*time.Hour), sql.NullTime{Time: now.Add(-24 * time.Hour), Valid: true}),
			wantEligible: true,
			wantState:    entitlement.BillingRefunded,
			wantRecovery: now.Add(-24 * time.Hour),
		},
		{
			name:    "expired refund",
			license: monthlyLicense("refunded", entitlement.BillingActive, now.Add(14*24*time.Hour), sql.NullTime{Time: now.Add(-7 * 24 * time.Hour), Valid: true}),
		},
		{
			name:    "revoked",
			license: monthlyLicense("revoked", entitlement.BillingActive, now.Add(14*24*time.Hour), sql.NullTime{}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			terms, eligible, err := monthlyEntitlementTerms(test.license, now)
			if err != nil {
				t.Fatalf("monthly entitlement terms: %v", err)
			}
			if eligible != test.wantEligible {
				t.Fatalf("eligible = %t, want %t", eligible, test.wantEligible)
			}
			if !eligible {
				return
			}
			if terms.billingState != test.wantState {
				t.Errorf("billing state = %q, want %q", terms.billingState, test.wantState)
			}
			if terms.recoveryUntil != test.wantRecovery.Unix() {
				t.Errorf("recovery until = %d, want %d", terms.recoveryUntil, test.wantRecovery.Unix())
			}
			if terms.expiresAt != test.wantRecovery.Add(monthlyGracePeriod).Unix() {
				t.Errorf("expiry = %d", terms.expiresAt)
			}
			if terms.refreshAfter > terms.expiresAt {
				t.Errorf("refresh after %d exceeds expiry %d", terms.refreshAfter, terms.expiresAt)
			}
		})
	}
}

func monthlyLicense(state string, billingState entitlement.BillingState, recoveryUntil time.Time, terminalAt sql.NullTime) licenseRecord {
	return licenseRecord{
		plan:              "monthly",
		state:             state,
		subscriptionState: sql.NullString{String: string(billingState), Valid: true},
		billingPeriodEnd:  sql.NullTime{Time: recoveryUntil.Add(-24 * time.Hour), Valid: true},
		recoveryUntil:     sql.NullTime{Time: recoveryUntil, Valid: true},
		terminalAt:        terminalAt,
	}
}
