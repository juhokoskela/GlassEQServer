package activation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEntitlementRefreshWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestService(t, database, localIssuer(t))
	now := service.now()
	seedMonthlyLicense(t, database, "lic_refresh", testLicenseKey, now.Add(14*24*time.Hour))

	activated := activate(t, service, testLicenseKey, testInstallA, "fd46f9d4-3844-4c1d-a5dd-6616af362eef")
	if activated.Status != http.StatusCreated {
		t.Fatalf("activation status = %d, want %d: %s", activated.Status, http.StatusCreated, activated.Body)
	}
	activationBody := decodeSuccess(t, activated)
	refreshTime := now.Add(24 * time.Hour)
	renewedBillingPeriodEnd := now.Add(30 * 24 * time.Hour)
	renewedRecoveryUntil := now.Add(44 * 24 * time.Hour)
	if _, err := database.ExecContext(context.Background(), `
		UPDATE subscriptions
		SET billing_period_end = $1, recovery_until = $2, updated_at = $3
		WHERE license_id = 'lic_refresh'`, renewedBillingPeriodEnd, renewedRecoveryUntil, refreshTime); err != nil {
		t.Fatalf("renew subscription: %v", err)
	}
	service.now = func() time.Time { return refreshTime }

	response, err := service.RefreshEntitlement(context.Background(), RefreshInput{
		ActivationToken: activationBody.ActivationToken,
		InstallationID:  testInstallA,
	})
	if err != nil {
		t.Fatalf("refresh entitlement: %v", err)
	}
	if response.Status != http.StatusOK {
		t.Fatalf("refresh status = %d, want %d: %s", response.Status, http.StatusOK, response.Body)
	}
	body := decodeRefresh(t, response)
	claims := decodeClaims(t, body.Entitlement)
	if claims.Plan != "monthly" || claims.Revision != 2 || claims.InstallationID != testInstallA ||
		claims.BillingPeriodEnd != renewedBillingPeriodEnd.Unix() ||
		claims.ExpiresAt != renewedRecoveryUntil.Add(monthlyGracePeriod).Unix() {
		t.Errorf("refreshed entitlement claims = %+v", claims)
	}
	if strings.Contains(string(response.Body), activationBody.ActivationToken) {
		t.Error("refresh response contained the activation token")
	}

	var revision int64
	var lastRefreshedAt time.Time
	if err := database.QueryRowContext(context.Background(), `
		SELECT entitlement_revision, last_refreshed_at
		FROM activations
		WHERE license_id = 'lic_refresh'`).Scan(&revision, &lastRefreshedAt); err != nil {
		t.Fatalf("read refreshed activation: %v", err)
	}
	if revision != 2 {
		t.Errorf("stored revision = %d, want 2", revision)
	}
	if !lastRefreshedAt.Equal(refreshTime) {
		t.Errorf("last refreshed at = %s, want %s", lastRefreshedAt, refreshTime)
	}
}

func TestEntitlementRefreshRejectsWrongInstallationWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_wrong_installation", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	activationBody := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallA, "174222be-2f60-4ef9-8e31-6ff60742c09a"))

	response, err := service.RefreshEntitlement(context.Background(), RefreshInput{
		ActivationToken: activationBody.ActivationToken,
		InstallationID:  testInstallB,
	})
	if err != nil {
		t.Fatalf("refresh wrong installation: %v", err)
	}
	assertErrorCode(t, response, http.StatusUnauthorized, "invalid_credentials")

	assertActivationRevision(t, database, "lic_wrong_installation", 1)
}

func TestEntitlementRefreshRejectsExpiredMonthlyLicenseWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestService(t, database, localIssuer(t))
	now := service.now()
	seedMonthlyLicense(t, database, "lic_expired", testLicenseKey, now.Add(24*time.Hour))
	activationBody := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallA, "00a3c50a-8b37-4fa0-bf78-22821bd23820"))
	service.now = func() time.Time { return now.Add(8 * 24 * time.Hour) }

	response, err := service.RefreshEntitlement(context.Background(), RefreshInput{
		ActivationToken: activationBody.ActivationToken,
		InstallationID:  testInstallA,
	})
	if err != nil {
		t.Fatalf("refresh expired license: %v", err)
	}
	assertErrorCode(t, response, http.StatusForbidden, "license_not_eligible")
	assertActivationRevision(t, database, "lic_expired", 1)
}

func TestEntitlementRefreshRollsBackSigningFailureWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_refresh_signing", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	activationBody := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallA, "a97a74c9-c352-468b-bc5c-a2dd010d46d2"))
	service.issuer = errorIssuer{}

	_, err := service.RefreshEntitlement(context.Background(), RefreshInput{
		ActivationToken: activationBody.ActivationToken,
		InstallationID:  testInstallA,
	})
	if err == nil {
		t.Fatal("refresh with failing signer succeeded")
	}
	assertActivationRevision(t, database, "lic_refresh_signing", 1)
}

func TestDeactivateCurrentIsIdempotentAndReleasesSlotWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_deactivate", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	first := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallA, "25c135f7-7641-40c9-b405-a7cd6baa406f"))
	second := activate(t, service, testLicenseKey, testInstallB, "4a1680d2-4aeb-485c-a080-f32baf8a92ca")
	if second.Status != http.StatusCreated {
		t.Fatalf("second activation status = %d, want %d: %s", second.Status, http.StatusCreated, second.Body)
	}

	for attempt := range 2 {
		response, err := service.DeactivateCurrent(context.Background(), first.ActivationToken)
		if err != nil {
			t.Fatalf("deactivate attempt %d: %v", attempt+1, err)
		}
		if response.Status != http.StatusNoContent {
			t.Errorf("deactivate attempt %d status = %d, want %d", attempt+1, response.Status, http.StatusNoContent)
		}
	}

	third := activate(t, service, testLicenseKey, testInstallC, "9a858ca0-6a5c-44ed-9365-989e98ca314f")
	if third.Status != http.StatusCreated {
		t.Fatalf("activation after deactivation status = %d, want %d: %s", third.Status, http.StatusCreated, third.Body)
	}
	response, err := service.RefreshEntitlement(context.Background(), RefreshInput{
		ActivationToken: first.ActivationToken,
		InstallationID:  testInstallA,
	})
	if err != nil {
		t.Fatalf("refresh deactivated activation: %v", err)
	}
	assertErrorCode(t, response, http.StatusForbidden, "activation_revoked")

	var state string
	var deactivatedAt sql.NullTime
	installationHash := sha256.Sum256([]byte(testInstallA))
	if err := database.QueryRowContext(context.Background(), `
		SELECT state, deactivated_at
		FROM activations
		WHERE license_id = 'lic_deactivate' AND installation_hash = $1`, installationHash[:]).Scan(&state, &deactivatedAt); err != nil {
		t.Fatalf("read deactivated activation: %v", err)
	}
	if state != "deactivated" || !deactivatedAt.Valid {
		t.Errorf("deactivated activation = (%q, %v)", state, deactivatedAt)
	}
}

func decodeRefresh(t *testing.T, response Response) refreshBody {
	t.Helper()
	var body refreshBody
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	return body
}

func assertActivationRevision(t *testing.T, database *sql.DB, licenseID string, want int64) {
	t.Helper()
	var revision int64
	if err := database.QueryRowContext(context.Background(), `
		SELECT entitlement_revision
		FROM activations
		WHERE license_id = $1`, licenseID).Scan(&revision); err != nil {
		t.Fatalf("read activation revision: %v", err)
	}
	if revision != want {
		t.Errorf("activation revision = %d, want %d", revision, want)
	}
}
