package activation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestManagementSessionListsActiveSlotsWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_management", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	first := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallA, "26a6756f-579f-4521-ab07-f662ed50a903"))
	second := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallB, "0cba4ae2-ce4f-4577-a0aa-34e414e47ee6"))

	session := createManagementSession(t, service, testLicenseKey)
	if session.Status != http.StatusCreated {
		t.Fatalf("management session status = %d, want %d: %s", session.Status, http.StatusCreated, session.Body)
	}
	sessionBody := decodeManagementSession(t, session)
	if _, valid := managementTokenHash(sessionBody.ManagementToken); !valid {
		t.Errorf("management token is invalid: %q", sessionBody.ManagementToken)
	}
	if sessionBody.ExpiresAt != service.now().Add(managementTokenLifetime).Unix() {
		t.Errorf("management expiry = %d", sessionBody.ExpiresAt)
	}

	response, err := service.ListManagedActivations(context.Background(), sessionBody.ManagementToken)
	if err != nil {
		t.Fatalf("list managed activations: %v", err)
	}
	if response.Status != http.StatusOK {
		t.Fatalf("list status = %d, want %d: %s", response.Status, http.StatusOK, response.Body)
	}
	body := decodeManagedActivations(t, response)
	wantIDs := map[string]bool{
		decodeClaims(t, first.Entitlement).ActivationID:  true,
		decodeClaims(t, second.Entitlement).ActivationID: true,
	}
	if len(body.Activations) != len(wantIDs) {
		t.Fatalf("managed activations = %+v", body.Activations)
	}
	for _, activation := range body.Activations {
		if !wantIDs[activation.ID] {
			t.Errorf("unexpected managed activation %q", activation.ID)
		}
		if activation.ActivatedAt != service.now().Unix() || activation.LastRefreshedAt != service.now().Unix() {
			t.Errorf("managed activation times = %+v", activation)
		}
	}

	tokenHash := sha256.Sum256([]byte(sessionBody.ManagementToken))
	assertRowCount(t, database, `
		SELECT count(*)
		FROM access_tokens
		WHERE token_hash = $1 AND purpose = 'management'`, tokenHash[:], 1)
	service.now = func() time.Time { return time.Unix(sessionBody.ExpiresAt, 0).UTC() }
	deleted, err := service.CleanupExpired(context.Background(), service.now())
	if err != nil {
		t.Fatalf("clean expired management session: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted rows = %d, want 1", deleted)
	}
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens", nil, 0)
}

func TestManagementSessionRateLimitWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestService(t, database, localIssuer(t))

	for attempt := 1; attempt <= licenseKeyAttemptLimit+1; attempt++ {
		response := createManagementSession(t, service, testLicenseKey)
		if attempt <= licenseKeyAttemptLimit {
			assertErrorCode(t, response, http.StatusUnauthorized, "invalid_credentials")
			continue
		}
		assertErrorCode(t, response, http.StatusTooManyRequests, "rate_limited")
	}
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens", nil, 0)
}

func TestManagedDeactivationIsIdempotentAndReleasesSlotWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_remote_deactivate", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	first := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallA, "e1af1f07-b2bb-4f39-ae14-f15bfccf4db5"))
	second := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallB, "cd605aca-ac65-40de-a961-c3ad03268293"))
	firstID := decodeClaims(t, first.Entitlement).ActivationID
	secondID := decodeClaims(t, second.Entitlement).ActivationID
	session := decodeManagementSession(t, createManagementSession(t, service, testLicenseKey))

	for attempt := range 2 {
		response, err := service.DeactivateManaged(context.Background(), ManagedDeactivationInput{
			ManagementToken: session.ManagementToken,
			ActivationID:    firstID,
		})
		if err != nil {
			t.Fatalf("managed deactivation attempt %d: %v", attempt+1, err)
		}
		if response.Status != http.StatusNoContent {
			t.Errorf("managed deactivation attempt %d status = %d, want %d", attempt+1, response.Status, http.StatusNoContent)
		}
	}

	listed, err := service.ListManagedActivations(context.Background(), session.ManagementToken)
	if err != nil {
		t.Fatalf("list after managed deactivation: %v", err)
	}
	activations := decodeManagedActivations(t, listed).Activations
	if len(activations) != 1 || activations[0].ID != secondID {
		t.Errorf("active managed slots = %+v, want %q", activations, secondID)
	}
	third := activate(t, service, testLicenseKey, testInstallC, "80cf82b3-03dd-4ea7-879c-3191a57218d9")
	if third.Status != http.StatusCreated {
		t.Fatalf("activation after managed release status = %d, want %d: %s", third.Status, http.StatusCreated, third.Body)
	}
	refreshed, err := service.RefreshEntitlement(context.Background(), RefreshInput{
		ActivationToken: first.ActivationToken,
		InstallationID:  testInstallA,
	})
	if err != nil {
		t.Fatalf("refresh remotely deactivated activation: %v", err)
	}
	assertErrorCode(t, refreshed, http.StatusForbidden, "activation_revoked")
}

func TestManagedDeactivationCannotCrossLicensesWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_managed_a", testLicenseKey)
	seedPerpetualLicense(t, database, "lic_managed_b", testLicenseKeyB)
	service := newTestService(t, database, localIssuer(t))
	first := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallA, "c6f2c179-a272-4150-9f1f-9e9f8564d576"))
	firstID := decodeClaims(t, first.Entitlement).ActivationID
	session := decodeManagementSession(t, createManagementSession(t, service, testLicenseKeyB))

	response, err := service.DeactivateManaged(context.Background(), ManagedDeactivationInput{
		ManagementToken: session.ManagementToken,
		ActivationID:    firstID,
	})
	if err != nil {
		t.Fatalf("cross-license managed deactivation: %v", err)
	}
	if response.Status != http.StatusNoContent {
		t.Errorf("cross-license status = %d, want %d", response.Status, http.StatusNoContent)
	}
	assertRowCount(t, database, `
		SELECT count(*)
		FROM activations
		WHERE id = $1 AND state = 'active'`, firstID, 1)
}

func TestManagedDeactivationReturnsWhenActivationIsBusyWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_managed_busy", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	activation := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallA, "cefcaa68-5354-4b69-9672-98f449a6a439"))
	activationID := decodeClaims(t, activation.Entitlement).ActivationID
	session := decodeManagementSession(t, createManagementSession(t, service, testLicenseKey))

	lock, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin activation lock: %v", err)
	}
	t.Cleanup(func() { lock.Rollback() })
	if _, err := lock.ExecContext(context.Background(), "SELECT id FROM activations WHERE id = $1 FOR UPDATE", activationID); err != nil {
		t.Fatalf("lock activation: %v", err)
	}

	response, err := service.DeactivateManaged(context.Background(), ManagedDeactivationInput{
		ManagementToken: session.ManagementToken,
		ActivationID:    activationID,
	})
	if err != nil {
		t.Fatalf("deactivate busy activation: %v", err)
	}
	assertErrorCode(t, response, http.StatusServiceUnavailable, "temporarily_unavailable")
	if response.RetryAfterSeconds != 1 {
		t.Errorf("Retry-After = %d, want 1", response.RetryAfterSeconds)
	}
}

func TestExpiredManagementSessionIsRejectedWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_management_expired", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	activation := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallA, "33bc50e0-cd48-4a22-a034-900f68a6de76"))
	activationID := decodeClaims(t, activation.Entitlement).ActivationID
	session := decodeManagementSession(t, createManagementSession(t, service, testLicenseKey))
	service.now = func() time.Time { return time.Unix(session.ExpiresAt, 0).UTC() }

	listed, err := service.ListManagedActivations(context.Background(), session.ManagementToken)
	if err != nil {
		t.Fatalf("list with expired session: %v", err)
	}
	assertErrorCode(t, listed, http.StatusUnauthorized, "invalid_credentials")
	deactivated, err := service.DeactivateManaged(context.Background(), ManagedDeactivationInput{
		ManagementToken: session.ManagementToken,
		ActivationID:    activationID,
	})
	if err != nil {
		t.Fatalf("deactivate with expired session: %v", err)
	}
	assertErrorCode(t, deactivated, http.StatusUnauthorized, "invalid_credentials")
	assertRowCount(t, database, `
		SELECT count(*)
		FROM activations
		WHERE id = $1 AND state = 'active'`, activationID, 1)
}

func createManagementSession(t *testing.T, service *Service, licenseKey string) Response {
	t.Helper()
	response, err := service.CreateManagementSession(context.Background(), ManagementSessionInput{
		LicenseKey: licenseKey,
		ClientIP:   netip.MustParseAddr("192.0.2.42"),
	})
	if err != nil {
		t.Fatalf("create management session: %v", err)
	}
	return response
}

func decodeManagementSession(t *testing.T, response Response) managementSessionBody {
	t.Helper()
	if response.Status != http.StatusCreated {
		t.Fatalf("management session status = %d, want %d: %s", response.Status, http.StatusCreated, response.Body)
	}
	var body managementSessionBody
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("decode management session: %v", err)
	}
	return body
}

func decodeManagedActivations(t *testing.T, response Response) managedActivationsBody {
	t.Helper()
	if response.Status != http.StatusOK {
		t.Fatalf("managed activations status = %d, want %d: %s", response.Status, http.StatusOK, response.Body)
	}
	var body managedActivationsBody
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("decode managed activations: %v", err)
	}
	return body
}
