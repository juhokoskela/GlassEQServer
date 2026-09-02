package activation

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLicenseKeyRotationWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_rotation", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	activation := decodeSuccess(t, activate(t, service, testLicenseKey, testInstallA, "cb0d985e-1595-44bd-91d4-e4e25c639ae6"))
	session := decodeManagementSession(t, createManagementSession(t, service, testLicenseKey))

	input := LicenseKeyRotationInput{
		ManagementToken: session.ManagementToken,
		IdempotencyKey:  "80cbbaf8-a9a4-4920-80a7-3aa29d25b309",
	}
	first := rotateLicenseKey(t, service, input)
	firstBody := decodeLicenseKeyRotation(t, first)
	if firstBody.LicenseKey == testLicenseKey {
		t.Error("rotation returned the previous license key")
	}
	if _, valid := normalizeLicenseKey(firstBody.LicenseKey); !valid {
		t.Errorf("rotated license key is invalid: %q", firstBody.LicenseKey)
	}

	replay := rotateLicenseKey(t, service, input)
	if replay.Status != first.Status || string(replay.Body) != string(first.Body) {
		t.Errorf("replay = (%d, %s), want (%d, %s)", replay.Status, replay.Body, first.Status, first.Body)
	}
	assertRotationResponseIsEncrypted(t, database, firstBody.LicenseKey)
	assertErrorCode(t, createManagementSession(t, service, testLicenseKey), http.StatusUnauthorized, "invalid_credentials")
	if response := createManagementSession(t, service, firstBody.LicenseKey); response.Status != http.StatusCreated {
		t.Errorf("management session with rotated key status = %d, want %d", response.Status, http.StatusCreated)
	}

	refreshed, err := service.RefreshEntitlement(context.Background(), RefreshInput{
		ActivationToken: activation.ActivationToken,
		InstallationID:  testInstallA,
	})
	if err != nil {
		t.Fatalf("refresh after license-key rotation: %v", err)
	}
	if refreshed.Status != http.StatusOK {
		t.Errorf("refresh after rotation status = %d, want %d", refreshed.Status, http.StatusOK)
	}

	second := rotateLicenseKey(t, service, LicenseKeyRotationInput{
		ManagementToken: session.ManagementToken,
		IdempotencyKey:  "b0554c65-a281-4bfe-8de6-c10d07992950",
	})
	secondBody := decodeLicenseKeyRotation(t, second)
	if secondBody.LicenseKey == firstBody.LicenseKey {
		t.Error("second rotation returned the previous license key")
	}
	assertErrorCode(t, createManagementSession(t, service, firstBody.LicenseKey), http.StatusUnauthorized, "invalid_credentials")
	if response := createManagementSession(t, service, secondBody.LicenseKey); response.Status != http.StatusCreated {
		t.Errorf("management session with second rotated key status = %d, want %d", response.Status, http.StatusCreated)
	}

	assertRowCount(t, database, "SELECT count(*) FROM license_keys WHERE license_id = 'lic_rotation' AND state = 'active'", nil, 1)
	assertRowCount(t, database, "SELECT count(*) FROM license_keys WHERE license_id = 'lic_rotation' AND state = 'revoked'", nil, 2)
	assertRowCount(t, database, "SELECT count(*) FROM activations WHERE license_id = 'lic_rotation' AND state = 'active'", nil, 1)
}

func TestLicenseKeyRotationRejectsExpiredManagementSessionWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_rotation_expired", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	session := decodeManagementSession(t, createManagementSession(t, service, testLicenseKey))
	service.now = func() time.Time { return time.Unix(session.ExpiresAt, 0).UTC() }

	response := rotateLicenseKey(t, service, LicenseKeyRotationInput{
		ManagementToken: session.ManagementToken,
		IdempotencyKey:  "fb594f7f-6139-49db-8e8b-d32d6368e7ea",
	})
	assertErrorCode(t, response, http.StatusUnauthorized, "invalid_credentials")
	assertRowCount(t, database, "SELECT count(*) FROM license_keys WHERE license_id = 'lic_rotation_expired' AND state = 'active'", nil, 1)
}

func TestLicenseKeyRotationReturnsWhenLicenseIsBusyWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_rotation_busy", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	session := decodeManagementSession(t, createManagementSession(t, service, testLicenseKey))

	lock, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin license lock: %v", err)
	}
	t.Cleanup(func() { lock.Rollback() })
	if _, err := lock.ExecContext(context.Background(), "SELECT id FROM licenses WHERE id = 'lic_rotation_busy' FOR NO KEY UPDATE"); err != nil {
		t.Fatalf("lock license: %v", err)
	}

	response := rotateLicenseKey(t, service, LicenseKeyRotationInput{
		ManagementToken: session.ManagementToken,
		IdempotencyKey:  "e7f109c5-ad3f-455f-bf96-cf2de4142802",
	})
	assertErrorCode(t, response, http.StatusServiceUnavailable, "temporarily_unavailable")
	if response.RetryAfterSeconds != 1 {
		t.Errorf("Retry-After = %d, want 1", response.RetryAfterSeconds)
	}
	assertRowCount(t, database, "SELECT count(*) FROM idempotency_records WHERE scope = 'license_key_rotation'", nil, 0)
}

func rotateLicenseKey(t *testing.T, service *Service, input LicenseKeyRotationInput) Response {
	t.Helper()
	response, err := service.RotateLicenseKey(context.Background(), input)
	if err != nil {
		t.Fatalf("rotate license key: %v", err)
	}
	return response
}

func decodeLicenseKeyRotation(t *testing.T, response Response) licenseKeyRotationBody {
	t.Helper()
	if response.Status != http.StatusCreated {
		t.Fatalf("license-key rotation status = %d, want %d: %s", response.Status, http.StatusCreated, response.Body)
	}
	var body licenseKeyRotationBody
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("decode license-key rotation: %v", err)
	}
	return body
}

func assertRotationResponseIsEncrypted(t *testing.T, database *sql.DB, licenseKey string) {
	t.Helper()
	var ciphertext []byte
	if err := database.QueryRowContext(context.Background(), `
		SELECT response_ciphertext
		FROM idempotency_records
		WHERE scope = $1`, licenseKeyRotationScope).Scan(&ciphertext); err != nil {
		t.Fatalf("read stored rotation replay: %v", err)
	}
	if strings.Contains(string(ciphertext), licenseKey) {
		t.Error("stored replay contains the plaintext license key")
	}
}
