package activation

import (
	"bytes"
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
	rotationTime := service.now()
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

	second := rotateLicenseKey(t, service, LicenseKeyRotationInput{
		ManagementToken: session.ManagementToken,
		IdempotencyKey:  "b0554c65-a281-4bfe-8de6-c10d07992950",
	})
	assertErrorCode(t, second, http.StatusUnauthorized, "invalid_credentials")
	assertErrorCode(t, createManagementSession(t, service, testLicenseKey), http.StatusUnauthorized, "invalid_credentials")
	newSessionResponse := createManagementSession(t, service, firstBody.LicenseKey)
	if newSessionResponse.Status != http.StatusCreated {
		t.Fatalf("management session with rotated key status = %d, want %d", newSessionResponse.Status, http.StatusCreated)
	}
	newSession := decodeManagementSession(t, newSessionResponse)
	cooldown := rotateLicenseKey(t, service, LicenseKeyRotationInput{
		ManagementToken: newSession.ManagementToken,
		IdempotencyKey:  "f4bf4696-78d0-414f-9c7a-b0fc79e3c34f",
	})
	assertErrorCode(t, cooldown, http.StatusTooManyRequests, "rate_limited")
	if cooldown.RetryAfterSeconds != int(licenseKeyRotationCooldown.Seconds()) {
		t.Errorf("cooldown Retry-After = %d", cooldown.RetryAfterSeconds)
	}

	service.now = func() time.Time { return rotationTime.Add(managementTokenLifetime) }
	expiredSessionReplay := rotateLicenseKey(t, service, input)
	if expiredSessionReplay.Status != first.Status || string(expiredSessionReplay.Body) != string(first.Body) {
		t.Errorf("expired-session replay = (%d, %s), want (%d, %s)", expiredSessionReplay.Status, expiredSessionReplay.Body, first.Status, first.Body)
	}

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

	assertRowCount(t, database, "SELECT count(*) FROM license_keys WHERE license_id = 'lic_rotation' AND state = 'active'", nil, 1)
	assertRowCount(t, database, "SELECT count(*) FROM license_keys WHERE license_id = 'lic_rotation' AND state = 'revoked'", nil, 1)
	assertRowCount(t, database, "SELECT count(*) FROM activations WHERE license_id = 'lic_rotation' AND state = 'active'", nil, 1)
}

func TestLicenseKeyRotationBoundsRetainedKeysWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_rotation_retention", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	currentKey := testLicenseKey
	now := service.now()
	service.now = func() time.Time { return now }
	idempotencyKeys := [...]string{
		"d532f449-4f43-4375-b941-141649636a1c",
		"3f779e0e-5a3f-491c-b2c8-68251c04ac45",
		"c61566bf-159c-4ef0-acf9-ef301ee295f9",
	}

	for rotation := range 3 {
		if rotation > 0 {
			now = now.Add(licenseKeyRotationCooldown)
		}
		session := decodeManagementSession(t, createManagementSession(t, service, currentKey))
		response := rotateLicenseKey(t, service, LicenseKeyRotationInput{
			ManagementToken: session.ManagementToken,
			IdempotencyKey:  idempotencyKeys[rotation],
		})
		currentKey = decodeLicenseKeyRotation(t, response).LicenseKey
	}

	assertRowCount(t, database, "SELECT count(*) FROM license_keys WHERE license_id = 'lic_rotation_retention' AND state = 'active'", nil, 1)
	assertRowCount(t, database, "SELECT count(*) FROM license_keys WHERE license_id = 'lic_rotation_retention' AND state = 'revoked'", nil, 1)
}

func TestLicenseKeyRotationRollsBackWhenReplayEncryptionFailsWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_rotation_rollback", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	session := decodeManagementSession(t, createManagementSession(t, service, testLicenseKey))
	service.responses.random = bytes.NewReader(nil)

	_, err := service.RotateLicenseKey(context.Background(), LicenseKeyRotationInput{
		ManagementToken: session.ManagementToken,
		IdempotencyKey:  "a17721ab-5c74-4d7d-8494-f3e47cdf0ab7",
	})
	if err == nil {
		t.Fatal("rotation with failed replay encryption succeeded")
	}

	assertRowCount(t, database, "SELECT count(*) FROM license_keys WHERE license_id = 'lic_rotation_rollback' AND state = 'active'", nil, 1)
	assertRowCount(t, database, "SELECT count(*) FROM license_keys WHERE license_id = 'lic_rotation_rollback' AND state = 'revoked'", nil, 0)
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens", nil, 1)
	assertRowCount(t, database, "SELECT count(*) FROM idempotency_records", nil, 0)
	if response := createManagementSession(t, service, testLicenseKey); response.Status != http.StatusCreated {
		t.Errorf("management session with original key status = %d, want %d", response.Status, http.StatusCreated)
	}
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

func TestLicenseKeyRotationLocksManagementSessionAgainstCleanupWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_rotation_session_lock", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	session := decodeManagementSession(t, createManagementSession(t, service, testLicenseKey))
	tokenHash, valid := managementTokenHash(session.ManagementToken)
	if !valid {
		t.Fatal("generated management token is invalid")
	}

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin rotation transaction: %v", err)
	}
	t.Cleanup(func() { tx.Rollback() })

	expiresAt := time.Unix(session.ExpiresAt, 0).UTC()
	if _, found, err := lockManagementLicense(
		context.Background(),
		tx,
		tokenHash,
		expiresAt.Add(-time.Second),
	); err != nil {
		t.Fatalf("lock management session: %v", err)
	} else if !found {
		t.Fatal("management session was not found")
	}

	if _, err := service.CleanupExpired(context.Background(), expiresAt); err != nil {
		t.Fatalf("clean expired records during rotation: %v", err)
	}
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE token_hash = $1", tokenHash[:], 1)

	if err := tx.Rollback(); err != nil {
		t.Fatalf("roll back rotation transaction: %v", err)
	}
	if _, err := service.CleanupExpired(context.Background(), expiresAt); err != nil {
		t.Fatalf("clean expired records after rotation: %v", err)
	}
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE token_hash = $1", tokenHash[:], 0)
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
