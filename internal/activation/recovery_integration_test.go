package activation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"testing"
	"time"
)

func TestRecoveryTokenExchangeWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_recovery", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	recoveryToken := testRecoveryToken(1)
	seedRecoveryToken(t, database, "lic_recovery", recoveryToken, service.now())

	response, err := service.ExchangeRecoveryToken(context.Background(), recoveryToken)
	if err != nil {
		t.Fatalf("exchange recovery token: %v", err)
	}
	session := decodeManagementSession(t, response)
	if _, valid := managementTokenHash(session.ManagementToken); !valid {
		t.Errorf("management token is invalid: %q", session.ManagementToken)
	}
	if session.ExpiresAt != service.now().Add(managementTokenLifetime).Unix() {
		t.Errorf("management expiry = %d", session.ExpiresAt)
	}

	recoveryHash, _ := recoveryTokenHash(recoveryToken)
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE token_hash = $1 AND consumed_at IS NOT NULL", recoveryHash[:], 1)
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE license_id = 'lic_recovery' AND purpose = 'management'", nil, 1)

	reused, err := service.ExchangeRecoveryToken(context.Background(), recoveryToken)
	if err != nil {
		t.Fatalf("reuse recovery token: %v", err)
	}
	assertErrorCode(t, reused, http.StatusUnauthorized, "invalid_credentials")
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE license_id = 'lic_recovery' AND purpose = 'management'", nil, 1)
}

func TestRecoveryTokenExchangeRejectsExpiredTokenWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_recovery_expired", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	recoveryToken := testRecoveryToken(2)
	seedRecoveryToken(t, database, "lic_recovery_expired", recoveryToken, service.now().Add(-recoveryTokenLifetime))

	response, err := service.ExchangeRecoveryToken(context.Background(), recoveryToken)
	if err != nil {
		t.Fatalf("exchange expired recovery token: %v", err)
	}
	assertErrorCode(t, response, http.StatusUnauthorized, "invalid_credentials")
	recoveryHash, _ := recoveryTokenHash(recoveryToken)
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE token_hash = $1 AND consumed_at IS NULL", recoveryHash[:], 1)
}

func TestRecoveryTokenExchangeIsSingleUseWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_recovery_single_use", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	recoveryToken := testRecoveryToken(3)
	seedRecoveryToken(t, database, "lic_recovery_single_use", recoveryToken, service.now())

	type result struct {
		response Response
		err      error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			response, err := service.ExchangeRecoveryToken(context.Background(), recoveryToken)
			results <- result{response: response, err: err}
		}()
	}
	close(start)

	statuses := map[int]int{}
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("exchange recovery token concurrently: %v", result.err)
		}
		statuses[result.response.Status]++
	}
	if statuses[http.StatusCreated] != 1 || statuses[http.StatusUnauthorized] != 1 {
		t.Errorf("exchange statuses = %v", statuses)
	}
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE license_id = 'lic_recovery_single_use' AND purpose = 'management'", nil, 1)
}

func TestRecoveryTokenExchangeRollsBackConsumptionWhenSessionInsertFailsWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_recovery_rollback", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	recoveryToken := testRecoveryToken(4)
	seedRecoveryToken(t, database, "lic_recovery_rollback", recoveryToken, service.now())

	managementToken := managementTokenPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	managementHash := sha256.Sum256([]byte(managementToken))
	_, err := database.ExecContext(context.Background(), `
		INSERT INTO access_tokens (token_hash, license_id, purpose, created_at, expires_at)
		VALUES ($1, 'lic_recovery_rollback', 'management', $2, $3)`,
		managementHash[:], service.now(), service.now().Add(managementTokenLifetime))
	if err != nil {
		t.Fatalf("seed colliding management token: %v", err)
	}
	service.random = bytes.NewReader(make([]byte, 32))

	if _, err := service.ExchangeRecoveryToken(context.Background(), recoveryToken); err == nil {
		t.Fatal("exchange with colliding management token succeeded")
	}
	recoveryHash, _ := recoveryTokenHash(recoveryToken)
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE token_hash = $1 AND consumed_at IS NULL", recoveryHash[:], 1)
}

func testRecoveryToken(value byte) string {
	return recoveryTokenPrefix + base64.RawURLEncoding.EncodeToString(bytesOf(value, 32))
}

func seedRecoveryToken(t *testing.T, database *sql.DB, licenseID, token string, createdAt time.Time) {
	t.Helper()
	tokenHash, valid := recoveryTokenHash(token)
	if !valid {
		t.Fatalf("test recovery token %q is invalid", token)
	}
	_, err := database.ExecContext(context.Background(), `
		INSERT INTO access_tokens (token_hash, license_id, purpose, created_at, expires_at)
		VALUES ($1, $2, 'recovery', $3, $4)`, tokenHash[:], licenseID, createdAt, createdAt.Add(recoveryTokenLifetime))
	if err != nil {
		t.Fatalf("seed recovery token: %v", err)
	}
}
