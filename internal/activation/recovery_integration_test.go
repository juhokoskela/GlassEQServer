package activation

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testRecoveryTokenLifetime = 30 * time.Minute

func TestRecoveryTokenExchangeWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_recovery", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	exchangeTime := service.now()
	recoveryToken := testRecoveryToken(1)
	seedRecoveryToken(t, database, "lic_recovery", recoveryToken, service.now())
	input := RecoverySessionInput{
		RecoveryToken:  recoveryToken,
		IdempotencyKey: "21b10f07-81ad-4c17-af59-7b5b68b84819",
	}

	response, err := service.ExchangeRecoveryToken(context.Background(), input)
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
	assertRecoveryResponseIsEncrypted(t, database, session.ManagementToken)

	listed, err := service.ListManagedActivations(context.Background(), session.ManagementToken)
	if err != nil {
		t.Fatalf("list activations with recovered management token: %v", err)
	}
	if listed.Status != http.StatusOK {
		t.Errorf("list status = %d, want %d", listed.Status, http.StatusOK)
	}

	replay, err := service.ExchangeRecoveryToken(context.Background(), input)
	if err != nil {
		t.Fatalf("replay recovery exchange: %v", err)
	}
	if replay.Status != response.Status || string(replay.Body) != string(response.Body) {
		t.Errorf("replay = (%d, %s), want (%d, %s)", replay.Status, replay.Body, response.Status, response.Body)
	}

	reused, err := service.ExchangeRecoveryToken(context.Background(), RecoverySessionInput{
		RecoveryToken:  recoveryToken,
		IdempotencyKey: "51ef9ad2-d59f-4261-bb24-0b7e132e61a4",
	})
	if err != nil {
		t.Fatalf("reuse recovery token for a new exchange: %v", err)
	}
	assertErrorCode(t, reused, http.StatusUnauthorized, "invalid_credentials")
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE license_id = 'lic_recovery' AND purpose = 'management'", nil, 1)

	service.now = func() time.Time { return exchangeTime.Add(testRecoveryTokenLifetime) }
	expiredTokenReplay, err := service.ExchangeRecoveryToken(context.Background(), input)
	if err != nil {
		t.Fatalf("replay after recovery token expiry: %v", err)
	}
	if expiredTokenReplay.Status != response.Status || string(expiredTokenReplay.Body) != string(response.Body) {
		t.Errorf("expired-token replay = (%d, %s), want (%d, %s)", expiredTokenReplay.Status, expiredTokenReplay.Body, response.Status, response.Body)
	}
}

func TestRecoveryTokenExchangeRejectsExpiredTokenWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_recovery_expired", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	recoveryToken := testRecoveryToken(2)
	seedRecoveryToken(t, database, "lic_recovery_expired", recoveryToken, service.now().Add(-testRecoveryTokenLifetime))

	response, err := service.ExchangeRecoveryToken(context.Background(), RecoverySessionInput{
		RecoveryToken:  recoveryToken,
		IdempotencyKey: "1806a6d2-e4ad-4f29-a69a-3eea407a3f45",
	})
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
	input := RecoverySessionInput{
		RecoveryToken:  recoveryToken,
		IdempotencyKey: "4230d371-b8c1-4286-b60a-6656f451591d",
	}

	type result struct {
		response Response
		err      error
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			response, err := service.ExchangeRecoveryToken(ctx, input)
			results <- result{response: response, err: err}
		}()
	}
	close(start)

	var created Response
	busy := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("exchange recovery token concurrently: %v", result.err)
		}
		switch result.response.Status {
		case http.StatusCreated:
			if created.Status == 0 {
				created = result.response
			} else if string(result.response.Body) != string(created.Body) {
				t.Errorf("concurrent replay body = %s, want %s", result.response.Body, created.Body)
			}
		case http.StatusServiceUnavailable:
			busy++
		default:
			t.Errorf("concurrent exchange status = %d", result.response.Status)
		}
	}
	if created.Status == 0 {
		t.Fatal("neither concurrent exchange succeeded")
	}
	if busy > 0 {
		replay, err := service.ExchangeRecoveryToken(context.Background(), input)
		if err != nil {
			t.Fatalf("retry busy recovery exchange: %v", err)
		}
		if replay.Status != created.Status || string(replay.Body) != string(created.Body) {
			t.Errorf("retry = (%d, %s), want (%d, %s)", replay.Status, replay.Body, created.Status, created.Body)
		}
	}
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE license_id = 'lic_recovery_single_use' AND purpose = 'management'", nil, 1)
	assertRowCount(t, database, "SELECT count(*) FROM idempotency_records WHERE scope = 'recovery_session'", nil, 1)
}

func TestRecoveryTokenExchangeRollsBackWhenReplayEncryptionFailsWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_recovery_rollback", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	recoveryToken := testRecoveryToken(4)
	seedRecoveryToken(t, database, "lic_recovery_rollback", recoveryToken, service.now())
	input := RecoverySessionInput{
		RecoveryToken:  recoveryToken,
		IdempotencyKey: "5134cb7d-2b69-4619-a86f-309114986e32",
	}

	service.responses.random = bytes.NewReader(nil)

	if _, err := service.ExchangeRecoveryToken(context.Background(), input); err == nil {
		t.Fatal("exchange with failed replay encryption succeeded")
	}
	recoveryHash, _ := recoveryTokenHash(recoveryToken)
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE token_hash = $1 AND consumed_at IS NULL", recoveryHash[:], 1)
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE license_id = 'lic_recovery_rollback' AND purpose = 'management'", nil, 0)
	assertRowCount(t, database, "SELECT count(*) FROM idempotency_records WHERE scope = 'recovery_session'", nil, 0)

	service.responses.random = bytes.NewReader(make([]byte, 12))
	if response, err := service.ExchangeRecoveryToken(context.Background(), input); err != nil {
		t.Fatalf("exchange recovery token after rollback: %v", err)
	} else if response.Status != http.StatusCreated {
		t.Errorf("exchange status after rollback = %d, want %d", response.Status, http.StatusCreated)
	}
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
		VALUES ($1, $2, 'recovery', $3, $4)`, tokenHash[:], licenseID, createdAt, createdAt.Add(testRecoveryTokenLifetime))
	if err != nil {
		t.Fatalf("seed recovery token: %v", err)
	}
}

func assertRecoveryResponseIsEncrypted(t *testing.T, database *sql.DB, managementToken string) {
	t.Helper()
	var ciphertext []byte
	if err := database.QueryRowContext(context.Background(), `
		SELECT response_ciphertext
		FROM idempotency_records
		WHERE scope = $1`, recoverySessionScope).Scan(&ciphertext); err != nil {
		t.Fatalf("read stored recovery-session replay: %v", err)
	}
	if strings.Contains(string(ciphertext), managementToken) {
		t.Error("stored replay contains the plaintext management token")
	}
}
