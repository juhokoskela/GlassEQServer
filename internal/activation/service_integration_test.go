package activation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/juhokoskela/GlassEQServer/internal/entitlement"
)

const (
	testLicenseKey = "GEQ1-01234-56789-ABCDE-FGHJK-MNPQR-S"
	testInstallA   = "4E70638A-A75B-4BFB-B4B0-15E959A91465"
	testInstallB   = "9184CDB7-1EB1-43E5-97F3-EC269111171F"
	testInstallC   = "D45AB9E0-606C-4873-A285-14F3339D026D"
)

func TestActivationLifecycleWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_lifecycle", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))

	first := activate(t, service, testLicenseKey, testInstallA, "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23")
	if first.Status != http.StatusCreated {
		t.Fatalf("first status = %d, want %d: %s", first.Status, http.StatusCreated, first.Body)
	}
	firstBody := decodeSuccess(t, first)
	claims := decodeClaims(t, firstBody.Entitlement)
	if claims.Plan != "perpetual_v1" || claims.Revision != 1 || claims.InstallationID != testInstallA {
		t.Errorf("first entitlement claims = %+v", claims)
	}

	replay := activate(t, service, testLicenseKey, testInstallA, "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23")
	if replay.Status != first.Status || string(replay.Body) != string(first.Body) {
		t.Errorf("replay = (%d, %s), want (%d, %s)", replay.Status, replay.Body, first.Status, first.Body)
	}
	assertStoredResponseIsEncrypted(t, database, firstBody.ActivationToken)

	conflict := activate(t, service, testLicenseKey, testInstallB, "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23")
	assertErrorCode(t, conflict, http.StatusConflict, "idempotency_conflict")

	reactivated := activate(t, service, testLicenseKey, testInstallA, "0cab5769-e736-490f-82b8-b445e81c36cc")
	if reactivated.Status != http.StatusOK {
		t.Fatalf("reactivation status = %d, want %d: %s", reactivated.Status, http.StatusOK, reactivated.Body)
	}
	reactivatedBody := decodeSuccess(t, reactivated)
	if reactivatedBody.ActivationToken == firstBody.ActivationToken {
		t.Error("reactivation did not rotate the activation token")
	}
	if claims := decodeClaims(t, reactivatedBody.Entitlement); claims.Revision != 2 {
		t.Errorf("reactivation revision = %d, want 2", claims.Revision)
	}
	assertActivationCount(t, database, "lic_lifecycle", 1)
}

func TestActivationLimitIsAtomicWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_limit", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))

	first := activate(t, service, testLicenseKey, testInstallA, "fbec68c9-04d2-4245-9991-ea624bc29c90")
	if first.Status != http.StatusCreated {
		t.Fatalf("first status = %d, want %d: %s", first.Status, http.StatusCreated, first.Body)
	}

	inputs := []Input{
		activationInput(testLicenseKey, testInstallB, "688db6f4-bb35-44dc-a42a-0c36eb842de1"),
		activationInput(testLicenseKey, testInstallC, "2e1e5683-dda7-4b87-8d68-e357851b6633"),
	}
	responses := make([]Response, len(inputs))
	errorsByIndex := make([]error, len(inputs))
	var wait sync.WaitGroup
	for index := range inputs {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses[index], errorsByIndex[index] = service.Activate(context.Background(), inputs[index])
		}()
	}
	wait.Wait()

	created, limited := 0, 0
	for index, response := range responses {
		if errorsByIndex[index] != nil {
			t.Fatalf("concurrent activation %d: %v", index, errorsByIndex[index])
		}
		switch response.Status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			assertErrorCode(t, response, http.StatusConflict, "activation_limit")
			limited++
		default:
			t.Errorf("concurrent activation status = %d: %s", response.Status, response.Body)
		}
	}
	if created != 1 || limited != 1 {
		t.Errorf("created = %d, limited = %d; want 1 each", created, limited)
	}
	assertActivationCount(t, database, "lic_limit", 2)
}

func TestActivationRollsBackSigningFailureWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_signing", testLicenseKey)
	failing := newTestService(t, database, errorIssuer{})
	input := activationInput(testLicenseKey, testInstallA, "ad65c3fd-9968-4c99-8367-bf96152c14f0")

	if _, err := failing.Activate(context.Background(), input); err == nil {
		t.Fatal("activation with failing signer succeeded")
	}
	assertActivationCount(t, database, "lic_signing", 0)

	working := newTestService(t, database, localIssuer(t))
	response, err := working.Activate(context.Background(), input)
	if err != nil {
		t.Fatalf("activation after signer recovery: %v", err)
	}
	if response.Status != http.StatusCreated {
		t.Fatalf("status after signer recovery = %d: %s", response.Status, response.Body)
	}
}

func TestActivationRateLimitWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestService(t, database, localIssuer(t))

	for attempt := 1; attempt <= licenseKeyAttemptLimit+1; attempt++ {
		response := activate(t, service, testLicenseKey, testInstallA, fmt.Sprintf("00000000-0000-4000-8000-%012d", attempt))
		if attempt <= licenseKeyAttemptLimit {
			assertErrorCode(t, response, http.StatusUnauthorized, "invalid_credentials")
			continue
		}
		assertErrorCode(t, response, http.StatusTooManyRequests, "rate_limited")
		if response.RetryAfterSeconds <= 0 || response.RetryAfterSeconds > int(rateLimitWindow.Seconds()) {
			t.Errorf("Retry-After = %d", response.RetryAfterSeconds)
		}
	}
}

func openTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	databaseURL := os.Getenv("GLASSEQ_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("GLASSEQ_TEST_DATABASE_URL is not set")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.PingContext(context.Background()); err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	return database
}

func resetActivationData(t *testing.T, database *sql.DB) {
	t.Helper()
	_, err := database.ExecContext(context.Background(), `
		TRUNCATE activation_rate_limits, idempotency_records, activations,
		         subscriptions, license_keys, licenses CASCADE`)
	if err != nil {
		t.Fatalf("reset activation data: %v", err)
	}
}

func seedPerpetualLicense(t *testing.T, database *sql.DB, licenseID, licenseKey string) {
	t.Helper()
	now := time.Now().UTC()
	credential, valid := normalizeLicenseKey(licenseKey)
	if !valid {
		t.Fatalf("test license key %q is invalid", licenseKey)
	}
	credentialHash := sha256.Sum256([]byte(credential))
	lookupHash := sha256.Sum256([]byte("test@example.com"))
	_, err := database.ExecContext(context.Background(), `
		INSERT INTO licenses (
		    id, plan, state, policy_version, recovery_email_ciphertext,
		    recovery_email_lookup, created_at, updated_at
		) VALUES ($1, 'perpetual_v1', 'active', 'v1', $2, $3, $4, $4)`,
		licenseID, []byte("encrypted"), lookupHash[:], now)
	if err != nil {
		t.Fatalf("seed perpetual license: %v", err)
	}
	_, err = database.ExecContext(context.Background(), `
		INSERT INTO license_keys (id, license_id, secret_hash, state, created_at)
		VALUES ($1, $2, $3, 'active', $4)`, "key_"+licenseID, licenseID, credentialHash[:], now)
	if err != nil {
		t.Fatalf("seed perpetual license key: %v", err)
	}
}

func newTestService(t *testing.T, database *sql.DB, issuer entitlementIssuer) *Service {
	t.Helper()
	service, err := NewService(database, issuer, make([]byte, 32), bytesOf(1, 32))
	if err != nil {
		t.Fatalf("create activation service: %v", err)
	}
	service.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	return service
}

func localIssuer(t *testing.T) *entitlement.Issuer {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytesOf(2, ed25519.SeedSize))
	issuer, err := entitlement.NewIssuer("test-key", localSigner{privateKey: privateKey})
	if err != nil {
		t.Fatalf("create local entitlement issuer: %v", err)
	}
	return issuer
}

type localSigner struct {
	privateKey ed25519.PrivateKey
}

func (s localSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, message), nil
}

type errorIssuer struct{}

func (errorIssuer) IssuePerpetual(context.Context, entitlement.Claims) (string, error) {
	return "", errors.New("signing unavailable")
}

func (errorIssuer) IssueMonthly(context.Context, entitlement.MonthlyClaims) (string, error) {
	return "", errors.New("signing unavailable")
}

func activate(t *testing.T, service *Service, licenseKey, installationID, idempotencyKey string) Response {
	t.Helper()
	response, err := service.Activate(context.Background(), activationInput(licenseKey, installationID, idempotencyKey))
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	return response
}

func activationInput(licenseKey, installationID, idempotencyKey string) Input {
	return Input{
		LicenseKey:     licenseKey,
		InstallationID: installationID,
		IdempotencyKey: idempotencyKey,
		ClientIP:       "192.0.2.42",
		RequestID:      "req_test",
	}
}

func decodeSuccess(t *testing.T, response Response) successBody {
	t.Helper()
	var body successBody
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("decode success response: %v", err)
	}
	return body
}

type entitlementClaims struct {
	Plan           string `json:"plan"`
	InstallationID string `json:"installation_id"`
	Revision       int64  `json:"revision"`
}

func decodeClaims(t *testing.T, compactJWS string) entitlementClaims {
	t.Helper()
	parts := strings.Split(compactJWS, ".")
	if len(parts) != 3 {
		t.Fatalf("entitlement has %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode entitlement payload: %v", err)
	}
	var claims entitlementClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode entitlement claims: %v", err)
	}
	return claims
}

func assertStoredResponseIsEncrypted(t *testing.T, database *sql.DB, activationToken string) {
	t.Helper()
	var ciphertext []byte
	if err := database.QueryRowContext(context.Background(), "SELECT response_ciphertext FROM idempotency_records LIMIT 1").Scan(&ciphertext); err != nil {
		t.Fatalf("read stored replay: %v", err)
	}
	if strings.Contains(string(ciphertext), activationToken) {
		t.Error("stored replay contains the plaintext activation token")
	}
}

func assertActivationCount(t *testing.T, database *sql.DB, licenseID string, want int) {
	t.Helper()
	var count int
	if err := database.QueryRowContext(context.Background(), "SELECT count(*) FROM activations WHERE license_id = $1", licenseID).Scan(&count); err != nil {
		t.Fatalf("count activations: %v", err)
	}
	if count != want {
		t.Errorf("activation count = %d, want %d", count, want)
	}
}

func assertErrorCode(t *testing.T, response Response, wantStatus int, wantCode string) {
	t.Helper()
	if response.Status != wantStatus {
		t.Fatalf("status = %d, want %d: %s", response.Status, wantStatus, response.Body)
	}
	var body errorEnvelope
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error.Code != wantCode {
		t.Errorf("error code = %q, want %q", body.Error.Code, wantCode)
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
