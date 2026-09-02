package activation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/juhokoskela/GlassEQServer/internal/entitlement"
)

const (
	testLicenseKey  = "GEQ1-01234-56789-ABCDE-FGHJK-MNPQR-S"
	testLicenseKeyB = "GEQ1-01234-56789-ABCDE-FGHJK-MNPQR-T"
	testInstallA    = "4E70638A-A75B-4BFB-B4B0-15E959A91465"
	testInstallB    = "9184CDB7-1EB1-43E5-97F3-EC269111171F"
	testInstallC    = "D45AB9E0-606C-4873-A285-14F3339D026D"
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
	service.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC().Add(idempotencyLifetime + time.Hour) }
	afterExpiry := activate(t, service, testLicenseKey, testInstallA, "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23")
	if afterExpiry.Status != http.StatusOK {
		t.Fatalf("status after replay expiry = %d, want %d: %s", afterExpiry.Status, http.StatusOK, afterExpiry.Body)
	}
	afterExpiryBody := decodeSuccess(t, afterExpiry)
	if afterExpiryBody.ActivationToken == firstBody.ActivationToken {
		t.Error("expired replay returned the original activation token")
	}
	if claims := decodeClaims(t, afterExpiryBody.Entitlement); claims.Revision != 3 {
		t.Errorf("revision after replay expiry = %d, want 3", claims.Revision)
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

func TestActivationReturnsWhenCredentialIsBusyWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_busy", testLicenseKey)
	service := newTestService(t, database, localIssuer(t))
	input := activationInput(testLicenseKey, testInstallA, "5992d0c4-d8d3-4fc3-a4d2-520f3278c71a")
	prepared, invalidCode := prepare(input)
	if invalidCode != "" {
		t.Fatalf("prepare test input: %s", invalidCode)
	}

	lock, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin lock transaction: %v", err)
	}
	t.Cleanup(func() { lock.Rollback() })
	lockKey := int64(binary.BigEndian.Uint64(prepared.credentialHash[:8]))
	if _, err := lock.ExecContext(context.Background(), "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		t.Fatalf("hold credential lock: %v", err)
	}

	response := activate(t, service, testLicenseKey, testInstallA, input.IdempotencyKey)
	assertErrorCode(t, response, http.StatusServiceUnavailable, "temporarily_unavailable")
	if response.RetryAfterSeconds != 1 {
		t.Errorf("Retry-After = %d, want 1", response.RetryAfterSeconds)
	}
}

func TestSharedIPDoesNotHoldRateLimitLockDuringSigningWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	seedPerpetualLicense(t, database, "lic_nat_a", testLicenseKey)
	seedPerpetualLicense(t, database, "lic_nat_b", testLicenseKeyB)
	issuer := &blockingIssuer{entered: make(chan struct{}, 2), release: make(chan struct{})}
	service := newTestService(t, database, issuer)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	results := make(chan error, 2)

	go func() {
		_, err := service.Activate(ctx, activationInput(testLicenseKey, testInstallA, "29687cd6-607e-4bb2-aa8a-75ab69e164bd"))
		results <- err
	}()
	select {
	case <-issuer.entered:
	case err := <-results:
		t.Fatalf("first activation returned before signing: %v", err)
	case <-ctx.Done():
		t.Fatal("first activation did not reach signing")
	}

	go func() {
		_, err := service.Activate(ctx, activationInput(testLicenseKeyB, testInstallB, "0485aa72-a17d-48f7-afbe-8abdd89c19b8"))
		results <- err
	}()
	secondReachedSigning := false
	select {
	case <-issuer.entered:
		secondReachedSigning = true
	case <-time.After(time.Second):
	}
	close(issuer.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Errorf("activation failed: %v", err)
		}
	}
	if !secondReachedSigning {
		t.Error("second activation remained blocked on the shared IP rate-limit row")
	}
}

func TestActivationRateLimitWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestService(t, database, localIssuer(t))

	var limitedIdempotencyKey string
	for attempt := 1; attempt <= licenseKeyAttemptLimit+1; attempt++ {
		limitedIdempotencyKey = fmt.Sprintf("00000000-0000-4000-8000-%012d", attempt)
		response := activate(t, service, testLicenseKey, testInstallA, limitedIdempotencyKey)
		if attempt <= licenseKeyAttemptLimit {
			assertErrorCode(t, response, http.StatusUnauthorized, "invalid_credentials")
			continue
		}
		assertErrorCode(t, response, http.StatusTooManyRequests, "rate_limited")
		if response.RetryAfterSeconds <= 0 || response.RetryAfterSeconds > int(rateLimitWindow.Seconds()) {
			t.Errorf("Retry-After = %d", response.RetryAfterSeconds)
		}
	}
	service.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC().Add(rateLimitWindow) }
	recovered := activate(t, service, testLicenseKey, testInstallA, limitedIdempotencyKey)
	assertErrorCode(t, recovered, http.StatusUnauthorized, "invalid_credentials")
	assertRowCount(t, database, "SELECT count(*) FROM idempotency_records", nil, 0)
}

func TestIPRateLimitStopsCreatingCredentialRowsWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestService(t, database, localIssuer(t))

	for attempt := 1; attempt <= ipAttemptLimit+10; attempt++ {
		licenseKey := fmt.Sprintf("invalid-license-%d", attempt)
		idempotencyKey := fmt.Sprintf("00000000-0000-4000-8001-%012d", attempt)
		response := activate(t, service, licenseKey, testInstallA, idempotencyKey)
		if attempt <= ipAttemptLimit {
			assertErrorCode(t, response, http.StatusUnauthorized, "invalid_credentials")
			continue
		}
		assertErrorCode(t, response, http.StatusTooManyRequests, "rate_limited")
	}

	assertRowCount(t, database, "SELECT count(*) FROM activation_rate_limits WHERE kind = 'ip'", nil, 1)
	assertRowCount(t, database, "SELECT count(*) FROM activation_rate_limits WHERE kind = 'license_key'", nil, ipAttemptLimit)
}

func TestActivationCleanupIsBoundedWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestService(t, database, localIssuer(t))
	now := time.Unix(1_800_000_000, 0).UTC()

	for index, expiresAt := range []time.Time{now.Add(-2 * time.Hour), now.Add(-time.Hour), now.Add(24 * time.Hour)} {
		credentialHash := sha256.Sum256([]byte(fmt.Sprintf("credential-%d", index)))
		requestHash := sha256.Sum256([]byte(fmt.Sprintf("request-%d", index)))
		_, err := database.ExecContext(context.Background(), `
			INSERT INTO idempotency_records (
			    scope, credential_hash, idempotency_key, request_hash, status_code,
			    response_ciphertext, created_at, expires_at
			) VALUES ('activation', $1, $2, $3, 201, $4, $5, $6)`,
			credentialHash[:], fmt.Sprintf("00000000-0000-4000-8000-%012d", index+1), requestHash[:],
			[]byte("ciphertext"), expiresAt.Add(-24*time.Hour), expiresAt)
		if err != nil {
			t.Fatalf("insert idempotency record %d: %v", index, err)
		}

		subjectHash := sha256.Sum256([]byte(fmt.Sprintf("subject-%d", index)))
		windowStart := now.Truncate(rateLimitWindow)
		if index < 2 {
			windowStart = windowStart.Add(-time.Duration(index+1) * rateLimitWindow)
		}
		_, err = database.ExecContext(context.Background(), `
			INSERT INTO activation_rate_limits (kind, subject_hash, window_start, attempts)
			VALUES ('ip', $1, $2, 1)`, subjectHash[:], windowStart)
		if err != nil {
			t.Fatalf("insert rate limit %d: %v", index, err)
		}
	}

	deleted, err := service.cleanupExpired(context.Background(), now, 1)
	if err != nil {
		t.Fatalf("clean one batch: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted rows = %d, want 2", deleted)
	}
	assertRowCount(t, database, "SELECT count(*) FROM idempotency_records WHERE expires_at <= $1", now, 1)
	assertRowCount(t, database, "SELECT count(*) FROM activation_rate_limits WHERE window_start < $1", now.Truncate(rateLimitWindow), 1)

	deleted, err = service.CleanupExpired(context.Background(), now)
	if err != nil {
		t.Fatalf("clean remaining rows: %v", err)
	}
	if deleted != 2 {
		t.Errorf("remaining deleted rows = %d, want 2", deleted)
	}
	assertRowCount(t, database, "SELECT count(*) FROM idempotency_records", nil, 1)
	assertRowCount(t, database, "SELECT count(*) FROM activation_rate_limits", nil, 1)
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

type blockingIssuer struct {
	entered chan struct{}
	release chan struct{}
}

func (i *blockingIssuer) IssuePerpetual(ctx context.Context, _ entitlement.Claims) (string, error) {
	i.entered <- struct{}{}
	select {
	case <-i.release:
		return "signed", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (i *blockingIssuer) IssueMonthly(ctx context.Context, _ entitlement.MonthlyClaims) (string, error) {
	return i.IssuePerpetual(ctx, entitlement.Claims{})
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
		ClientIP:       netip.MustParseAddr("192.0.2.42"),
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

func assertRowCount(t *testing.T, database *sql.DB, query string, argument any, want int) {
	t.Helper()
	var row *sql.Row
	if argument == nil {
		row = database.QueryRowContext(context.Background(), query)
	} else {
		row = database.QueryRowContext(context.Background(), query, argument)
	}
	var count int
	if err := row.Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != want {
		t.Errorf("row count = %d, want %d", count, want)
	}
}

func assertErrorCode(t *testing.T, response Response, wantStatus int, wantCode string) {
	t.Helper()
	if response.Status != wantStatus {
		t.Fatalf("status = %d, want %d: %s", response.Status, wantStatus, response.Body)
	}
	if response.ErrorCode != wantCode {
		t.Errorf("error code = %q, want %q", response.ErrorCode, wantCode)
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
