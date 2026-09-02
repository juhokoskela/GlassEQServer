package activation

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

const testRecoveryEmail = "customer@example.com"

func TestNormalizeRecoveryEmail(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		want      string
		wantValid bool
	}{
		{name: "canonical", value: testRecoveryEmail, want: testRecoveryEmail, wantValid: true},
		{name: "case and surrounding space", value: " Customer@Example.COM ", want: testRecoveryEmail, wantValid: true},
		{name: "display name", value: "Customer <customer@example.com>", want: "customer <customer@example.com>"},
		{name: "missing domain", value: "customer", want: "customer"},
		{name: "empty", value: "  ", want: ""},
		{name: "too long", value: strings.Repeat("a", 255), want: strings.Repeat("a", 255)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, valid := normalizeRecoveryEmail(test.value)
			if got != test.want || valid != test.wantValid {
				t.Errorf("normalizeRecoveryEmail(%q) = (%q, %t), want (%q, %t)", test.value, got, valid, test.want, test.wantValid)
			}
		})
	}
}

func TestRecoveryRequestRejectsInvalidProtocolInput(t *testing.T) {
	tests := []RecoveryRequestInput{
		{Email: testRecoveryEmail, IdempotencyKey: testRecoveryIdempotencyKey(1)},
		{Email: testRecoveryEmail, IdempotencyKey: "not-a-uuid", ClientIP: netip.MustParseAddr("192.0.2.50")},
	}
	for _, input := range tests {
		response, err := (&Service{}).RequestRecovery(context.Background(), input)
		if err != nil {
			t.Fatalf("request recovery: %v", err)
		}
		assertErrorCode(t, response, http.StatusBadRequest, "invalid_request")
	}
}

func TestRecoveryRequestAndDispatchWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	queue := &recordingRecoveryEmailQueue{}
	service := newTestServiceWithRecoveryQueue(t, database, localIssuer(t), queue)
	seedRecoverableLicense(t, service, "lic_recovery_request", testLicenseKey, testRecoveryEmail)

	response, err := service.RequestRecovery(context.Background(), RecoveryRequestInput{
		Email:          " Customer@Example.COM ",
		IdempotencyKey: testRecoveryIdempotencyKey(1),
		ClientIP:       netip.MustParseAddr("192.0.2.50"),
	})
	if err != nil {
		t.Fatalf("request recovery: %v", err)
	}
	assertRecoveryAccepted(t, response)
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE purpose = 'recovery'", nil, 1)
	assertRowCount(t, database, "SELECT count(*) FROM recovery_email_outbox WHERE dispatched_at IS NULL", nil, 1)

	replay, err := service.RequestRecovery(context.Background(), RecoveryRequestInput{
		Email:          testRecoveryEmail,
		IdempotencyKey: testRecoveryIdempotencyKey(1),
		ClientIP:       netip.MustParseAddr("192.0.2.50"),
	})
	if err != nil {
		t.Fatalf("replay recovery request: %v", err)
	}
	if replay.Status != response.Status || string(replay.Body) != string(response.Body) {
		t.Errorf("replay = (%d, %s), want (%d, %s)", replay.Status, replay.Body, response.Status, response.Body)
	}
	assertRowCount(t, database, "SELECT count(*) FROM recovery_email_outbox", nil, 1)

	dispatched, err := service.DispatchRecoveryEmail(context.Background(), service.now())
	if err != nil {
		t.Fatalf("dispatch recovery email: %v", err)
	}
	if !dispatched {
		t.Fatal("recovery email was not dispatched")
	}
	messages := queue.snapshot()
	if len(messages) != 1 {
		t.Fatalf("queued messages = %d, want 1", len(messages))
	}
	message := messages[0]
	if message.Schema != 1 {
		t.Errorf("recovery message schema = %d, want 1", message.Schema)
	}
	if message.Email != testRecoveryEmail {
		t.Errorf("queued email = %q", message.Email)
	}
	if message.ExpiresAt != service.now().Add(recoveryTokenLifetime).Unix() {
		t.Errorf("recovery expiry = %d", message.ExpiresAt)
	}
	if _, valid := recoveryTokenHash(message.RecoveryToken); !valid {
		t.Errorf("queued recovery token is invalid: %q", message.RecoveryToken)
	}
	assertRecoveryTokenEncrypted(t, database, message.RecoveryToken)

	session, err := service.ExchangeRecoveryToken(context.Background(), RecoverySessionInput{
		RecoveryToken:  message.RecoveryToken,
		IdempotencyKey: "a1f1fd76-4ac4-4bf7-a154-4a179d1dabed",
	})
	if err != nil {
		t.Fatalf("exchange queued recovery token: %v", err)
	}
	if session.Status != http.StatusCreated {
		t.Errorf("recovery session status = %d, want %d", session.Status, http.StatusCreated)
	}

	dispatched, err = service.DispatchRecoveryEmail(context.Background(), service.now())
	if err != nil {
		t.Fatalf("dispatch empty outbox: %v", err)
	}
	if dispatched {
		t.Error("dispatched the same recovery email twice")
	}
}

func TestRecoveryRequestDoesNotRevealUnknownEmailWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestService(t, database, localIssuer(t))
	seedRecoverableLicense(t, service, "lic_recovery_private", testLicenseKey, testRecoveryEmail)

	known, err := service.RequestRecovery(context.Background(), RecoveryRequestInput{
		Email:          testRecoveryEmail,
		IdempotencyKey: testRecoveryIdempotencyKey(2),
		ClientIP:       netip.MustParseAddr("192.0.2.51"),
	})
	if err != nil {
		t.Fatalf("request recovery for known email: %v", err)
	}
	unknown, err := service.RequestRecovery(context.Background(), RecoveryRequestInput{
		Email:          "unknown@example.com",
		IdempotencyKey: testRecoveryIdempotencyKey(3),
		ClientIP:       netip.MustParseAddr("192.0.2.52"),
	})
	if err != nil {
		t.Fatalf("request recovery for unknown email: %v", err)
	}
	if unknown.Status != known.Status || string(unknown.Body) != string(known.Body) {
		t.Errorf("unknown response = (%d, %s), want (%d, %s)", unknown.Status, unknown.Body, known.Status, known.Body)
	}
	invalid, err := service.RequestRecovery(context.Background(), RecoveryRequestInput{
		Email:          "not-an-email",
		IdempotencyKey: testRecoveryIdempotencyKey(6),
		ClientIP:       netip.MustParseAddr("192.0.2.58"),
	})
	if err != nil {
		t.Fatalf("request recovery for invalid email: %v", err)
	}
	if invalid.Status != known.Status || string(invalid.Body) != string(known.Body) {
		t.Errorf("invalid response = (%d, %s), want (%d, %s)", invalid.Status, invalid.Body, known.Status, known.Body)
	}
	assertRowCount(t, database, "SELECT count(*) FROM recovery_email_outbox", nil, 1)
}

func TestRecoveryRequestRateLimitsEmailAndIPWithoutChangingResponseWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestService(t, database, localIssuer(t))
	seedRecoverableLicense(t, service, "lic_recovery_limited", testLicenseKey, testRecoveryEmail)

	for attempt := range recoveryEmailAttemptLimit + 1 {
		response, err := service.RequestRecovery(context.Background(), RecoveryRequestInput{
			Email:          testRecoveryEmail,
			IdempotencyKey: testRecoveryIdempotencyKey(10 + attempt),
			ClientIP:       netip.MustParseAddr("192.0.2.53"),
		})
		if err != nil {
			t.Fatalf("request email-limited recovery: %v", err)
		}
		assertRecoveryAccepted(t, response)
	}
	assertRowCount(t, database, "SELECT count(*) FROM recovery_email_outbox", nil, recoveryEmailAttemptLimit)

	clientIP := netip.MustParseAddr("192.0.2.54")
	for attempt := range recoveryIPAttemptLimit + 1 {
		response, err := service.RequestRecovery(context.Background(), RecoveryRequestInput{
			Email:          fmt.Sprintf("unknown-%d@example.com", attempt),
			IdempotencyKey: testRecoveryIdempotencyKey(20 + attempt),
			ClientIP:       clientIP,
		})
		if err != nil {
			t.Fatalf("request IP-limited recovery %d: %v", attempt, err)
		}
		assertRecoveryAccepted(t, response)
	}
	assertRowCount(t, database, "SELECT count(*) FROM activation_rate_limits WHERE kind = 'recovery_email'", nil, recoveryIPAttemptLimit+1)
	assertRowCount(t, database, "SELECT count(*) FROM idempotency_records WHERE scope = 'recovery_request'", nil, recoveryEmailAttemptLimit+recoveryIPAttemptLimit)
}

func TestRecoveryRequestRollsBackWhenReplayEncryptionFailsWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestService(t, database, localIssuer(t))
	seedRecoverableLicense(t, service, "lic_recovery_rollback_request", testLicenseKey, testRecoveryEmail)
	service.responses.random = bytes.NewReader(nil)

	_, err := service.RequestRecovery(context.Background(), RecoveryRequestInput{
		Email:          testRecoveryEmail,
		IdempotencyKey: testRecoveryIdempotencyKey(4),
		ClientIP:       netip.MustParseAddr("192.0.2.55"),
	})
	if err == nil {
		t.Fatal("recovery request with failed replay encryption succeeded")
	}
	assertRowCount(t, database, "SELECT count(*) FROM access_tokens WHERE purpose = 'recovery'", nil, 0)
	assertRowCount(t, database, "SELECT count(*) FROM recovery_email_outbox", nil, 0)
}

func TestRecoveryEmailDispatchRetriesAfterQueueFailureWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	queue := &recordingRecoveryEmailQueue{err: errors.New("queue unavailable")}
	service := newTestServiceWithRecoveryQueue(t, database, localIssuer(t), queue)
	seedRecoverableLicense(t, service, "lic_recovery_retry", testLicenseKey, testRecoveryEmail)
	requestRecovery(t, service, testRecoveryEmail, "192.0.2.56")
	now := service.now()

	if _, err := service.DispatchRecoveryEmail(context.Background(), now); err == nil {
		t.Fatal("dispatch with unavailable queue succeeded")
	}
	if dispatched, err := service.DispatchRecoveryEmail(context.Background(), now.Add(30*time.Second)); err != nil {
		t.Fatalf("dispatch before retry time: %v", err)
	} else if dispatched {
		t.Error("recovery email retried before its delay")
	}
	queue.setError(nil)
	if dispatched, err := service.DispatchRecoveryEmail(context.Background(), now.Add(recoveryDispatchRetryDelay)); err != nil {
		t.Fatalf("retry recovery email: %v", err)
	} else if !dispatched {
		t.Error("recovery email was not retried")
	}
	if len(queue.snapshot()) != 2 {
		t.Errorf("queue attempts = %d, want 2", len(queue.snapshot()))
	}
}

func TestConcurrentRecoveryDispatchClaimsOneEmailWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	queue := &recordingRecoveryEmailQueue{}
	service := newTestServiceWithRecoveryQueue(t, database, localIssuer(t), queue)
	seedRecoverableLicense(t, service, "lic_recovery_claim", testLicenseKey, testRecoveryEmail)
	requestRecovery(t, service, testRecoveryEmail, "192.0.2.57")

	type result struct {
		dispatched bool
		err        error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			dispatched, err := service.DispatchRecoveryEmail(context.Background(), service.now())
			results <- result{dispatched: dispatched, err: err}
		}()
	}
	close(start)

	dispatched := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("dispatch recovery email concurrently: %v", result.err)
		}
		if result.dispatched {
			dispatched++
		}
	}
	if dispatched != 1 {
		t.Errorf("successful dispatches = %d, want 1", dispatched)
	}
	if len(queue.snapshot()) != 1 {
		t.Errorf("queued messages = %d, want 1", len(queue.snapshot()))
	}
}

func seedRecoverableLicense(t *testing.T, service *Service, licenseID, licenseKey, email string) {
	t.Helper()
	seedPerpetualLicense(t, service.database, licenseID, licenseKey)
	normalizedEmail, valid := normalizeRecoveryEmail(email)
	if !valid {
		t.Fatalf("test recovery email %q is invalid", email)
	}
	emailCiphertext, err := service.databaseValues.seal([]byte(normalizedEmail), recoveryEmailAdditionalData(licenseID))
	if err != nil {
		t.Fatalf("encrypt test recovery email: %v", err)
	}
	lookupHash := hmacSHA256(service.emailLookupHMACKey, normalizedEmail)
	if _, err := service.database.ExecContext(context.Background(), `
		UPDATE licenses
		SET recovery_email_ciphertext = $1, recovery_email_lookup = $2
		WHERE id = $3`, emailCiphertext, lookupHash[:], licenseID); err != nil {
		t.Fatalf("update test recovery email: %v", err)
	}
}

func requestRecovery(t *testing.T, service *Service, email, clientIP string) {
	t.Helper()
	response, err := service.RequestRecovery(context.Background(), RecoveryRequestInput{
		Email:          email,
		IdempotencyKey: testRecoveryIdempotencyKey(5),
		ClientIP:       netip.MustParseAddr(clientIP),
	})
	if err != nil {
		t.Fatalf("request recovery: %v", err)
	}
	assertRecoveryAccepted(t, response)
}

func testRecoveryIdempotencyKey(value int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", value)
}

func assertRecoveryAccepted(t *testing.T, response Response) {
	t.Helper()
	if response.Status != http.StatusAccepted || string(response.Body) != string(recoveryAcceptedBody) {
		t.Errorf("recovery response = (%d, %s), want (%d, %s)", response.Status, response.Body, http.StatusAccepted, recoveryAcceptedBody)
	}
}

func assertRecoveryTokenEncrypted(t *testing.T, database *sql.DB, token string) {
	t.Helper()
	var ciphertext []byte
	if err := database.QueryRowContext(context.Background(), `
		SELECT token_ciphertext
		FROM recovery_email_outbox`).Scan(&ciphertext); err != nil {
		t.Fatalf("read encrypted recovery token: %v", err)
	}
	if strings.Contains(string(ciphertext), token) {
		t.Error("recovery outbox contains the plaintext token")
	}
}

type recordingRecoveryEmailQueue struct {
	mu       sync.Mutex
	messages []RecoveryEmail
	err      error
}

func (q *recordingRecoveryEmailQueue) SendRecoveryEmail(_ context.Context, message RecoveryEmail) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.messages = append(q.messages, message)
	return q.err
}

func (q *recordingRecoveryEmailQueue) snapshot() []RecoveryEmail {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]RecoveryEmail(nil), q.messages...)
}

func (q *recordingRecoveryEmailQueue) setError(err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.err = err
}
