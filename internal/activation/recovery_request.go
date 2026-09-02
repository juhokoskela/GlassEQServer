package activation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/mail"
	"net/netip"
	"strings"
	"time"
)

const (
	recoveryRequestScope       = "recovery_request"
	recoveryTokenLifetime      = 30 * time.Minute
	recoveryQueueTimeout       = 10 * time.Second
	recoveryDispatchRetryDelay = time.Minute
	recoveryEmailAttemptLimit  = 3
	recoveryIPAttemptLimit     = 20
)

var recoveryAcceptedBody = []byte(`{"accepted":true}`)

type RecoveryRequestInput struct {
	Email          string
	IdempotencyKey string
	ClientIP       netip.Addr
}

type RecoveryEmail struct {
	Schema        int    `json:"schema"`
	DeliveryID    string `json:"delivery_id"`
	Email         string `json:"email"`
	RecoveryToken string `json:"recovery_token"`
	ExpiresAt     int64  `json:"expires_at"`
}

type RecoveryEmailQueue interface {
	SendRecoveryEmail(context.Context, RecoveryEmail) error
}

func (s *Service) RequestRecovery(ctx context.Context, input RecoveryRequestInput) (Response, error) {
	normalizedEmail, emailValid := normalizeRecoveryEmail(input.Email)
	if !input.ClientIP.IsValid() {
		return responseError(http.StatusBadRequest, "invalid_request", "The recovery request is invalid."), nil
	}
	idempotencyKey, valid := canonicalIdempotencyKey(input.IdempotencyKey)
	if !valid {
		return responseError(http.StatusBadRequest, "invalid_request", "The recovery request is invalid."), nil
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	credentialHash := hmacSHA256(s.rateLimitHMACKey, "recovery_request\x00"+normalizedEmail)
	idempotency := idempotencyRequest{
		scope:          recoveryRequestScope,
		credentialHash: credentialHash,
		key:            idempotencyKey,
		requestHash:    sha256.Sum256(nil),
	}
	replayed, replayFound, _, err := s.loadIdempotency(ctx, s.database, idempotency, now)
	if err != nil {
		return Response{}, err
	}
	if replayFound {
		return replayed, nil
	}

	limited, err := s.consumeRecoveryRateLimits(ctx, normalizedEmail, input.ClientIP.Unmap(), now)
	if err != nil {
		return Response{}, err
	}
	if limited {
		return recoveryAcceptedResponse(), nil
	}

	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Response{}, fmt.Errorf("begin recovery request: %w", err)
	}
	defer tx.Rollback()

	locked, err := tryLockCredential(ctx, tx, credentialHash)
	if err != nil {
		return Response{}, err
	}
	if !locked {
		return databaseBusyResponse(), nil
	}
	replayed, replayFound, _, err = s.loadIdempotency(ctx, tx, idempotency, now)
	if err != nil {
		return Response{}, err
	}
	if replayFound {
		return replayed, nil
	}

	var licenseIDs []string
	if emailValid {
		lookupHash := hmacSHA256(s.emailLookupHMACKey, normalizedEmail)
		licenseIDs, err = findRecoveryLicenses(ctx, tx, lookupHash)
		if err != nil {
			return Response{}, err
		}
	}
	for _, licenseID := range licenseIDs {
		if err := s.createRecoveryDelivery(ctx, tx, licenseID, now); err != nil {
			return Response{}, err
		}
	}
	return s.storeAndCommit(ctx, tx, idempotency, recoveryAcceptedResponse(), now)
}

func findRecoveryLicenses(ctx context.Context, tx *sql.Tx, lookupHash [sha256.Size]byte) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id
		FROM licenses
		WHERE recovery_email_lookup = $1 AND state = 'active'
		ORDER BY id`, lookupHash[:])
	if err != nil {
		return nil, fmt.Errorf("find licenses for recovery: %w", err)
	}
	defer rows.Close()
	var licenseIDs []string
	for rows.Next() {
		var licenseID string
		if err := rows.Scan(&licenseID); err != nil {
			return nil, fmt.Errorf("scan license for recovery: %w", err)
		}
		licenseIDs = append(licenseIDs, licenseID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("find licenses for recovery: %w", err)
	}
	return licenseIDs, nil
}

func (s *Service) createRecoveryDelivery(ctx context.Context, tx *sql.Tx, licenseID string, now time.Time) error {
	token, err := randomValue(s.random, recoveryTokenPrefix, 32)
	if err != nil {
		return fmt.Errorf("generate recovery token: %w", err)
	}
	deliveryID, err := randomValue(s.random, "red_", 16)
	if err != nil {
		return fmt.Errorf("generate recovery delivery ID: %w", err)
	}
	expiresAt := now.Add(recoveryTokenLifetime)
	tokenCiphertext, err := s.databaseValues.seal([]byte(token), recoveryTokenAdditionalData(deliveryID, licenseID, expiresAt))
	if err != nil {
		return fmt.Errorf("encrypt recovery token: %w", err)
	}
	tokenHash := sha256.Sum256([]byte(token))
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO access_tokens (token_hash, license_id, purpose, created_at, expires_at)
		VALUES ($1, $2, 'recovery', $3, $4)`, tokenHash[:], licenseID, now, expiresAt); err != nil {
		return fmt.Errorf("save recovery token: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO recovery_email_outbox (
		    id, license_id, token_ciphertext, created_at, expires_at, next_attempt_at
		) VALUES ($1, $2, $3, $4, $5, $4)`,
		deliveryID, licenseID, tokenCiphertext, now, expiresAt); err != nil {
		return fmt.Errorf("save recovery email: %w", err)
	}
	return nil
}

func (s *Service) consumeRecoveryRateLimits(ctx context.Context, normalizedEmail string, clientIP netip.Addr, now time.Time) (bool, error) {
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin recovery rate limit: %w", err)
	}
	defer tx.Rollback()

	windowStart := now.Truncate(rateLimitWindow)
	ipHash := hmacSHA256(s.rateLimitHMACKey, "recovery_ip\x00"+clientIP.String())
	ipAttempts, err := incrementRateLimit(ctx, tx, "recovery_ip", ipHash, windowStart)
	if err != nil {
		return false, err
	}
	limited := ipAttempts > recoveryIPAttemptLimit
	if !limited {
		emailHash := hmacSHA256(s.rateLimitHMACKey, "recovery_email\x00"+normalizedEmail)
		emailAttempts, err := incrementRateLimit(ctx, tx, "recovery_email", emailHash, windowStart)
		if err != nil {
			return false, err
		}
		limited = emailAttempts > recoveryEmailAttemptLimit
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit recovery rate limit: %w", err)
	}
	return limited, nil
}

func normalizeRecoveryEmail(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 254 {
		return strings.ToLower(value), false
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Name != "" || address.Address != value {
		return strings.ToLower(value), false
	}
	return strings.ToLower(value), true
}

func recoveryAcceptedResponse() Response {
	return Response{Status: http.StatusAccepted, Body: recoveryAcceptedBody}
}

func recoveryEmailAdditionalData(licenseID string) []byte {
	return []byte("recovery-email\x00" + licenseID)
}

func recoveryTokenAdditionalData(deliveryID, licenseID string, expiresAt time.Time) []byte {
	additionalData := make([]byte, 0, len(deliveryID)+len(licenseID)+32)
	additionalData = append(additionalData, "recovery-token\x00"...)
	additionalData = append(additionalData, deliveryID...)
	additionalData = append(additionalData, 0)
	additionalData = append(additionalData, licenseID...)
	additionalData = append(additionalData, 0)
	return binary.BigEndian.AppendUint64(additionalData, uint64(expiresAt.Unix()))
}
