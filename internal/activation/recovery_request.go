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
	recoveryRequestScope      = "recovery_request"
	recoveryRequestLifetime   = 30 * time.Minute
	recoveryTokenLifetime     = 30 * time.Minute
	recoveryEmailAttemptLimit = 3
	recoveryIPAttemptLimit    = 20
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
	normalizedEmail, _ := normalizeRecoveryEmail(input.Email)
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

	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Response{}, fmt.Errorf("begin recovery request: %w", err)
	}
	defer tx.Rollback()

	if err := lockRecoveryCredential(ctx, tx, credentialHash); err != nil {
		return Response{}, err
	}
	replayed, replayFound, _, err = s.loadIdempotency(ctx, tx, idempotency, now)
	if err != nil {
		return Response{}, err
	}
	if replayFound {
		return replayed, nil
	}
	limited, err := s.recoveryRateLimited(ctx, tx, normalizedEmail, input.ClientIP.Unmap(), now)
	if err != nil {
		return Response{}, err
	}

	if !limited {
		if err := s.enqueueRecoveryRequest(ctx, tx, normalizedEmail, now); err != nil {
			return Response{}, err
		}
	}
	return s.storeAndCommit(ctx, tx, idempotency, recoveryAcceptedResponse(), now)
}

func (s *Service) enqueueRecoveryRequest(ctx context.Context, tx *sql.Tx, normalizedEmail string, now time.Time) error {
	requestID, err := randomValue(s.random, "rrq_", 16)
	if err != nil {
		return fmt.Errorf("generate recovery request ID: %w", err)
	}
	lookupHash := hmacSHA256(s.emailLookupHMACKey, normalizedEmail)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO recovery_request_jobs (id, email_lookup, created_at, expires_at)
		VALUES ($1, $2, $3, $4)`,
		requestID, lookupHash[:], now, now.Add(recoveryRequestLifetime)); err != nil {
		return fmt.Errorf("save recovery request: %w", err)
	}
	return nil
}

func (s *Service) recoveryRateLimited(ctx context.Context, tx *sql.Tx, normalizedEmail string, clientIP netip.Addr, now time.Time) (bool, error) {
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
	return limited, nil
}

func lockRecoveryCredential(ctx context.Context, tx *sql.Tx, credentialHash [sha256.Size]byte) error {
	key := int64(binary.BigEndian.Uint64(credentialHash[:8]))
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", key); err != nil {
		return fmt.Errorf("lock recovery credential: %w", err)
	}
	return nil
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
