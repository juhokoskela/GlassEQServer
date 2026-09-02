package activation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"
)

const (
	licenseKeyRotationScope    = "license_key_rotation"
	licenseKeyRotationCooldown = 24 * time.Hour
)

type LicenseKeyRotationInput struct {
	ManagementToken string
	IdempotencyKey  string
}

func (s *Service) RotateLicenseKey(ctx context.Context, input LicenseKeyRotationInput) (Response, error) {
	tokenHash, valid := managementTokenHash(input.ManagementToken)
	if !valid {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The management token is invalid."), nil
	}
	idempotencyKey, valid := canonicalIdempotencyKey(input.IdempotencyKey)
	if !valid {
		return responseError(http.StatusBadRequest, "invalid_request", "The license-key rotation request is invalid."), nil
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	idempotency := idempotencyRequest{
		scope:          licenseKeyRotationScope,
		credentialHash: tokenHash,
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
		return Response{}, fmt.Errorf("begin license-key rotation: %w", err)
	}
	defer tx.Rollback()

	licenseID, sessionFound, err := lockManagementLicense(ctx, tx, tokenHash, now)
	if databaseLockUnavailable(err) {
		return databaseBusyResponse(), nil
	}
	if err != nil {
		return Response{}, err
	}
	if !sessionFound {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The management token is invalid."), nil
	}
	replayed, replayFound, _, err = s.loadIdempotency(ctx, tx, idempotency, now)
	if err != nil {
		return Response{}, err
	}
	if replayFound {
		return replayed, nil
	}
	retryAfter, err := licenseKeyRotationRetryAfter(ctx, tx, licenseID, now)
	if err != nil {
		return Response{}, err
	}
	if retryAfter > 0 {
		response := responseError(http.StatusTooManyRequests, "rate_limited", "The license key was rotated recently. Try again later.")
		response.RetryAfterSeconds = retryAfter
		return response, nil
	}

	licenseKey, normalizedKey, err := generateLicenseKey(s.random)
	if err != nil {
		return Response{}, fmt.Errorf("generate license key: %w", err)
	}
	keyHash := sha256.Sum256([]byte(normalizedKey))
	keyID, err := randomValue(s.random, "key_", 16)
	if err != nil {
		return Response{}, fmt.Errorf("generate license-key ID: %w", err)
	}

	var revokedKeyID string
	err = tx.QueryRowContext(ctx, `
		UPDATE license_keys
		SET state = 'revoked', revoked_at = $1
		WHERE license_id = $2 AND state = 'active'
		RETURNING id`, now, licenseID).Scan(&revokedKeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return Response{}, fmt.Errorf("license %q has no active license key", licenseID)
	}
	if err != nil {
		return Response{}, fmt.Errorf("revoke current license key: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO license_keys (id, license_id, secret_hash, state, created_at)
		VALUES ($1, $2, $3, 'active', $4)`, keyID, licenseID, keyHash[:], now)
	if err != nil {
		return Response{}, fmt.Errorf("save rotated license key: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM license_keys
		WHERE license_id = $1 AND state = 'revoked' AND id <> $2`, licenseID, revokedKeyID); err != nil {
		return Response{}, fmt.Errorf("delete older revoked license keys: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		DELETE FROM access_tokens
		WHERE token_hash = $1 AND purpose = 'management'`, tokenHash[:])
	if err != nil {
		return Response{}, fmt.Errorf("consume management session: %w", err)
	}
	consumed, err := result.RowsAffected()
	if err != nil {
		return Response{}, fmt.Errorf("read consumed management-session count: %w", err)
	}
	if consumed != 1 {
		return Response{}, errors.New("management session disappeared during license-key rotation")
	}

	body, err := json.Marshal(licenseKeyRotationBody{LicenseKey: licenseKey})
	if err != nil {
		return Response{}, fmt.Errorf("encode license-key rotation response: %w", err)
	}
	return s.storeAndCommit(ctx, tx, idempotency, Response{Status: http.StatusCreated, Body: body}, now)
}

func licenseKeyRotationRetryAfter(ctx context.Context, tx *sql.Tx, licenseID string, now time.Time) (int, error) {
	var lastRotation sql.NullTime
	if err := tx.QueryRowContext(ctx, `
		SELECT max(revoked_at)
		FROM license_keys
		WHERE license_id = $1 AND state = 'revoked'`, licenseID).Scan(&lastRotation); err != nil {
		return 0, fmt.Errorf("find latest license-key rotation: %w", err)
	}
	if !lastRotation.Valid || !now.Before(lastRotation.Time.Add(licenseKeyRotationCooldown)) {
		return 0, nil
	}
	return max(int(math.Ceil(lastRotation.Time.Add(licenseKeyRotationCooldown).Sub(now).Seconds())), 1), nil
}

func lockManagementLicense(ctx context.Context, tx *sql.Tx, tokenHash [sha256.Size]byte, now time.Time) (string, bool, error) {
	var licenseID string
	err := tx.QueryRowContext(ctx, `
		SELECT token.license_id
		FROM access_tokens AS token
		JOIN licenses AS license ON license.id = token.license_id
		WHERE token.token_hash = $1 AND token.purpose = 'management' AND token.expires_at > $2
		FOR NO KEY UPDATE OF license NOWAIT`, tokenHash[:], now).Scan(&licenseID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("lock license for key rotation: %w", err)
	}
	return licenseID, true, nil
}

type licenseKeyRotationBody struct {
	LicenseKey string `json:"license_key"`
}
