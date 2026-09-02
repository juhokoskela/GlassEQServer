package activation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	licenseKeyRotationScope = "license_key_rotation"
	licenseKeyPrefix        = "GEQ1"
	licenseKeyByteCount     = 16
)

var licenseKeyEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

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
	replayed, found, _, err := s.loadIdempotency(ctx, s.database, idempotency, now)
	if err != nil {
		return Response{}, err
	}
	if found {
		return replayed, nil
	}

	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Response{}, fmt.Errorf("begin license-key rotation: %w", err)
	}
	defer tx.Rollback()

	licenseID, found, err := lockManagementLicense(ctx, tx, tokenHash, now)
	if databaseLockUnavailable(err) {
		response := responseError(http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.")
		response.RetryAfterSeconds = 1
		return response, nil
	}
	if err != nil {
		return Response{}, err
	}
	if !found {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The management token is invalid."), nil
	}
	replayed, found, _, err = s.loadIdempotency(ctx, tx, idempotency, now)
	if err != nil {
		return Response{}, err
	}
	if found {
		return replayed, nil
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

	result, err := tx.ExecContext(ctx, `
		UPDATE license_keys
		SET state = 'revoked', revoked_at = $1
		WHERE license_id = $2 AND state = 'active'`, now, licenseID)
	if err != nil {
		return Response{}, fmt.Errorf("revoke current license key: %w", err)
	}
	revoked, err := result.RowsAffected()
	if err != nil {
		return Response{}, fmt.Errorf("read revoked license-key count: %w", err)
	}
	if revoked != 1 {
		return Response{}, fmt.Errorf("license %q has %d active license keys", licenseID, revoked)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO license_keys (id, license_id, secret_hash, state, created_at)
		VALUES ($1, $2, $3, 'active', $4)`, keyID, licenseID, keyHash[:], now)
	if err != nil {
		return Response{}, fmt.Errorf("save rotated license key: %w", err)
	}

	body, err := json.Marshal(licenseKeyRotationBody{LicenseKey: licenseKey})
	if err != nil {
		return Response{}, fmt.Errorf("encode license-key rotation response: %w", err)
	}
	return s.storeAndCommit(ctx, tx, idempotency, Response{Status: http.StatusCreated, Body: body}, now)
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

func databaseLockUnavailable(err error) bool {
	var databaseError interface{ SQLState() string }
	return errors.As(err, &databaseError) && databaseError.SQLState() == "55P03"
}

func generateLicenseKey(random io.Reader) (string, string, error) {
	value := make([]byte, licenseKeyByteCount)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", "", err
	}
	encoded := licenseKeyEncoding.EncodeToString(value)
	display := licenseKeyPrefix + "-" + encoded[:5] + "-" + encoded[5:10] + "-" + encoded[10:15] + "-" + encoded[15:20] + "-" + encoded[20:25] + "-" + encoded[25:]
	return display, licenseKeyPrefix + encoded, nil
}

type licenseKeyRotationBody struct {
	LicenseKey string `json:"license_key"`
}
