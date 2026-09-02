package activation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

const (
	managementTokenPrefix   = "gem_"
	managementTokenLifetime = 15 * time.Minute
)

type ManagementSessionInput struct {
	LicenseKey string
	ClientIP   netip.Addr
}

type ManagedDeactivationInput struct {
	ManagementToken string
	ActivationID    string
}

func (s *Service) CreateManagementSession(ctx context.Context, input ManagementSessionInput) (Response, error) {
	normalizedKey, credentialValid := normalizeLicenseKey(input.LicenseKey)
	credentialHash := sha256.Sum256([]byte(normalizedKey))
	if !input.ClientIP.IsValid() {
		return responseError(http.StatusBadRequest, "invalid_request", "The management session request is invalid."), nil
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	retryAfter, err := s.consumeRateLimits(ctx, credentialHash, input.ClientIP.Unmap(), now)
	if err != nil {
		return Response{}, err
	}
	if retryAfter > 0 {
		response := responseError(http.StatusTooManyRequests, "rate_limited", "Too many management session attempts. Try again later.")
		response.RetryAfterSeconds = retryAfter
		return response, nil
	}
	if !credentialValid {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The license key is invalid."), nil
	}

	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Response{}, fmt.Errorf("begin management session: %w", err)
	}
	defer tx.Rollback()

	locked, err := tryLockCredential(ctx, tx, credentialHash)
	if err != nil {
		return Response{}, err
	}
	if !locked {
		response := responseError(http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.")
		response.RetryAfterSeconds = 1
		return response, nil
	}
	license, found, err := findLicense(ctx, tx, credentialHash)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The license key is invalid."), nil
	}

	token, err := randomValue(s.random, managementTokenPrefix, 32)
	if err != nil {
		return Response{}, fmt.Errorf("generate management token: %w", err)
	}
	tokenHash := sha256.Sum256([]byte(token))
	expiresAt := now.Add(managementTokenLifetime)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO access_tokens (token_hash, license_id, purpose, created_at, expires_at)
		VALUES ($1, $2, 'management', $3, $4)`, tokenHash[:], license.id, now, expiresAt); err != nil {
		return Response{}, fmt.Errorf("save management session: %w", err)
	}
	body, err := json.Marshal(managementSessionBody{ManagementToken: token, ExpiresAt: expiresAt.Unix()})
	if err != nil {
		return Response{}, fmt.Errorf("encode management session response: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Response{}, fmt.Errorf("commit management session: %w", err)
	}
	return Response{Status: http.StatusCreated, Body: body}, nil
}

func (s *Service) ListManagedActivations(ctx context.Context, managementToken string) (Response, error) {
	tokenHash, valid := managementTokenHash(managementToken)
	if !valid {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The management token is invalid."), nil
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	licenseID, found, err := findManagementLicenseID(ctx, s.database, tokenHash, now)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The management token is invalid."), nil
	}

	rows, err := s.database.QueryContext(ctx, `
		SELECT id, activated_at, last_refreshed_at
		FROM activations
		WHERE license_id = $1 AND state = 'active'
		ORDER BY activated_at, id`, licenseID)
	if err != nil {
		return Response{}, fmt.Errorf("list managed activations: %w", err)
	}
	defer rows.Close()

	activations := make([]managedActivation, 0, maximumActivations)
	for rows.Next() {
		var id string
		var activatedAt, lastRefreshedAt time.Time
		if err := rows.Scan(&id, &activatedAt, &lastRefreshedAt); err != nil {
			return Response{}, fmt.Errorf("scan managed activation: %w", err)
		}
		activations = append(activations, managedActivation{
			ID:              id,
			ActivatedAt:     activatedAt.Unix(),
			LastRefreshedAt: lastRefreshedAt.Unix(),
		})
	}
	if err := rows.Err(); err != nil {
		return Response{}, fmt.Errorf("list managed activations: %w", err)
	}
	body, err := json.Marshal(managedActivationsBody{Activations: activations})
	if err != nil {
		return Response{}, fmt.Errorf("encode managed activations response: %w", err)
	}
	return Response{Status: http.StatusOK, Body: body}, nil
}

func (s *Service) DeactivateManaged(ctx context.Context, input ManagedDeactivationInput) (Response, error) {
	tokenHash, valid := managementTokenHash(input.ManagementToken)
	if !valid {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The management token is invalid."), nil
	}
	if !activationIDValid(input.ActivationID) {
		return responseError(http.StatusBadRequest, "invalid_request", "The managed deactivation request is invalid."), nil
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Response{}, fmt.Errorf("begin managed deactivation: %w", err)
	}
	defer tx.Rollback()

	locked, err := tryLockCredential(ctx, tx, tokenHash)
	if err != nil {
		return Response{}, err
	}
	if !locked {
		response := responseError(http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.")
		response.RetryAfterSeconds = 1
		return response, nil
	}
	licenseID, found, err := findManagementLicenseID(ctx, tx, tokenHash, now)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The management token is invalid."), nil
	}
	// Activation mutations lock the license before the activation row.
	if _, found, err := findLicenseByID(ctx, tx, licenseID); err != nil {
		return Response{}, err
	} else if !found {
		return Response{}, errors.New("management session license does not exist")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE activations
		SET state = 'deactivated', deactivated_at = COALESCE(deactivated_at, $1)
		WHERE id = $2 AND license_id = $3`, now, input.ActivationID, licenseID); err != nil {
		return Response{}, fmt.Errorf("deactivate managed activation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Response{}, fmt.Errorf("commit managed deactivation: %w", err)
	}
	return Response{Status: http.StatusNoContent}, nil
}

func managementTokenHash(value string) ([sha256.Size]byte, bool) {
	return randomValueHash(value, managementTokenPrefix, 32)
}

func activationIDValid(value string) bool {
	return randomValueValid(value, "act_", 16)
}

func findManagementLicenseID(ctx context.Context, database rowQuerier, tokenHash [sha256.Size]byte, now time.Time) (string, bool, error) {
	var licenseID string
	err := database.QueryRowContext(ctx, `
		SELECT license_id
		FROM access_tokens
		WHERE token_hash = $1 AND purpose = 'management' AND expires_at > $2`, tokenHash[:], now).Scan(&licenseID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("find management session: %w", err)
	}
	return licenseID, true, nil
}

type managementSessionBody struct {
	ManagementToken string `json:"management_token"`
	ExpiresAt       int64  `json:"expires_at"`
}

type managedActivationsBody struct {
	Activations []managedActivation `json:"activations"`
}

type managedActivation struct {
	ID              string `json:"id"`
	ActivatedAt     int64  `json:"activated_at"`
	LastRefreshedAt int64  `json:"last_refreshed_at"`
}
