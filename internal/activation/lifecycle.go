package activation

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/entitlement"
)

const activationTokenPrefix = "gea_"

type RefreshInput struct {
	ActivationToken string
	InstallationID  string
}

func (s *Service) RefreshEntitlement(ctx context.Context, input RefreshInput) (Response, error) {
	installationID, installationHash, valid := canonicalInstallation(input.InstallationID)
	if !valid {
		return responseError(http.StatusBadRequest, "invalid_request", "The entitlement refresh request is invalid."), nil
	}
	tokenHash, valid := activationTokenHash(input.ActivationToken)
	if !valid {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The activation token is invalid."), nil
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Response{}, fmt.Errorf("begin entitlement refresh: %w", err)
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

	licenseID, found, err := findActivationLicenseIDByToken(ctx, tx, tokenHash)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The activation token is invalid."), nil
	}
	// Activation mutations lock the license before the activation row.
	license, found, err := findLicenseByID(ctx, tx, licenseID)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return Response{}, errors.New("activation license does not exist")
	}
	current, found, err := findActivationByToken(ctx, tx, tokenHash)
	if err != nil {
		return Response{}, err
	}
	if !found || subtle.ConstantTimeCompare(current.installationHash, installationHash[:]) != 1 {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The activation token is invalid."), nil
	}
	if current.state == "deactivated" {
		return responseError(http.StatusForbidden, "activation_revoked", "This activation has been deactivated."), nil
	}
	terms, eligible, err := entitlementTerms(license, now)
	if err != nil {
		return Response{}, err
	}
	if !eligible {
		return responseError(http.StatusForbidden, "license_not_eligible", "This license is not eligible for entitlement refresh."), nil
	}
	if current.revision == math.MaxInt64 {
		return Response{}, errors.New("activation revision is exhausted")
	}

	entitlementID, err := randomValue(s.random, "ent_", 16)
	if err != nil {
		return Response{}, fmt.Errorf("generate entitlement ID: %w", err)
	}
	revision := current.revision + 1
	signedEntitlement, err := s.issueEntitlement(ctx, terms, entitlement.Claims{
		LicenseID:      license.id,
		EntitlementID:  entitlementID,
		IssuedAt:       now.Unix(),
		ActivationID:   current.id,
		InstallationID: installationID,
		Revision:       revision,
	})
	if err != nil {
		return Response{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE activations
		SET entitlement_revision = $1, last_refreshed_at = $2
		WHERE id = $3`, revision, now, current.id); err != nil {
		return Response{}, fmt.Errorf("save entitlement refresh: %w", err)
	}
	body, err := json.Marshal(refreshBody{Entitlement: signedEntitlement})
	if err != nil {
		return Response{}, fmt.Errorf("encode entitlement refresh response: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Response{}, fmt.Errorf("commit entitlement refresh: %w", err)
	}
	return Response{Status: http.StatusOK, Body: body}, nil
}

func (s *Service) DeactivateCurrent(ctx context.Context, activationToken string) (Response, error) {
	tokenHash, valid := activationTokenHash(activationToken)
	if !valid {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The activation token is invalid."), nil
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Response{}, fmt.Errorf("begin activation deactivation: %w", err)
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

	licenseID, found, err := findActivationLicenseIDByToken(ctx, tx, tokenHash)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The activation token is invalid."), nil
	}
	// Activation mutations lock the license before the activation row.
	if _, found, err := findLicenseByID(ctx, tx, licenseID); err != nil {
		return Response{}, err
	} else if !found {
		return Response{}, errors.New("activation license does not exist")
	}
	current, found, err := findActivationByToken(ctx, tx, tokenHash)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The activation token is invalid."), nil
	}
	if current.state == "active" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE activations
			SET state = 'deactivated', deactivated_at = $1
			WHERE id = $2`, now, current.id); err != nil {
			return Response{}, fmt.Errorf("deactivate current activation: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Response{}, fmt.Errorf("commit activation deactivation: %w", err)
	}
	return Response{Status: http.StatusNoContent}, nil
}

func activationTokenHash(value string) ([sha256.Size]byte, bool) {
	return randomValueHash(value, activationTokenPrefix, 32)
}

type tokenActivationRecord struct {
	id               string
	licenseID        string
	installationHash []byte
	state            string
	revision         int64
}

func findActivationLicenseIDByToken(ctx context.Context, tx *sql.Tx, tokenHash [sha256.Size]byte) (string, bool, error) {
	var licenseID string
	err := tx.QueryRowContext(ctx, `
		SELECT license_id
		FROM activations
		WHERE token_hash = $1`, tokenHash[:]).Scan(&licenseID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("find token activation license: %w", err)
	}
	return licenseID, true, nil
}

func findActivationByToken(ctx context.Context, tx *sql.Tx, tokenHash [sha256.Size]byte) (tokenActivationRecord, bool, error) {
	var activation tokenActivationRecord
	err := tx.QueryRowContext(ctx, `
		SELECT id, license_id, installation_hash, state, entitlement_revision
		FROM activations
		WHERE token_hash = $1
		FOR UPDATE`, tokenHash[:]).Scan(
		&activation.id, &activation.licenseID, &activation.installationHash,
		&activation.state, &activation.revision,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return tokenActivationRecord{}, false, nil
	}
	if err != nil {
		return tokenActivationRecord{}, false, fmt.Errorf("find token activation: %w", err)
	}
	return activation, true, nil
}

func findLicenseByID(ctx context.Context, tx *sql.Tx, licenseID string) (licenseRecord, bool, error) {
	var license licenseRecord
	err := tx.QueryRowContext(ctx, `
		SELECT l.id, l.plan, l.state, s.state, s.billing_period_end, s.recovery_until, s.terminal_at
		FROM licenses AS l
		LEFT JOIN subscriptions AS s ON s.license_id = l.id
		WHERE l.id = $1
		FOR NO KEY UPDATE OF l`, licenseID).Scan(
		&license.id, &license.plan, &license.state, &license.subscriptionState,
		&license.billingPeriodEnd, &license.recoveryUntil, &license.terminalAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return licenseRecord{}, false, nil
	}
	if err != nil {
		return licenseRecord{}, false, fmt.Errorf("find activation license: %w", err)
	}
	return license, true, nil
}

type refreshBody struct {
	Entitlement string `json:"entitlement"`
}
