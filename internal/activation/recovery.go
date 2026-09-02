package activation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	recoverySessionScope = "recovery_session"
	recoveryTokenPrefix  = "ger_"
)

type RecoverySessionInput struct {
	RecoveryToken  string
	IdempotencyKey string
}

func (s *Service) ExchangeRecoveryToken(ctx context.Context, input RecoverySessionInput) (Response, error) {
	tokenHash, valid := recoveryTokenHash(input.RecoveryToken)
	if !valid {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The recovery token is invalid."), nil
	}
	idempotencyKey, valid := canonicalIdempotencyKey(input.IdempotencyKey)
	if !valid {
		return responseError(http.StatusBadRequest, "invalid_request", "The recovery session request is invalid."), nil
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	idempotency := idempotencyRequest{
		scope:          recoverySessionScope,
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
		return Response{}, fmt.Errorf("begin recovery-session exchange: %w", err)
	}
	defer tx.Rollback()

	var available bool
	err = tx.QueryRowContext(ctx, `
		SELECT expires_at > $2 AND consumed_at IS NULL
		FROM access_tokens
		WHERE token_hash = $1 AND purpose = 'recovery'
		FOR UPDATE NOWAIT`, tokenHash[:], now).Scan(&available)
	if databaseLockUnavailable(err) {
		return databaseBusyResponse(), nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The recovery token is invalid."), nil
	}
	if err != nil {
		return Response{}, fmt.Errorf("lock recovery token: %w", err)
	}

	replayed, replayFound, _, err = s.loadIdempotency(ctx, tx, idempotency, now)
	if err != nil {
		return Response{}, err
	}
	if replayFound {
		return replayed, nil
	}
	if !available {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The recovery token is invalid."), nil
	}

	session, err := s.mintManagementSession(now)
	if err != nil {
		return Response{}, err
	}

	result, err := tx.ExecContext(ctx, `
		WITH recovery AS (
			UPDATE access_tokens
			SET consumed_at = $2
			WHERE token_hash = $1
			  AND purpose = 'recovery'
			  AND expires_at > $2
			  AND consumed_at IS NULL
			RETURNING license_id
		)
		INSERT INTO access_tokens (token_hash, license_id, purpose, created_at, expires_at)
		SELECT $3, license_id, 'management', $2, $4
		FROM recovery`, tokenHash[:], now, session.tokenHash[:], session.expiresAt)
	if err != nil {
		return Response{}, fmt.Errorf("exchange recovery token: %w", err)
	}
	created, err := result.RowsAffected()
	if err != nil {
		return Response{}, fmt.Errorf("read recovery-session result: %w", err)
	}
	if created == 0 {
		return Response{}, errors.New("locked recovery token changed during exchange")
	}
	return s.storeAndCommit(ctx, tx, idempotency, Response{Status: http.StatusCreated, Body: session.body}, now)
}

func recoveryTokenHash(value string) ([sha256.Size]byte, bool) {
	return randomValueHash(value, recoveryTokenPrefix, 32)
}
