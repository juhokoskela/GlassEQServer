package activation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	recoveryTokenPrefix   = "ger_"
	recoveryTokenLifetime = 30 * time.Minute
)

func (s *Service) ExchangeRecoveryToken(ctx context.Context, recoveryToken string) (Response, error) {
	tokenHash, valid := recoveryTokenHash(recoveryToken)
	if !valid {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The recovery token is invalid."), nil
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	managementToken, err := randomValue(s.random, managementTokenPrefix, 32)
	if err != nil {
		return Response{}, fmt.Errorf("generate management token: %w", err)
	}
	managementTokenHash := sha256.Sum256([]byte(managementToken))
	expiresAt := now.Add(managementTokenLifetime)
	body, err := json.Marshal(managementSessionBody{
		ManagementToken: managementToken,
		ExpiresAt:       expiresAt.Unix(),
	})
	if err != nil {
		return Response{}, fmt.Errorf("encode management session response: %w", err)
	}

	result, err := s.database.ExecContext(ctx, `
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
		FROM recovery`, tokenHash[:], now, managementTokenHash[:], expiresAt)
	if err != nil {
		return Response{}, fmt.Errorf("exchange recovery token: %w", err)
	}
	created, err := result.RowsAffected()
	if err != nil {
		return Response{}, fmt.Errorf("read recovery-session result: %w", err)
	}
	if created == 0 {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The recovery token is invalid."), nil
	}
	return Response{Status: http.StatusCreated, Body: body}, nil
}

func recoveryTokenHash(value string) ([sha256.Size]byte, bool) {
	return randomValueHash(value, recoveryTokenPrefix, 32)
}
