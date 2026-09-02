package activation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	recoveryDatabaseTimeout         = 3 * time.Second
	recoveryQueueTimeout            = 10 * time.Second
	recoveryDispatchRetryDelay      = time.Minute
	recoveryMinimumDeliveryLifetime = 5 * time.Minute
)

func (s *Service) DispatchRecoveryEmail(ctx context.Context, now time.Time) (bool, error) {
	now = now.UTC().Truncate(time.Microsecond)
	prepared, err := s.prepareRecoveryRequest(ctx, now)
	if err != nil {
		return false, err
	}
	dispatched, err := s.dispatchRecoveryEmail(ctx, now)
	if err != nil {
		return false, err
	}
	return prepared || dispatched, nil
}

func (s *Service) prepareRecoveryRequest(ctx context.Context, now time.Time) (bool, error) {
	prepareCtx, cancel := context.WithTimeout(ctx, recoveryDatabaseTimeout)
	defer cancel()
	tx, err := s.database.BeginTx(prepareCtx, nil)
	if err != nil {
		return false, fmt.Errorf("begin recovery request preparation: %w", err)
	}
	defer tx.Rollback()

	var requestID string
	var lookupHash []byte
	err = tx.QueryRowContext(prepareCtx, `
		SELECT id, email_lookup
		FROM recovery_request_jobs
		WHERE expires_at > $1
		ORDER BY created_at, id
		LIMIT 1
		FOR UPDATE SKIP LOCKED`, now).Scan(&requestID, &lookupHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim recovery request: %w", err)
	}
	licenseIDs, err := findRecoveryLicenses(prepareCtx, tx, lookupHash)
	if err != nil {
		return false, err
	}
	for _, licenseID := range licenseIDs {
		if err := s.createRecoveryDelivery(prepareCtx, tx, licenseID, now); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(prepareCtx, `
		DELETE FROM recovery_request_jobs
		WHERE id = $1`, requestID); err != nil {
		return false, fmt.Errorf("delete prepared recovery request: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit recovery request preparation: %w", err)
	}
	return true, nil
}

func findRecoveryLicenses(ctx context.Context, tx *sql.Tx, lookupHash []byte) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id
		FROM licenses
		WHERE recovery_email_lookup = $1 AND state = 'active'
		ORDER BY id`, lookupHash)
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

func (s *Service) dispatchRecoveryEmail(ctx context.Context, now time.Time) (bool, error) {
	var deliveryID, licenseID string
	var tokenCiphertext, emailCiphertext []byte
	var expiresAt time.Time
	claimCtx, cancel := context.WithTimeout(ctx, recoveryDatabaseTimeout)
	err := s.database.QueryRowContext(claimCtx, `
		WITH candidate AS (
			SELECT outbox.id
			FROM recovery_email_outbox AS outbox
			JOIN licenses AS license ON license.id = outbox.license_id
			WHERE outbox.next_attempt_at <= $1
			  AND outbox.expires_at > $3
			  AND license.state = 'active'
			ORDER BY outbox.next_attempt_at, outbox.created_at, outbox.id
			LIMIT 1
			FOR UPDATE OF outbox SKIP LOCKED
		)
		UPDATE recovery_email_outbox AS outbox
		SET next_attempt_at = $2
		FROM candidate, licenses AS license
		WHERE outbox.id = candidate.id AND license.id = outbox.license_id
		RETURNING outbox.id, outbox.license_id, outbox.token_ciphertext,
		          outbox.expires_at, license.recovery_email_ciphertext`,
		now, now.Add(recoveryDispatchRetryDelay), now.Add(recoveryMinimumDeliveryLifetime)).Scan(
		&deliveryID, &licenseID, &tokenCiphertext, &expiresAt, &emailCiphertext,
	)
	cancel()
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim recovery email: %w", err)
	}

	email, err := s.databaseValues.open(emailCiphertext, recoveryEmailAdditionalData(licenseID))
	if err != nil {
		return false, fmt.Errorf("decrypt recovery email: %w", err)
	}
	token, err := s.databaseValues.open(tokenCiphertext, recoveryTokenAdditionalData(deliveryID, licenseID, expiresAt))
	if err != nil {
		return false, fmt.Errorf("decrypt recovery token: %w", err)
	}
	message := RecoveryEmail{
		Schema:        1,
		DeliveryID:    deliveryID,
		Email:         string(email),
		RecoveryToken: string(token),
		ExpiresAt:     expiresAt.Unix(),
	}
	queueCtx, cancel := context.WithTimeout(ctx, recoveryQueueTimeout)
	err = s.recoveryEmails.SendRecoveryEmail(queueCtx, message)
	cancel()
	if err != nil {
		return false, fmt.Errorf("send recovery email to queue: %w", err)
	}
	ackCtx, cancel := context.WithTimeout(ctx, recoveryDatabaseTimeout)
	result, err := s.database.ExecContext(ackCtx, `
		DELETE FROM recovery_email_outbox
		WHERE id = $1`, deliveryID)
	cancel()
	if err != nil {
		return false, fmt.Errorf("delete dispatched recovery email: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read deleted recovery email count: %w", err)
	}
	if deleted != 1 {
		return false, errors.New("claimed recovery email disappeared before dispatch completed")
	}
	return true, nil
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
