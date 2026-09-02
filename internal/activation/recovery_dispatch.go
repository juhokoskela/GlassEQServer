package activation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (s *Service) DispatchRecoveryEmail(ctx context.Context, now time.Time) (bool, error) {
	now = now.UTC().Truncate(time.Microsecond)
	var deliveryID, licenseID string
	var tokenCiphertext, emailCiphertext []byte
	var expiresAt time.Time
	err := s.database.QueryRowContext(ctx, `
		WITH candidate AS (
			SELECT outbox.id
			FROM recovery_email_outbox AS outbox
			JOIN licenses AS license ON license.id = outbox.license_id
			WHERE outbox.dispatched_at IS NULL
			  AND outbox.next_attempt_at <= $1
			  AND outbox.expires_at > $1
			  AND license.state = 'active'
			ORDER BY outbox.next_attempt_at, outbox.created_at, outbox.id
			LIMIT 1
			FOR UPDATE OF outbox SKIP LOCKED
		)
		UPDATE recovery_email_outbox AS outbox
		SET attempts = outbox.attempts + 1, next_attempt_at = $2
		FROM candidate, licenses AS license
		WHERE outbox.id = candidate.id AND license.id = outbox.license_id
		RETURNING outbox.id, outbox.license_id, outbox.token_ciphertext,
		          outbox.expires_at, license.recovery_email_ciphertext`,
		now, now.Add(recoveryDispatchRetryDelay)).Scan(
		&deliveryID, &licenseID, &tokenCiphertext, &expiresAt, &emailCiphertext,
	)
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
	result, err := s.database.ExecContext(ctx, `
		UPDATE recovery_email_outbox
		SET dispatched_at = $2
		WHERE id = $1 AND dispatched_at IS NULL`, deliveryID, now)
	if err != nil {
		return false, fmt.Errorf("mark recovery email dispatched: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read dispatched recovery email count: %w", err)
	}
	if updated != 1 {
		return false, errors.New("claimed recovery email disappeared before dispatch completed")
	}
	return true, nil
}
