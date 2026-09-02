package activation

import (
	"context"
	"database/sql"
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
