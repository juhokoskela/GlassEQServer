package activation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type LicenseEmail struct {
	Email      string
	LicenseKey string
}

func (s *Service) DispatchLicenseEmail(ctx context.Context, now time.Time) (bool, error) {
	now = now.UTC().Truncate(time.Microsecond)
	var deliveryID, keyID, licenseID string
	var keyCiphertext, emailCiphertext []byte
	var expiresAt time.Time
	claimCtx, cancel := context.WithTimeout(ctx, recoveryDatabaseTimeout)
	err := s.database.QueryRowContext(claimCtx, `
		WITH candidate AS (
			SELECT outbox.id
			FROM license_delivery_outbox AS outbox
			JOIN license_keys AS key ON key.id = outbox.license_key_id
			JOIN licenses AS license ON license.id = key.license_id
			WHERE outbox.next_attempt_at <= $1 AND outbox.expires_at > $3
			  AND key.state = 'active' AND license.state = 'active'
			  AND key.delivery_ciphertext IS NOT NULL
			ORDER BY outbox.next_attempt_at, outbox.created_at, outbox.id
			LIMIT 1 FOR UPDATE OF outbox SKIP LOCKED
		)
		UPDATE license_delivery_outbox AS outbox
		SET next_attempt_at = $2
		FROM candidate, license_keys AS key, licenses AS license
		WHERE outbox.id = candidate.id AND key.id = outbox.license_key_id AND license.id = key.license_id
		RETURNING outbox.id, key.id, license.id, key.delivery_ciphertext,
		          key.delivery_expires_at, license.recovery_email_ciphertext`,
		now, now.Add(recoveryRetryDelay), now.Add(recoveryMinimumDeliveryLifetime)).Scan(
		&deliveryID, &keyID, &licenseID, &keyCiphertext, &expiresAt, &emailCiphertext,
	)
	cancel()
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim license email: %w", err)
	}
	email, err := s.databaseValues.open(emailCiphertext, recoveryEmailAdditionalData(licenseID))
	if err != nil {
		return false, fmt.Errorf("decrypt license email address: %w", err)
	}
	key, err := s.databaseValues.open(keyCiphertext, licenseDeliveryAdditionalData(keyID, licenseID, expiresAt))
	if err != nil {
		return false, fmt.Errorf("decrypt license key for delivery: %w", err)
	}
	emailCtx, cancel := context.WithTimeout(ctx, recoveryEmailTimeout)
	err = s.emails.SendLicenseEmail(emailCtx, LicenseEmail{Email: string(email), LicenseKey: string(key)})
	cancel()
	if err != nil {
		return false, fmt.Errorf("send license email: %w", err)
	}
	ackCtx, cancel := context.WithTimeout(ctx, recoveryDatabaseTimeout)
	defer cancel()
	tx, err := s.database.BeginTx(ackCtx, nil)
	if err != nil {
		return false, fmt.Errorf("begin license email acknowledgement: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ackCtx, `DELETE FROM license_delivery_outbox WHERE id = $1 AND license_key_id = $2`, deliveryID, keyID)
	if err != nil {
		return false, fmt.Errorf("delete sent license email: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted != 1 {
		return false, errors.New("claimed license email disappeared before acknowledgement")
	}
	if _, err := tx.ExecContext(ackCtx, `UPDATE license_keys SET delivery_ciphertext = NULL, delivery_expires_at = NULL WHERE id = $1`, keyID); err != nil {
		return false, fmt.Errorf("clear delivered license key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit license email acknowledgement: %w", err)
	}
	return true, nil
}
