package activation

import (
	"context"
	"fmt"
	"time"
)

const cleanupBatchSize = 1000

// CleanupExpired deletes one bounded batch of stale request state.
func (s *Service) CleanupExpired(ctx context.Context, now time.Time) (int64, error) {
	return s.cleanupExpired(ctx, now.UTC(), cleanupBatchSize)
}

func (s *Service) cleanupExpired(ctx context.Context, now time.Time, batchSize int) (int64, error) {
	idempotencyResult, err := s.database.ExecContext(ctx, `
		WITH expired AS (
			SELECT scope, credential_hash, idempotency_key
			FROM idempotency_records
			WHERE expires_at <= $1
			ORDER BY expires_at
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM idempotency_records AS records
		USING expired
		WHERE records.scope = expired.scope
		  AND records.credential_hash = expired.credential_hash
		  AND records.idempotency_key = expired.idempotency_key`, now, batchSize)
	if err != nil {
		return 0, fmt.Errorf("delete expired idempotency records: %w", err)
	}
	idempotencyCount, err := idempotencyResult.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted idempotency count: %w", err)
	}

	rateLimitResult, err := s.database.ExecContext(ctx, `
		WITH expired AS (
			SELECT kind, subject_hash, window_start
			FROM activation_rate_limits
			WHERE window_start < $1
			ORDER BY window_start
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM activation_rate_limits AS records
		USING expired
		WHERE records.kind = expired.kind
		  AND records.subject_hash = expired.subject_hash
		  AND records.window_start = expired.window_start`, now.Truncate(rateLimitWindow), batchSize)
	if err != nil {
		return idempotencyCount, fmt.Errorf("delete expired activation rate limits: %w", err)
	}
	rateLimitCount, err := rateLimitResult.RowsAffected()
	if err != nil {
		return idempotencyCount, fmt.Errorf("read deleted rate-limit count: %w", err)
	}
	return idempotencyCount + rateLimitCount, nil
}
