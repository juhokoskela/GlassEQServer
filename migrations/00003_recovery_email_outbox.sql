-- +goose Up

ALTER TABLE activation_rate_limits
    DROP CONSTRAINT activation_rate_limits_kind_check,
    ADD CONSTRAINT activation_rate_limits_kind_check
        CHECK (kind IN ('ip', 'license_key', 'recovery_ip', 'recovery_email'));

CREATE INDEX licenses_active_recovery_email_lookup
    ON licenses (recovery_email_lookup)
    WHERE state = 'active';

CREATE TABLE recovery_request_jobs (
    id text PRIMARY KEY,
    email_lookup bytea NOT NULL CHECK (octet_length(email_lookup) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at = created_at + interval '30 minutes')
);

CREATE INDEX recovery_request_jobs_pending
    ON recovery_request_jobs (created_at, id);

CREATE INDEX recovery_request_jobs_expiry
    ON recovery_request_jobs (expires_at);

CREATE TABLE recovery_email_outbox (
    id text PRIMARY KEY,
    license_id text NOT NULL REFERENCES licenses (id),
    token_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    next_attempt_at timestamptz NOT NULL,
    CHECK (expires_at = created_at + interval '30 minutes'),
    CHECK (next_attempt_at >= created_at)
);

CREATE INDEX recovery_email_outbox_pending
    ON recovery_email_outbox (next_attempt_at, created_at);

CREATE INDEX recovery_email_outbox_expiry
    ON recovery_email_outbox (expires_at);

-- +goose Down

DROP TABLE recovery_email_outbox;
DROP TABLE recovery_request_jobs;
DROP INDEX licenses_active_recovery_email_lookup;

DELETE FROM activation_rate_limits
WHERE kind IN ('recovery_ip', 'recovery_email');

ALTER TABLE activation_rate_limits
    DROP CONSTRAINT activation_rate_limits_kind_check,
    ADD CONSTRAINT activation_rate_limits_kind_check
        CHECK (kind IN ('ip', 'license_key'));
