-- +goose Up

ALTER TABLE activation_rate_limits
    DROP CONSTRAINT activation_rate_limits_kind_check,
    ADD CONSTRAINT activation_rate_limits_kind_check
        CHECK (kind IN ('ip', 'license_key', 'recovery_ip', 'recovery_email', 'checkout_ip', 'checkout_attempt_ip'));

-- +goose Down

DELETE FROM activation_rate_limits
WHERE kind = 'checkout_attempt_ip';

ALTER TABLE activation_rate_limits
    DROP CONSTRAINT activation_rate_limits_kind_check,
    ADD CONSTRAINT activation_rate_limits_kind_check
        CHECK (kind IN ('ip', 'license_key', 'recovery_ip', 'recovery_email', 'checkout_ip'));
