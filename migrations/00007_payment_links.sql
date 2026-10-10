-- +goose Up

-- Payment Links create Checkout Sessions without a server reservation.
ALTER TABLE checkout_orders ALTER COLUMN request_id DROP NOT NULL;

DELETE FROM activation_rate_limits WHERE kind IN ('checkout_ip', 'checkout_attempt_ip');
ALTER TABLE activation_rate_limits
    DROP CONSTRAINT activation_rate_limits_kind_check,
    ADD CONSTRAINT activation_rate_limits_kind_check
        CHECK (kind IN ('ip', 'license_key', 'recovery_ip', 'recovery_email'));

-- +goose Down

ALTER TABLE activation_rate_limits
    DROP CONSTRAINT activation_rate_limits_kind_check,
    ADD CONSTRAINT activation_rate_limits_kind_check
        CHECK (kind IN ('ip', 'license_key', 'recovery_ip', 'recovery_email', 'checkout_ip', 'checkout_attempt_ip'));

ALTER TABLE checkout_orders ALTER COLUMN request_id SET NOT NULL;
