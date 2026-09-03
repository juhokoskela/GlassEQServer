-- +goose Up

-- Billing has not shipped, so checkout_orders has no legacy rows to backfill.
ALTER TABLE checkout_orders
    ADD COLUMN request_id uuid NOT NULL,
    ADD COLUMN stripe_payment_intent_id text,
    ADD COLUMN stripe_subscription_id text,
    ALTER COLUMN stripe_checkout_session_id DROP NOT NULL,
    ADD CONSTRAINT checkout_orders_request_id_key UNIQUE (request_id),
    ADD CONSTRAINT checkout_orders_payment_intent_id_key UNIQUE (stripe_payment_intent_id),
    ADD CONSTRAINT checkout_orders_subscription_id_key UNIQUE (stripe_subscription_id),
    ADD CONSTRAINT checkout_orders_session_state_check CHECK (
        stripe_checkout_session_id IS NOT NULL
        OR (
            state = 'pending'
            AND stripe_payment_intent_id IS NULL
            AND stripe_subscription_id IS NULL
        )
    ),
    ADD CONSTRAINT checkout_orders_plan_reference_check CHECK (
        (plan = 'perpetual_v1' AND stripe_subscription_id IS NULL)
        OR (plan = 'monthly' AND stripe_payment_intent_id IS NULL)
    ),
    ADD CONSTRAINT checkout_orders_paid_reference_check CHECK (
        state NOT IN ('paid', 'fulfilled')
        OR (plan = 'perpetual_v1' AND stripe_payment_intent_id IS NOT NULL)
        OR (plan = 'monthly' AND stripe_subscription_id IS NOT NULL)
    );

CREATE INDEX checkout_orders_unfulfilled
    ON checkout_orders (state, created_at, id)
    WHERE state <> 'fulfilled';

ALTER TABLE activation_rate_limits
    DROP CONSTRAINT activation_rate_limits_kind_check,
    ADD CONSTRAINT activation_rate_limits_kind_check
        CHECK (kind IN ('ip', 'license_key', 'recovery_ip', 'recovery_email', 'checkout_ip'));

CREATE TABLE license_delivery_outbox (
    id text PRIMARY KEY,
    license_key_id text NOT NULL UNIQUE REFERENCES license_keys (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    next_attempt_at timestamptz NOT NULL,
    CHECK (expires_at = created_at + interval '7 days'),
    CHECK (next_attempt_at >= created_at)
);

CREATE INDEX license_delivery_outbox_pending
    ON license_delivery_outbox (next_attempt_at, created_at, id);

CREATE INDEX license_delivery_outbox_expiry
    ON license_delivery_outbox (expires_at);

CREATE INDEX stripe_events_processed
    ON stripe_events (processed_at)
    WHERE processed_at IS NOT NULL;

-- +goose Down

DROP INDEX stripe_events_processed;
DROP TABLE license_delivery_outbox;

DELETE FROM activation_rate_limits
WHERE kind = 'checkout_ip';

ALTER TABLE activation_rate_limits
    DROP CONSTRAINT activation_rate_limits_kind_check,
    ADD CONSTRAINT activation_rate_limits_kind_check
        CHECK (kind IN ('ip', 'license_key', 'recovery_ip', 'recovery_email'));

DROP INDEX checkout_orders_unfulfilled;

ALTER TABLE checkout_orders
    DROP CONSTRAINT checkout_orders_paid_reference_check,
    DROP CONSTRAINT checkout_orders_plan_reference_check,
    DROP CONSTRAINT checkout_orders_session_state_check,
    DROP CONSTRAINT checkout_orders_subscription_id_key,
    DROP CONSTRAINT checkout_orders_payment_intent_id_key,
    DROP CONSTRAINT checkout_orders_request_id_key;

DELETE FROM checkout_orders
WHERE stripe_checkout_session_id IS NULL;

ALTER TABLE checkout_orders
    DROP COLUMN stripe_subscription_id,
    DROP COLUMN stripe_payment_intent_id,
    DROP COLUMN request_id,
    ALTER COLUMN stripe_checkout_session_id SET NOT NULL;
