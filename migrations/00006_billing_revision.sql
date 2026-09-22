-- +goose Up

-- Compare the revision observed before Stripe hydration with the locked order.
-- A competing reconciliation invalidates the snapshot and leaves the event retryable.
ALTER TABLE checkout_orders ADD COLUMN billing_revision bigint NOT NULL DEFAULT 0 CHECK (billing_revision >= 0);

-- +goose Down

ALTER TABLE checkout_orders DROP COLUMN billing_revision;
