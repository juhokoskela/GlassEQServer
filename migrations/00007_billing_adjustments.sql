-- +goose Up

-- Persist the decision before canceling Stripe billing. Pending adjustments block
-- ordinary fulfillment/reconciliation until the external outcome is confirmed.
CREATE TABLE billing_adjustments (
    stripe_object_id text PRIMARY KEY,
    order_id text NOT NULL REFERENCES checkout_orders (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('refund', 'dispute')),
    stripe_charge_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('blocking', 'resolved')),
    pending boolean NOT NULL,
    cancel_required boolean NOT NULL,
    effective_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (kind <> 'refund' OR state = 'blocking')
);
CREATE INDEX billing_adjustments_order ON billing_adjustments (order_id);

-- +goose Down

DROP TABLE billing_adjustments;
