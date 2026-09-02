-- +goose Up

CREATE TABLE licenses (
    id text PRIMARY KEY,
    plan text NOT NULL CHECK (plan IN ('perpetual_v1', 'monthly')),
    state text NOT NULL CHECK (state IN ('active', 'refunded', 'charged_back', 'revoked')),
    policy_version text NOT NULL,
    recovery_email_ciphertext bytea NOT NULL,
    recovery_email_lookup bytea NOT NULL CHECK (octet_length(recovery_email_lookup) = 32),
    stripe_customer_id text,
    stripe_subscription_id text UNIQUE,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE checkout_orders (
    id text PRIMARY KEY,
    plan text NOT NULL CHECK (plan IN ('perpetual_v1', 'monthly')),
    policy_version text NOT NULL,
    stripe_price_id text NOT NULL,
    stripe_checkout_session_id text NOT NULL UNIQUE,
    state text NOT NULL CHECK (state IN ('pending', 'paid', 'failed', 'fulfilled')),
    license_id text UNIQUE REFERENCES licenses (id),
    created_at timestamptz NOT NULL,
    fulfilled_at timestamptz,
    CHECK (
        (state = 'fulfilled' AND license_id IS NOT NULL AND fulfilled_at IS NOT NULL)
        OR (state <> 'fulfilled' AND license_id IS NULL AND fulfilled_at IS NULL)
    )
);

CREATE TABLE license_keys (
    id text PRIMARY KEY,
    license_id text NOT NULL REFERENCES licenses (id),
    secret_hash bytea NOT NULL UNIQUE CHECK (octet_length(secret_hash) = 32),
    delivery_ciphertext bytea,
    delivery_expires_at timestamptz,
    state text NOT NULL CHECK (state IN ('active', 'revoked')),
    created_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK ((delivery_ciphertext IS NULL) = (delivery_expires_at IS NULL)),
    CHECK (
        delivery_expires_at IS NULL
        OR (delivery_expires_at > created_at AND delivery_expires_at <= created_at + interval '7 days')
    ),
    CHECK (
        (state = 'active' AND revoked_at IS NULL)
        OR (state = 'revoked' AND revoked_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX license_keys_one_active_per_license
    ON license_keys (license_id)
    WHERE state = 'active';

CREATE TABLE subscriptions (
    license_id text PRIMARY KEY REFERENCES licenses (id),
    state text NOT NULL CHECK (state IN ('active', 'recovering', 'ending', 'lapsed')),
    billing_period_end timestamptz NOT NULL,
    recovery_until timestamptz NOT NULL,
    terminal_at timestamptz,
    last_paid_invoice_id text UNIQUE,
    last_stripe_event_id text,
    last_reconciled_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (billing_period_end <= recovery_until)
);

CREATE TABLE activations (
    id text PRIMARY KEY,
    license_id text NOT NULL REFERENCES licenses (id),
    installation_hash bytea NOT NULL CHECK (octet_length(installation_hash) = 32),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    state text NOT NULL CHECK (state IN ('active', 'deactivated')),
    entitlement_revision bigint NOT NULL CHECK (entitlement_revision > 0),
    activated_at timestamptz NOT NULL,
    last_refreshed_at timestamptz NOT NULL,
    deactivated_at timestamptz,
    UNIQUE (license_id, installation_hash),
    CHECK (
        (state = 'active' AND deactivated_at IS NULL)
        OR (state = 'deactivated' AND deactivated_at IS NOT NULL)
    )
);

CREATE INDEX activations_active_license
    ON activations (license_id)
    WHERE state = 'active';

CREATE TABLE idempotency_records (
    scope text NOT NULL,
    credential_hash bytea NOT NULL CHECK (octet_length(credential_hash) = 32),
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    status_code integer NOT NULL CHECK (status_code BETWEEN 100 AND 599),
    response_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (scope, credential_hash, idempotency_key),
    CHECK (expires_at = created_at + interval '24 hours')
);

CREATE INDEX idempotency_records_expiry ON idempotency_records (expires_at);

CREATE TABLE stripe_events (
    stripe_event_id text PRIMARY KEY,
    event_type text NOT NULL,
    object_id text NOT NULL,
    stripe_created_at timestamptz NOT NULL,
    processed_at timestamptz,
    outcome text
);

CREATE INDEX stripe_events_unprocessed
    ON stripe_events (stripe_created_at)
    WHERE processed_at IS NULL;

CREATE TABLE access_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    license_id text NOT NULL REFERENCES licenses (id),
    purpose text NOT NULL CHECK (purpose IN ('management', 'recovery')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (
        (purpose = 'management' AND expires_at = created_at + interval '15 minutes')
        OR (purpose = 'recovery' AND expires_at = created_at + interval '30 minutes')
    ),
    CHECK (purpose = 'recovery' OR consumed_at IS NULL)
);

CREATE INDEX access_tokens_expiry ON access_tokens (expires_at);

CREATE TABLE releases (
    id text PRIMARY KEY,
    version text NOT NULL UNIQUE,
    major_version integer NOT NULL CHECK (major_version > 0),
    channel text NOT NULL CHECK (channel IN ('v1', 'stable', 'security')),
    is_security_fix boolean NOT NULL,
    archive_storage_key text NOT NULL UNIQUE,
    archive_sha256 bytea NOT NULL CHECK (octet_length(archive_sha256) = 32),
    published_at timestamptz NOT NULL
);

-- +goose Down

DROP TABLE releases;
DROP TABLE access_tokens;
DROP TABLE stripe_events;
DROP TABLE idempotency_records;
DROP TABLE activations;
DROP TABLE subscriptions;
DROP TABLE license_keys;
DROP TABLE checkout_orders;
DROP TABLE licenses;
