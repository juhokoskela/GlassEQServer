-- +goose Up

CREATE TABLE activation_rate_limits (
    kind text NOT NULL CHECK (kind IN ('ip', 'license_key')),
    subject_hash bytea NOT NULL CHECK (octet_length(subject_hash) = 32),
    window_start timestamptz NOT NULL,
    attempts integer NOT NULL CHECK (attempts > 0),
    PRIMARY KEY (kind, subject_hash, window_start)
);

CREATE INDEX activation_rate_limits_window ON activation_rate_limits (window_start);

-- +goose Down

DROP TABLE activation_rate_limits;
