-- Durable operations. An operation is the record of accepted remote work:
-- created once, idempotent under retries, progress-tracked, deadline-bounded,
-- cancellable, and truthful across controller restarts. Transitions between
-- states are validated by the domain (fleet-core); the CHECK here is the last
-- line of defense, not the policy.

CREATE TABLE operations (
    id               TEXT PRIMARY KEY,
    kind             TEXT NOT NULL,
    state            TEXT NOT NULL CHECK (state IN
                         ('pending', 'running', 'cancelling',
                          'succeeded', 'failed', 'cancelled', 'timed_out')),
    idempotency_key  TEXT UNIQUE,
    progress_current INTEGER,
    progress_total   INTEGER,
    progress_message TEXT,
    deadline_at      INTEGER,
    cancel_requested INTEGER NOT NULL CHECK (cancel_requested IN (0, 1)),
    result_json      TEXT,
    error_json       TEXT,
    correlation_id   TEXT,
    attempts         INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
) STRICT;

CREATE INDEX operations_state ON operations (state);
CREATE INDEX operations_correlation ON operations (correlation_id);
CREATE INDEX operations_deadline ON operations (deadline_at) WHERE deadline_at IS NOT NULL;
