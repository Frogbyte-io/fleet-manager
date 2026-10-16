-- FM-1040: the action broker's durable requests. One row per request; the
-- state moves only by compare-and-set (`UPDATE ... WHERE state = <from>`),
-- committed in the same transaction as its audit event, so of concurrent
-- decisions exactly one wins. Parameters are secret-free by construction
-- (refused when credential-like before they reach this table).
CREATE TABLE action_requests (
    id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    origin TEXT NOT NULL,
    action_id TEXT NOT NULL,
    target TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    risk_class TEXT NOT NULL CHECK (risk_class IN ('auto', 'approve', 'deny')),
    reason TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN
        ('pending', 'approved', 'denied', 'expired', 'executing', 'succeeded', 'failed')),
    decided_by TEXT,
    decided_at INTEGER,
    decision_note TEXT,
    operation_id TEXT,
    failure TEXT,
    correlation_id TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE INDEX action_requests_state_created ON action_requests (state, created_at);
CREATE INDEX action_requests_created ON action_requests (created_at);
