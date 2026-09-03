-- The append-only audit ledger. Append-only is enforced by the database
-- itself: triggers abort any UPDATE or DELETE, so a bug or a compromised code
-- path cannot rewrite history from inside the process. Ordering is the rowid
-- sequence; ids are uuid v7 for correlation across systems.

CREATE TABLE audit_events (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    id              TEXT NOT NULL UNIQUE,
    occurred_at     INTEGER NOT NULL,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource        TEXT,
    allowed         INTEGER NOT NULL CHECK (allowed IN (0, 1)),
    reason          TEXT NOT NULL,
    correlation_id  TEXT,
    operation_id    TEXT,
    outcome         TEXT CHECK (outcome IS NULL OR outcome IN ('succeeded', 'failed')),
    metadata_json   TEXT NOT NULL
) STRICT;

CREATE INDEX audit_events_occurred_at ON audit_events (occurred_at);
CREATE INDEX audit_events_correlation ON audit_events (correlation_id);
CREATE INDEX audit_events_operation ON audit_events (operation_id);

CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_no_delete
    BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
