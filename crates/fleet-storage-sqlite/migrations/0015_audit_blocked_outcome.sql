-- FM-303: the audit ledger records blocked_manual_approval as its own
-- terminal outcome, so the trail preserves the first-class state instead
-- of a failure. The audit_events table's outcome CHECK is rebuilt; the
-- append-only triggers are recreated exactly as 0003 defined them.
--
-- As with 0014, the rebuild runs inside the controller's startup
-- migration transaction, before any surface accepts work.
PRAGMA foreign_keys = OFF;

CREATE TABLE audit_events_new (
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
    outcome         TEXT CHECK (outcome IS NULL OR outcome IN ('succeeded', 'failed', 'cancelled', 'blocked_manual_approval')),
    metadata_json   TEXT NOT NULL
) STRICT;

INSERT INTO audit_events_new
    (seq, id, occurred_at, actor, action, resource, allowed, reason,
     correlation_id, operation_id, outcome, metadata_json)
SELECT
    seq, id, occurred_at, actor, action, resource, allowed, reason,
    correlation_id, operation_id, outcome, metadata_json
FROM audit_events;
DROP TABLE audit_events;
ALTER TABLE audit_events_new RENAME TO audit_events;

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

PRAGMA foreign_key_check;
PRAGMA foreign_keys = ON;
