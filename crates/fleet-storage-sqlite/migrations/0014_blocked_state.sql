-- FM-303: blocked_manual_approval is a first-class terminal operation
-- state, not a failure wearing a label. The operations table's state CHECK
-- is rebuilt to admit it; existing rows are unaffected (none can carry the
-- new state yet).
--
-- The rebuild is the only way SQLite can change a CHECK constraint. It
-- runs inside the controller's startup migration transaction, before the
-- HTTP surface or the worker accepts work, so no operation processing can
-- contend with it: the single-controller deployment has no concurrent
-- writers at migration time.
--
-- Recovery plan: the migration is transactional — a failure rolls the
-- whole rebuild back to the pre-migration schema, and the controller
-- refuses to start rather than serving against a half-migrated store. The
-- copy cost grows with the operations row count, which accumulates until
-- an operator prunes it; the startup cost is paid once per install, and
-- an operator with a very old store can archive and prune before
-- upgrading. The PRAGMA foreign_keys wrapper is a no-op inside a
-- transaction (enforcement stays ON); it is kept only as documentation
-- that nothing FK-references this table today, and a future FK into
-- operations must reorder migrations instead of relying on it.
PRAGMA foreign_keys = OFF;

CREATE TABLE operations_new (
    id               TEXT PRIMARY KEY,
    kind             TEXT NOT NULL,
    state            TEXT NOT NULL CHECK (state IN
                         ('pending', 'running', 'cancelling',
                          'succeeded', 'failed', 'cancelled', 'timed_out',
                          'blocked_manual_approval')),
    idempotency_key  TEXT UNIQUE,
    progress_current INTEGER,
    progress_total   INTEGER,
    progress_message TEXT,
    deadline_at      INTEGER,
    cancel_requested INTEGER NOT NULL CHECK (cancel_requested IN (0, 1)),
    result_json      TEXT,
    error_json       TEXT,
    correlation_id   TEXT,
    payload_json     TEXT,
    claimed_at       INTEGER,
    worker_id        TEXT,
    attempts         INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
) STRICT;

INSERT INTO operations_new
    (id, kind, state, idempotency_key, progress_current, progress_total,
     progress_message, deadline_at, cancel_requested, result_json,
     error_json, correlation_id, payload_json, claimed_at, worker_id,
     attempts, created_at, updated_at)
SELECT
    id, kind, state, idempotency_key, progress_current, progress_total,
    progress_message, deadline_at, cancel_requested, result_json,
    error_json, correlation_id, payload_json, claimed_at, worker_id,
    attempts, created_at, updated_at
FROM operations;
DROP TABLE operations;
ALTER TABLE operations_new RENAME TO operations;

CREATE INDEX operations_state ON operations (state);
CREATE INDEX operations_correlation ON operations (correlation_id);
CREATE INDEX operations_deadline ON operations (deadline_at) WHERE deadline_at IS NOT NULL;
CREATE INDEX operations_claimed ON operations (claimed_at) WHERE claimed_at IS NOT NULL;

PRAGMA foreign_key_check;
PRAGMA foreign_keys = ON;
