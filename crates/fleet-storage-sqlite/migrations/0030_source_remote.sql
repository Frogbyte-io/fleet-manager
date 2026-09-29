-- FM-405: the configured desired-source remote (single row). Non-secret
-- text only: the application layer refuses embedded credentials before it
-- reaches this table.
CREATE TABLE source_remote (
    singleton  TEXT PRIMARY KEY CHECK (singleton = 'remote'),
    remote     TEXT NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
