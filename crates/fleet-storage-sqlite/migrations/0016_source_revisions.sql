-- FM-403: the desired-state source's durable state — the active revision
-- (single row, upsert) and the prior valid revisions (append-only
-- history for manual rollback). Only VALID candidates are recorded; a
-- candidate carrying diagnostics is reported and forgotten.
CREATE TABLE source_active_revision (
    id             TEXT PRIMARY KEY,
    commit_sha     TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    activated_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE source_revision_history (
    id             TEXT PRIMARY KEY,
    commit_sha     TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    activated_at   INTEGER NOT NULL
) STRICT;

CREATE INDEX source_revision_history_at ON source_revision_history (activated_at);
