-- FM-711: Lab leases — the owner/purpose/project-scoped lifecycle with
-- the TTL deadline living in the row so the sweeper recomputes on
-- startup. The state machine is CHECK-constrained.
CREATE TABLE lab_leases (
    id             TEXT PRIMARY KEY,
    template_version_id TEXT NOT NULL,
    owner          TEXT NOT NULL,
    purpose        TEXT NOT NULL,
    project_id     TEXT,
    state          TEXT NOT NULL CHECK (state IN (
                       'requested', 'queued', 'reserving', 'provisioning',
                       'booting', 'ready', 'releasing', 'released',
                       'failed', 'cleanup_failed')),
    provision_id   TEXT,
    cleanup        TEXT NOT NULL CHECK (cleanup IN ('destroy', 'revert', 'keep')),
    created_at     INTEGER NOT NULL,
    ready_at       INTEGER,
    expires_at     INTEGER,
    cleanup_attempts INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX lab_leases_created ON lab_leases (created_at DESC);
CREATE INDEX lab_leases_expires ON lab_leases (expires_at) WHERE expires_at IS NOT NULL;
