-- FM-718: lease project linkage. The lease's `project_id` becomes a real
-- foreign key so deleting a project nulls the leases that served it.
-- `lab_leases` already carried a plain `project_id` column since 0022 and
-- SQLite cannot add a REFERENCES constraint to an existing column in
-- place, so the table is rebuilt with the constraint and the rows copied.
CREATE TABLE lab_leases_new (
    id             TEXT PRIMARY KEY,
    template_version_id TEXT NOT NULL,
    owner          TEXT NOT NULL,
    purpose        TEXT NOT NULL,
    project_id     TEXT REFERENCES projects(id) ON DELETE SET NULL,
    state          TEXT NOT NULL CHECK (state IN (
                       'requested', 'queued', 'reserving', 'provisioning',
                       'booting', 'bootstrapping', 'ready', 'releasing',
                       'released', 'failed', 'cleanup_failed')),
    provision_id   TEXT,
    cleanup        TEXT NOT NULL CHECK (cleanup IN ('destroy', 'revert', 'keep')),
    created_at     INTEGER NOT NULL,
    ready_at       INTEGER,
    expires_at     INTEGER,
    max_lifetime_at INTEGER,
    ttl_seconds    INTEGER NOT NULL DEFAULT 3600 CHECK (ttl_seconds > 0),
    cleanup_attempts INTEGER NOT NULL DEFAULT 0
) STRICT;

INSERT INTO lab_leases_new
    (id, template_version_id, owner, purpose, project_id, state, provision_id,
     cleanup, created_at, ready_at, expires_at, max_lifetime_at, ttl_seconds,
     cleanup_attempts)
SELECT id, template_version_id, owner, purpose, project_id, state, provision_id,
       cleanup, created_at, ready_at, expires_at, max_lifetime_at, ttl_seconds,
       cleanup_attempts
FROM lab_leases;

DROP TABLE lab_leases;

ALTER TABLE lab_leases_new RENAME TO lab_leases;

CREATE INDEX lab_leases_created ON lab_leases (created_at DESC);
CREATE INDEX lab_leases_expires ON lab_leases (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX lab_leases_project ON lab_leases (project_id) WHERE project_id IS NOT NULL;
