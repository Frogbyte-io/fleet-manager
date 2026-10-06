-- no-transaction

-- FM-718: lease project linkage. The lease's `project_id` becomes a real
-- foreign key so deleting a project nulls the leases that served it.
-- `lab_leases` already carried a plain `project_id` column since 0022 and
-- SQLite cannot add a REFERENCES constraint to an existing column in
-- place, so the table is rebuilt with the constraint and the rows copied.
--
-- This rebuild follows SQLite's documented 12-step table-rebuild
-- procedure. (https://sqlite.org/lang_altertable.html#otherbez)
--
-- Step 1 — disable foreign key enforcement for the rebuild:
PRAGMA foreign_keys=OFF;
--
-- `DROP TABLE lab_leases` would fail while 0025's
--    `lab_provisions.lease_id REFERENCES lab_leases(id)` rows exist, and
--    the copy would fail on leases still pointing at projects deleted
--    before this migration ran.
-- Step 2 — null legacy orphaned `project_id` values during the copy: the
--    plain column since 0022 never enforced existence, so rows can point
--    at projects deleted before this PR; the copy keeps only ids that
--    still exist in `projects`.
--
-- The migration runs outside a transaction (`-- no-transaction`) because
-- PRAGMA foreign_keys is a no-op inside one. Operational mitigation: the
-- copy and index rebuilds run at startup before the controller serves any
-- traffic (the singleton lock in `Store::open` serializes start against
-- other controllers), the runtime is bounded by the lease-row count, and
-- WAL journaling keeps the local file consistent — but the DDL is not
-- transactional, so an operator must take a database backup before
-- applying this build (the controller's `backup_to` / planned-backup
-- procedure) and restore it if this migration half-applies, leaving
-- `lab_leases_new` behind.
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
SELECT
    id, template_version_id, owner, purpose,
    CASE
        WHEN project_id IS NOT NULL
             AND EXISTS (SELECT 1 FROM projects WHERE projects.id = lab_leases.project_id)
        THEN project_id
        ELSE NULL
    END,
    state, provision_id, cleanup, created_at, ready_at, expires_at,
    max_lifetime_at, ttl_seconds, cleanup_attempts
FROM lab_leases;

DROP TABLE lab_leases;

ALTER TABLE lab_leases_new RENAME TO lab_leases;

CREATE INDEX lab_leases_created ON lab_leases (created_at DESC);
CREATE INDEX lab_leases_expires ON lab_leases (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX lab_leases_project ON lab_leases (project_id) WHERE project_id IS NOT NULL;

-- Step N — restore foreign key enforcement on this connection, then
-- diagnose: `PRAGMA foreign_key_check` reports any residual violation
-- (an empty answer on this schema by construction).

PRAGMA foreign_keys=ON;

PRAGMA foreign_key_check;

-- Hard re-validation: under FK enforcement, touching the FK column makes
-- SQLite re-check every row's `project_id` against `projects` and aborts
-- the migration on any violation. It passes by construction (every copied
-- id was validated against `projects` and the provision links were
-- untouched); a failure here means the copy itself was broken, the data
-- must be restored from the pre-migration backup, and the controller
-- refused to start with it.
UPDATE lab_leases SET project_id = project_id;
