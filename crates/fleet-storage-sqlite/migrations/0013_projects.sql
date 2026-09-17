-- Projects (FM-300): stable identity keyed by the normalized Git remote.
-- The remote is the identity; checkouts are per-machine observed facts in
-- their own table and never part of the identity. Deleting a project
-- cascades to its checkouts — Fleet forgets a project, it never touches the
-- repositories themselves. Deleting a machine cascades to its checkout
-- observations: a machine that is gone has no checkouts to observe.

CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    remote TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX idx_projects_idempotency
    ON projects (idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE project_checkouts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    machine_id TEXT NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    root TEXT NOT NULL,
    branch TEXT,
    dirty INTEGER CHECK (dirty IN (0, 1)),
    source TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    UNIQUE (project_id, machine_id, root)
) STRICT;

CREATE INDEX idx_project_checkouts_project ON project_checkouts (project_id, observed_at DESC);
