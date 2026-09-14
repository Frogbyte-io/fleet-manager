-- Projects (FM-300): stable identity keyed by the normalized Git remote.
-- The remote is the identity; checkouts are per-machine observed facts in
-- their own table and never part of the identity. Deleting a project
-- cascades to its checkouts — Fleet forgets a project, it never touches the
-- repositories themselves.

CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    remote TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE project_checkouts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    machine_id TEXT NOT NULL,
    root TEXT NOT NULL,
    branch TEXT,
    dirty INTEGER,
    source TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    UNIQUE (project_id, machine_id, root)
);

CREATE INDEX idx_project_checkouts_project ON project_checkouts (project_id, observed_at DESC);
