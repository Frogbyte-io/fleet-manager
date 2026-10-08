-- FM-721: Lab artifacts. SQLite keeps each artifact's metadata and digest;
-- the bytes live in the controller's artifact directory at `location`
-- (store-relative, content-addressed by sha256), never in this database.
-- Artifacts outlive their lease until `retain_until`, when the Lab sweeper
-- deletes them. `project_id` is a recorded fact, not a foreign key: a
-- deleted project must not take its artifacts' history with it.
CREATE TABLE lab_artifacts (
    id            TEXT PRIMARY KEY,
    lease_id      TEXT NOT NULL REFERENCES lab_leases (id),
    project_id    TEXT,
    owner         TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('exec-log', 'file')),
    name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 1024),
    size_bytes    INTEGER NOT NULL CHECK (size_bytes >= 0),
    sha256        TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    location      TEXT NOT NULL CHECK (location = 'sha256/' || substr(sha256, 1, 2) || '/' || sha256),
    operation_id  TEXT,
    created_at    INTEGER NOT NULL,
    retain_until  INTEGER NOT NULL
) STRICT;

CREATE INDEX lab_artifacts_lease ON lab_artifacts (lease_id, created_at DESC);
CREATE INDEX lab_artifacts_project ON lab_artifacts (project_id, created_at DESC)
    WHERE project_id IS NOT NULL;
CREATE INDEX lab_artifacts_retention ON lab_artifacts (retain_until);
CREATE INDEX lab_artifacts_location ON lab_artifacts (location);

-- The last failed collection of each lease: recorded beside the lease,
-- never on it, so a failed collection cannot change the lease's lifecycle
-- or hold up its cleanup.
CREATE TABLE lab_artifact_collection_failures (
    lease_id      TEXT PRIMARY KEY REFERENCES lab_leases (id),
    operation_id  TEXT NOT NULL,
    reason        TEXT NOT NULL,
    detail        TEXT NOT NULL,
    failed_at     INTEGER NOT NULL
) STRICT;
