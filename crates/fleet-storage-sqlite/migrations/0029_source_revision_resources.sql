-- FM-404: the validated resources of each valid desired revision. A
-- rebuildable cache of the Git revision (docs/architecture/desired-state.md),
-- not a second desired-state authority. A snapshot row proves the revision's
-- resources are held even when there are none; snapshots are immutable
-- because a content digest names its content.
CREATE TABLE source_revision_snapshots (
    commit_sha     TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    resource_count INTEGER NOT NULL,
    recorded_at    INTEGER NOT NULL,
    PRIMARY KEY (commit_sha, content_digest)
) STRICT;

CREATE TABLE source_revision_resources (
    commit_sha     TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    kind           TEXT NOT NULL,
    name           TEXT NOT NULL,
    spec_json      TEXT NOT NULL,
    PRIMARY KEY (commit_sha, content_digest, resource_id),
    FOREIGN KEY (commit_sha, content_digest)
        REFERENCES source_revision_snapshots (commit_sha, content_digest)
) STRICT;

CREATE INDEX source_revision_resources_kind
    ON source_revision_resources (commit_sha, content_digest, kind, resource_id);

CREATE TRIGGER source_revision_snapshots_no_update
    BEFORE UPDATE ON source_revision_snapshots
BEGIN
    SELECT RAISE(ABORT, 'source_revision_snapshots is append-only');
END;

CREATE TRIGGER source_revision_snapshots_no_delete
    BEFORE DELETE ON source_revision_snapshots
BEGIN
    SELECT RAISE(ABORT, 'source_revision_snapshots is append-only');
END;

CREATE TRIGGER source_revision_resources_no_update
    BEFORE UPDATE ON source_revision_resources
BEGIN
    SELECT RAISE(ABORT, 'source_revision_resources is append-only');
END;

CREATE TRIGGER source_revision_resources_no_delete
    BEFORE DELETE ON source_revision_resources
BEGIN
    SELECT RAISE(ABORT, 'source_revision_resources is append-only');
END;
