-- FM-1012: the Registry read model (ADR 0016). Every registry_* table below
-- is a rebuildable cache derived from the active revision's resource
-- snapshot (source_revision_resources); it is never a second authority and
-- holds no data the snapshot does not. registry_cache_state names the
-- revision the cache mirrors, so a reader can tell a stale cache from a
-- current one and rebuild it. Deleting these rows is always safe.
--
-- Entry keys are unique case-insensitively (FM-1010), so every key and every
-- registry-class target is stored twice: as written, for display, and
-- lowercased (`*_norm`), which lookups, joins, and cursors use.

-- The repository-relative file each snapshot resource came from, for edit
-- links. Snapshots recorded before this column exist keep NULL until a
-- repeat fetch of the same revision supplies the path: a path is not content,
-- so that fetch may fill a NULL (and only a NULL) in place.
ALTER TABLE source_revision_resources ADD COLUMN source_path TEXT;

DROP TRIGGER source_revision_resources_no_update;
CREATE TRIGGER source_revision_resources_no_update
    BEFORE UPDATE ON source_revision_resources
    WHEN NOT (
        OLD.source_path IS NULL
        AND NEW.source_path IS NOT NULL
        AND NEW.commit_sha = OLD.commit_sha
        AND NEW.content_digest = OLD.content_digest
        AND NEW.resource_id = OLD.resource_id
        AND NEW.kind = OLD.kind
        AND NEW.name = OLD.name
        AND NEW.spec_json = OLD.spec_json
    )
BEGIN
    SELECT RAISE(ABORT, 'source_revision_resources is append-only');
END;

CREATE TABLE registry_cache_state (
    singleton           TEXT PRIMARY KEY CHECK (singleton = 'cache'),
    commit_sha          TEXT NOT NULL,
    content_digest      TEXT NOT NULL,
    builtin_fingerprint TEXT NOT NULL,
    built_at            INTEGER NOT NULL
) STRICT;

CREATE TABLE registry_types (
    name           TEXT PRIMARY KEY,
    origin         TEXT NOT NULL CHECK (origin IN ('builtin', 'repository')),
    resource_id    TEXT,
    display_name   TEXT NOT NULL,
    key_field      TEXT NOT NULL,
    relations_json TEXT NOT NULL,
    spec_json      TEXT NOT NULL,
    source_path    TEXT
) STRICT;

CREATE TABLE registry_entries (
    entry_type     TEXT NOT NULL,
    entry_key      TEXT NOT NULL,
    entry_key_norm TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    name           TEXT NOT NULL,
    fields_json    TEXT NOT NULL,
    tags_json      TEXT NOT NULL,
    links_json     TEXT NOT NULL,
    notes          TEXT,
    source_path    TEXT,
    search_text    TEXT NOT NULL,
    PRIMARY KEY (entry_type, entry_key_norm)
) STRICT;

CREATE TABLE registry_entry_tags (
    entry_type     TEXT NOT NULL,
    entry_key_norm TEXT NOT NULL,
    tag            TEXT NOT NULL,
    PRIMARY KEY (entry_type, entry_key_norm, tag),
    FOREIGN KEY (entry_type, entry_key_norm)
        REFERENCES registry_entries (entry_type, entry_key_norm) ON DELETE CASCADE
) STRICT;

CREATE INDEX registry_entry_tags_by_tag
    ON registry_entry_tags (tag, entry_type, entry_key_norm);

CREATE TABLE registry_relations (
    entry_type      TEXT NOT NULL,
    entry_key_norm  TEXT NOT NULL,
    relation_type   TEXT NOT NULL,
    target_class    TEXT NOT NULL
        CHECK (target_class IN ('registry', 'machine', 'project', 'coolify', 'proxmoxGuest')),
    target_ref      TEXT NOT NULL,
    target_ref_norm TEXT NOT NULL,
    PRIMARY KEY (entry_type, entry_key_norm, relation_type, target_class, target_ref_norm),
    FOREIGN KEY (entry_type, entry_key_norm)
        REFERENCES registry_entries (entry_type, entry_key_norm) ON DELETE CASCADE
) STRICT;

-- The reverse lookup: what points at this target.
CREATE INDEX registry_relations_by_target
    ON registry_relations (target_class, target_ref_norm, entry_type, entry_key_norm, relation_type);
