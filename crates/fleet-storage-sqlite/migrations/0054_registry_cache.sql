-- FM-1012: the Registry read model (ADR 0016). Every table below is a
-- rebuildable cache derived from the active revision's resource snapshot
-- (source_revision_resources); it is never a second authority and holds no
-- data the snapshot does not. registry_cache_state names the revision the
-- cache mirrors, so a reader can tell a stale cache from a current one and
-- rebuild it. Deleting these rows is always safe.

-- The repository-relative file each snapshot resource came from, for edit
-- links. Snapshots recorded before this column exist keep NULL; they are
-- immutable, so the path appears once the revision is fetched again under
-- a new digest.
ALTER TABLE source_revision_resources ADD COLUMN source_path TEXT;

CREATE TABLE registry_cache_state (
    singleton           TEXT PRIMARY KEY CHECK (singleton = 'cache'),
    commit_sha          TEXT NOT NULL,
    content_digest      TEXT NOT NULL,
    builtin_fingerprint TEXT NOT NULL,
    built_at            INTEGER NOT NULL
) STRICT;

CREATE TABLE registry_types (
    name         TEXT PRIMARY KEY,
    origin       TEXT NOT NULL CHECK (origin IN ('builtin', 'repository')),
    resource_id  TEXT,
    display_name TEXT NOT NULL,
    key_field    TEXT NOT NULL,
    relations_json TEXT NOT NULL,
    spec_json    TEXT NOT NULL,
    source_path  TEXT
) STRICT;

CREATE TABLE registry_entries (
    entry_type  TEXT NOT NULL,
    entry_key   TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    name        TEXT NOT NULL,
    fields_json TEXT NOT NULL,
    tags_json   TEXT NOT NULL,
    links_json  TEXT NOT NULL,
    notes       TEXT,
    source_path TEXT,
    search_text TEXT NOT NULL,
    PRIMARY KEY (entry_type, entry_key)
) STRICT;

CREATE TABLE registry_entry_tags (
    entry_type TEXT NOT NULL,
    entry_key  TEXT NOT NULL,
    tag        TEXT NOT NULL,
    PRIMARY KEY (entry_type, entry_key, tag),
    FOREIGN KEY (entry_type, entry_key)
        REFERENCES registry_entries (entry_type, entry_key) ON DELETE CASCADE
) STRICT;

CREATE INDEX registry_entry_tags_by_tag
    ON registry_entry_tags (tag, entry_type, entry_key);

CREATE TABLE registry_relations (
    entry_type    TEXT NOT NULL,
    entry_key     TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    target_class  TEXT NOT NULL
        CHECK (target_class IN ('registry', 'machine', 'project', 'coolify', 'proxmoxGuest')),
    target_ref    TEXT NOT NULL,
    PRIMARY KEY (entry_type, entry_key, relation_type, target_class, target_ref),
    FOREIGN KEY (entry_type, entry_key)
        REFERENCES registry_entries (entry_type, entry_key) ON DELETE CASCADE
) STRICT;

-- The reverse lookup: what points at this target.
CREATE INDEX registry_relations_by_target
    ON registry_relations (target_class, target_ref, entry_type, entry_key, relation_type);
