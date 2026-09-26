CREATE TABLE skill_catalog_entries (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    content_json TEXT NOT NULL,
    published_from TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE skill_catalog_versions (
    id TEXT PRIMARY KEY NOT NULL,
    catalog_id TEXT NOT NULL REFERENCES skill_catalog_entries(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    content_json TEXT NOT NULL,
    published_at INTEGER NOT NULL,
    UNIQUE(catalog_id, content_digest)
) STRICT;

CREATE INDEX skill_catalog_versions_entry ON skill_catalog_versions(catalog_id, published_at DESC);
