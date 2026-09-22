-- FM-700: image recipes — drafts plus immutable published versions. The
-- content is the raw Packer template stored verbatim; the digest is the
-- SHA-256 of those bytes and the version's identity component.
CREATE TABLE image_recipes (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    description    TEXT NOT NULL DEFAULT '',
    node           TEXT NOT NULL,
    storage_pool   TEXT NOT NULL,
    source         TEXT NOT NULL,
    content        TEXT NOT NULL,
    published_from TEXT,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;

CREATE TABLE image_recipe_versions (
    id             TEXT PRIMARY KEY,
    recipe_id      TEXT NOT NULL REFERENCES image_recipes (id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    content        TEXT NOT NULL,
    source         TEXT NOT NULL,
    node           TEXT NOT NULL,
    storage_pool   TEXT NOT NULL,
    published_at   INTEGER NOT NULL,
    UNIQUE (recipe_id, content_digest)
) STRICT;

CREATE INDEX image_recipe_versions_recipe ON image_recipe_versions (recipe_id, published_at DESC);
