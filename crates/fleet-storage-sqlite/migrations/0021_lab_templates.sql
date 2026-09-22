-- FM-710: Lab templates (drafts + immutable versions with provenance) and
-- the provisioning saga's durable records. The image pin references a
-- promoted image version; the pin's promotion is validated at the
-- application boundary.
CREATE TABLE lab_templates (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    description    TEXT NOT NULL DEFAULT '',
    image_version_id TEXT NOT NULL,
    cores          INTEGER NOT NULL,
    memory_mib     INTEGER NOT NULL,
    disk_gib       INTEGER NOT NULL,
    bootstrap_project_id TEXT,
    readiness_probe TEXT NOT NULL,
    readiness_command TEXT,
    readiness_deadline_seconds INTEGER NOT NULL,
    ttl_seconds    INTEGER NOT NULL,
    cleanup        TEXT NOT NULL,
    published_from TEXT,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;

CREATE TABLE lab_template_versions (
    id             TEXT PRIMARY KEY,
    template_id    TEXT NOT NULL,
    name           TEXT NOT NULL,
    content        TEXT NOT NULL,
    image_digest   TEXT NOT NULL,
    published_by   TEXT NOT NULL,
    published_at   INTEGER NOT NULL
) STRICT;

CREATE INDEX lab_template_versions_template
    ON lab_template_versions (template_id, published_at DESC);

CREATE TABLE lab_provisions (
    id             TEXT PRIMARY KEY,
    template_version_id TEXT NOT NULL,
    state          TEXT NOT NULL,
    node           TEXT,
    vmid           INTEGER,
    clone_upid     TEXT,
    guest_ipv4     TEXT,
    ready_at       INTEGER,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;

CREATE INDEX lab_provisions_created ON lab_provisions (created_at DESC);
