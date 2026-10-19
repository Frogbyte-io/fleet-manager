-- FM-1001: external provider accounts for API-token providers (Coolify,
-- Cloudflare). The token never lives here: it is an encrypted secret record
-- named `external/<id>`. `last_probe` is the bounded JSON of the latest
-- classified probe (status, redacted detail, permission lists, time); it
-- never carries credential material.
CREATE TABLE external_accounts (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('coolify', 'cloudflare')),
    label       TEXT NOT NULL,
    base_url    TEXT NOT NULL,
    scope_id    TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    last_probe  TEXT,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE (kind, label)
) STRICT;

CREATE INDEX external_accounts_created ON external_accounts (created_at DESC);
