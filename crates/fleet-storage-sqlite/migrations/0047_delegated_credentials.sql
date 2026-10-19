-- #392 (ADR 0011): delegated, scoped, short-lived credentials for CI and
-- agents. Only the SHA-256 of the bearer token is stored, never the token.
-- The allow-list names Lab template ids and template version ids as JSON
-- arrays. A credential is usable while `revoked_at` is NULL and `expires_at`
-- is in the future; both are checked on every request.
CREATE TABLE delegated_credentials (
    id          TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    token_hash  TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    owner       TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 63),
    label       TEXT NOT NULL DEFAULT '' CHECK (length(label) <= 512),
    templates   TEXT NOT NULL DEFAULT '[]',
    versions    TEXT NOT NULL DEFAULT '[]',
    issued_by   TEXT NOT NULL,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked_at  INTEGER,
    revoked_by  TEXT
);

CREATE INDEX delegated_credentials_owner ON delegated_credentials (owner);
