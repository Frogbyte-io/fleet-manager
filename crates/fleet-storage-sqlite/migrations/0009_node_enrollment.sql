-- Node enrollment and identity (FM-204).
--
-- A node is the fleetd process bound to one machine's identity: an Ed25519
-- public key plus a monotonic key version. Enrollment tokens are stored
-- hashed and single-use; credentials and sessions are durable records the
-- controller re-validates against state, so revocation is storage-backed.
-- Deleting a machine cascades to every node fact about it.

CREATE TABLE node_enrollment_tokens (
    id          TEXT PRIMARY KEY,
    machine_id  TEXT NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    -- The SHA-256 of the token value; the value itself is never stored.
    token_hash  TEXT NOT NULL UNIQUE,
    status      TEXT NOT NULL CHECK (status IN ('pending', 'consumed')),
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    consumed_at INTEGER
) STRICT;

CREATE INDEX node_enrollment_tokens_machine
    ON node_enrollment_tokens (machine_id, created_at DESC);

CREATE TABLE node_identities (
    -- One identity per machine: the node binds to the machine's identity.
    machine_id   TEXT PRIMARY KEY REFERENCES machines (id) ON DELETE CASCADE,
    -- Hex-encoded 32-byte Ed25519 public key.
    public_key   TEXT NOT NULL,
    -- Monotonic version, bumped by rotation and re-enrollment after
    -- revocation; credentials record the version they were bound to.
    key_version  INTEGER NOT NULL CHECK (key_version >= 1),
    status       TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    os           TEXT NOT NULL DEFAULT '',
    arch         TEXT NOT NULL DEFAULT '',
    node_version TEXT NOT NULL DEFAULT '',
    enrolled_at  INTEGER NOT NULL,
    rotated_at   INTEGER
) STRICT;

CREATE TABLE node_credentials (
    id              TEXT PRIMARY KEY,
    machine_id      TEXT NOT NULL REFERENCES node_identities (machine_id) ON DELETE CASCADE,
    -- The node key version this credential was bound to at issuance.
    key_version     INTEGER NOT NULL CHECK (key_version >= 1),
    issued_at       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    last_used_at    INTEGER
) STRICT;

CREATE INDEX node_credentials_machine
    ON node_credentials (machine_id, status, expires_at DESC);

CREATE TABLE node_sessions (
    id            TEXT PRIMARY KEY,
    machine_id    TEXT NOT NULL REFERENCES node_identities (machine_id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL REFERENCES node_credentials (id) ON DELETE CASCADE,
    issued_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('active', 'revoked'))
) STRICT;

CREATE INDEX node_sessions_machine ON node_sessions (machine_id, status, expires_at DESC);

CREATE TABLE node_challenges (
    id             TEXT PRIMARY KEY,
    machine_id     TEXT NOT NULL REFERENCES node_identities (machine_id) ON DELETE CASCADE,
    -- Hex-encoded CSPRNG nonce; single use.
    nonce          TEXT NOT NULL,
    purpose        TEXT NOT NULL CHECK (purpose IN ('session', 'rotate')),
    -- For rotate challenges, the new public key the proof must bind.
    new_public_key TEXT,
    issued_at      INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    consumed_at    INTEGER
) STRICT;
