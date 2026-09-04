-- Machines and their mutable facts. The machine's id is its identity; the
-- name is a mutable label, and endpoints/observations/capabilities are facts
-- about how the machine is reached and what it looks like right now.
--
-- STRICT everywhere; foreign keys are enforced by the store's connection
-- policy, so deleting a machine removes its facts by cascade.

CREATE TABLE machines (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE machine_endpoints (
    id         TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('ssh', 'fleetd')),
    -- user@host:port or node id; never a secret.
    reference  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (machine_id, kind, reference)
) STRICT;

CREATE TABLE inventory_snapshots (
    id           TEXT PRIMARY KEY,
    machine_id   TEXT NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    -- What observed it, e.g. "agentless/1" or "fleetd/1.2.3".
    source       TEXT NOT NULL,
    collected_at INTEGER NOT NULL,
    payload_json TEXT NOT NULL
) STRICT;

CREATE INDEX inventory_snapshots_machine ON inventory_snapshots (machine_id, collected_at DESC);

CREATE TABLE machine_capabilities (
    machine_id  TEXT NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    namespace   TEXT NOT NULL,
    name        TEXT NOT NULL,
    value       TEXT,
    status      TEXT NOT NULL CHECK (status IN ('known', 'unknown', 'unavailable', 'stale')),
    observed_at INTEGER NOT NULL,
    source      TEXT NOT NULL,
    PRIMARY KEY (machine_id, namespace, name)
) STRICT;

CREATE TABLE tags (
    id   TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE machine_tags (
    machine_id TEXT NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    tag_id     TEXT NOT NULL REFERENCES tags (id) ON DELETE CASCADE,
    PRIMARY KEY (machine_id, tag_id)
) STRICT;

CREATE TABLE machine_groups (
    machine_id TEXT NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    group_name TEXT NOT NULL,
    PRIMARY KEY (machine_id, group_name)
) STRICT;
