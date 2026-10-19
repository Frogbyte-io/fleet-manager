-- FM-717: pooled Lab guests.
--
-- A pool binds a small set of operator-supplied QEMU guests to one
-- published template version. Fleet never creates or destroys a member:
-- fill registers it, cleanup reverts it to the baseline snapshot, drain
-- releases it from Lab.
CREATE TABLE lab_pools (
    id                  TEXT PRIMARY KEY,
    template_version_id TEXT NOT NULL UNIQUE,
    account_id          TEXT NOT NULL,
    baseline_snapshot   TEXT NOT NULL CHECK (length(baseline_snapshot) BETWEEN 2 AND 40),
    size                INTEGER NOT NULL CHECK (size BETWEEN 1 AND 16),
    created_by          TEXT NOT NULL,
    created_at          INTEGER NOT NULL
) STRICT;

-- One row per member guest. A guest (account and VMID) belongs to at most
-- one pool, and a lease is bound to at most one member while a member is
-- bound to at most one lease: the partial unique index on lease_id makes
-- a shared member impossible, whatever the application does.
CREATE TABLE lab_pool_members (
    id         TEXT PRIMARY KEY,
    pool_id    TEXT NOT NULL REFERENCES lab_pools(id),
    account_id TEXT NOT NULL,
    vmid       INTEGER NOT NULL CHECK (vmid BETWEEN 100 AND 999999999),
    node       TEXT CHECK (node IS NULL OR length(node) BETWEEN 1 AND 128),
    name       TEXT CHECK (name IS NULL OR length(name) <= 128),
    state      TEXT NOT NULL CHECK (state IN ('filling', 'available', 'leased', 'quarantined')),
    lease_id   TEXT REFERENCES lab_leases(id),
    draining   INTEGER NOT NULL DEFAULT 0 CHECK (draining IN (0, 1)),
    detail     TEXT CHECK (detail IS NULL OR length(detail) <= 1024),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (account_id, vmid),
    -- A leased member always names its lease; a filling or available one
    -- never does. A quarantined member may still be bound (a failed revert
    -- keeps its lease's cleanup owing) or not (kept, or a failed fill).
    CHECK (state <> 'leased' OR lease_id IS NOT NULL),
    CHECK (state NOT IN ('filling', 'available') OR lease_id IS NULL)
) STRICT;

CREATE UNIQUE INDEX lab_pool_members_lease
    ON lab_pool_members (lease_id) WHERE lease_id IS NOT NULL;
CREATE INDEX lab_pool_members_pool ON lab_pool_members (pool_id, state, vmid);
