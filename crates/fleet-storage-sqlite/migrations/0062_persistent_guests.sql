-- #489: permanent, Fleet-managed VMs. A row here is the explicit
-- "persistent" marker: Fleet keeps this guest, and Lab sweeps, pool fills
-- and Lab cleanup never select it, whatever its name. The row is written
-- before the clone, so a creation that stopped part-way is found and
-- resumed by its (account, VMID, name) instead of cloning twice. It holds
-- identifiers and progress only; no key or secret.
CREATE TABLE persistent_guests (
    account_id       TEXT NOT NULL,
    vmid             INTEGER NOT NULL CHECK (vmid BETWEEN 100 AND 999999999),
    name             TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 63),
    node             TEXT NOT NULL CHECK (length(node) BETWEEN 1 AND 128),
    image_version_id TEXT NOT NULL,
    machine_id       TEXT,
    state            TEXT NOT NULL CHECK (state IN ('creating', 'ready')),
    step             TEXT,
    operation_id     TEXT,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    PRIMARY KEY (account_id, vmid)
) STRICT;

CREATE UNIQUE INDEX persistent_guests_name ON persistent_guests (account_id, name);
CREATE INDEX persistent_guests_created ON persistent_guests (created_at DESC);
