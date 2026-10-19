-- FM-715: Lab placement and transactional capacity reservation.
--
-- The latest Proxmox node capacity observation, per account and node. The
-- provision executor refreshes it right before it reserves; the reservation
-- transaction refuses an observation older than the configured age.
CREATE TABLE lab_capacity_observations (
    account_id         TEXT NOT NULL,
    node               TEXT NOT NULL CHECK (length(node) BETWEEN 1 AND 128),
    cpu_count          INTEGER CHECK (cpu_count IS NULL OR cpu_count >= 0),
    memory_total_bytes INTEGER CHECK (memory_total_bytes IS NULL OR memory_total_bytes >= 0),
    memory_used_bytes  INTEGER CHECK (memory_used_bytes IS NULL OR memory_used_bytes >= 0),
    -- The per-storage capacity as a JSON array of {storage, usedBytes, totalBytes}.
    storages_json      TEXT NOT NULL CHECK (json_valid(storages_json) AND json_type(storages_json) = 'array'),
    observed_at        INTEGER NOT NULL,
    PRIMARY KEY (account_id, node)
) STRICT;

-- One capacity reservation per lease. A held reservation counts against its
-- node (and, for disk, its storage pool on the node) until it is released;
-- a released row stays as history and can never be held again. The lease's
-- own state is authoritative: a held row whose lease is `released`, or
-- `failed` without an allocated VMID, no longer counts, so a lost release
-- write can never strand capacity.
CREATE TABLE lab_capacity_reservations (
    id          TEXT PRIMARY KEY,
    lease_id    TEXT NOT NULL UNIQUE REFERENCES lab_leases(id) ON DELETE CASCADE,
    account_id  TEXT NOT NULL,
    node        TEXT NOT NULL CHECK (length(node) BETWEEN 1 AND 128),
    storage     TEXT NOT NULL CHECK (length(storage) BETWEEN 1 AND 128),
    cores       INTEGER NOT NULL CHECK (cores > 0),
    memory_mib  INTEGER NOT NULL CHECK (memory_mib > 0),
    disk_gib    INTEGER NOT NULL CHECK (disk_gib > 0),
    state       TEXT NOT NULL CHECK (state IN ('held', 'released')),
    created_at  INTEGER NOT NULL,
    released_at INTEGER,
    CHECK ((state = 'released') = (released_at IS NOT NULL))
) STRICT;

CREATE INDEX lab_capacity_reservations_held
    ON lab_capacity_reservations (node, storage) WHERE state = 'held';
