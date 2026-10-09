-- #394: detached Lab commands. One row per handle (the id of the
-- `lab.exec_detach` operation that started it). The command text is never
-- stored here: only its SHA-256 and size. The process itself lives in the
-- guest; this row is what lets a restarted controller, or any caller with
-- the handle, find it again.
CREATE TABLE lab_detached_execs (
    handle TEXT PRIMARY KEY,
    lease_id TEXT NOT NULL,
    -- The lease's owner, for owner scoping.
    owner TEXT NOT NULL,
    command_sha256 TEXT NOT NULL,
    command_bytes INTEGER NOT NULL,
    -- The bound the wrapper enforces, never past the lease's TTL.
    timeout_seconds INTEGER NOT NULL,
    start_state TEXT NOT NULL CHECK (start_state IN ('starting', 'started', 'failed')),
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    -- The scrubbed, bounded terminal answer (exited or lost), so later polls
    -- do not dial the guest.
    final_json TEXT
);
CREATE INDEX lab_detached_execs_lease ON lab_detached_execs (lease_id);
