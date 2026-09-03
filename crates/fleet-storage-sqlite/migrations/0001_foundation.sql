-- The controller's foundation schema. Everything is STRICT so the type of
-- every column is enforced at write time, and every table records facts, not
-- interpretations: desired-state interpretation belongs to the domain layer.

-- Small key/value facts about the runtime database itself: controller
-- instance identity, feature flags, and bookkeeping the controller owns.
CREATE TABLE schema_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- A row records that this controller instance accepted the singleton
-- responsibility most recently. Ownership is enforced at runtime by an OS
-- file lock beside the database file (see crates/fleet-storage-sqlite/README.md);
-- this row is the durable evidence of who held it, which survives the
-- automatic kernel release that follows a crash.
CREATE TABLE controller_lock (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    instance_id TEXT NOT NULL,
    acquired_at INTEGER NOT NULL
) STRICT;
