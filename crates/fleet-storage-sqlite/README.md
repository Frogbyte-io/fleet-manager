# fleet-storage-sqlite

The controller's SQLite persistence adapter: connection policy, migrations,
the singleton lock, metadata helpers, write transactions, and backups.

## Runtime policy

- **WAL journal mode** with `SYNCHRONOUS = NORMAL`: durable under the
  single-controller constraint without an fsync per commit.
- **Foreign keys are ON** for every connection.
- **Busy timeout is 5 s**: writers queue briefly under bursts, then fail
  loudly instead of hanging.
- **Pool of 4 connections**: SQLite serializes writes itself; a larger pool
  adds reader concurrency only.
- **All tables are `STRICT`**: column types are enforced by the database.

## The single-controller lock

Only one controller may operate on a database. The lock is an OS-level
exclusive lock on the file `<database>.lock`, held open for the life of the
`Store`. The kernel releases it automatically if the process dies, so a crash
never wedges the next startup behind a stale holder; the `controller_lock`
table records durable evidence of who held it last.

A second controller's `Store::open` fails with `LockHeld` before it writes
anything, including migrations.

## Write transactions

Under WAL, a transaction that reads first and writes later fails immediately
with `SQLITE_BUSY_SNAPSHOT` when another writer committed in between. The
store therefore exposes [`Store::begin_write`] (plain `BEGIN IMMEDIATE`);
repositories that write must use it rather than a plain `BEGIN`. The busy
timeout makes contention wait-and-succeed instead of fail-fast.

## Backups

`Store::backup_to(path)` writes a consistent snapshot with SQLite's online
backup (`VACUUM INTO`) while the controller stays live. The target must not
already exist; the API refuses to overwrite an operator file.

Restore procedure:

1. Stop the controller (it must not run while the database is swapped).
2. Replace the database file with the backup copy and remove any stale
   `-wal` / `-shm` sidecar files belonging to the old database.
3. Start the controller; migrations verify the restored schema before
   readiness.

The backup file is itself a working SQLite database, which the integration
test proves by opening it as a `Store`.

## Local-filesystem constraint

SQLite requires the database on a local filesystem with correct POSIX locking
semantics. Network filesystems (NFS, SMB, FUSE-over-object-storage) and
container volume drivers that do not honor these locks are unsupported: the
single-controller lock silently degrades on them. Run the controller with its
state on a local disk or a bind mount onto one; this is why the Compose
deployment uses a local named volume.
