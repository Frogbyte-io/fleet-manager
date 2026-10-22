-- #493 (ADR 0017): agent SSH access with Fleet-held keys.
--
-- `machine_endpoint_auth` records an SSH endpoint's default authentication,
-- so callers need not repeat it. It holds a kind and a reference only: the
-- identity file's path, or the opaque id of a secret record in the encrypted
-- store. A private key is never in this database outside that store. The row
-- goes away with its endpoint.
CREATE TABLE machine_endpoint_auth (
    endpoint_id TEXT PRIMARY KEY REFERENCES machine_endpoints (id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('agent', 'identityFile', 'secret')),
    reference   TEXT,
    updated_at  INTEGER NOT NULL,
    CHECK (
        (kind = 'agent' AND reference IS NULL)
        OR (kind <> 'agent' AND reference IS NOT NULL AND length(reference) BETWEEN 1 AND 1024)
    )
) STRICT;

-- Files collected from machines. SQLite keeps each file's metadata and
-- digest; the bytes live in the controller's artifact directory at
-- `location` (store-relative, content-addressed by sha256), shared with Lab
-- artifacts, so a blob is deleted only when no record in either table still
-- points at it. `machine_id` is a recorded fact, not a foreign key: a deleted
-- machine's files are removed by the retention pass, not by a cascade that
-- would orphan their blobs.
CREATE TABLE machine_files (
    id           TEXT PRIMARY KEY,
    machine_id   TEXT NOT NULL,
    owner        TEXT NOT NULL,
    name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 1024),
    size_bytes   INTEGER NOT NULL CHECK (size_bytes >= 0),
    sha256       TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    location     TEXT NOT NULL CHECK (location = 'sha256/' || substr(sha256, 1, 2) || '/' || sha256),
    operation_id TEXT,
    created_at   INTEGER NOT NULL,
    retain_until INTEGER NOT NULL
) STRICT;

CREATE INDEX machine_files_machine ON machine_files (machine_id, created_at DESC);
CREATE INDEX machine_files_retention ON machine_files (retain_until);
CREATE INDEX machine_files_location ON machine_files (location);
