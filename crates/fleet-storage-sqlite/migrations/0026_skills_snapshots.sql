-- Skills topology is sensitive and must not share general machine capability reads.
CREATE TABLE skills_snapshots (
    machine_id TEXT PRIMARY KEY REFERENCES machines(id) ON DELETE CASCADE,
    availability TEXT NOT NULL CHECK (availability IN ('available', 'absent', 'unsupported')),
    cli_version TEXT,
    data_json TEXT NOT NULL,
    update_check TEXT NOT NULL,
    observed_at INTEGER NOT NULL
) STRICT;
