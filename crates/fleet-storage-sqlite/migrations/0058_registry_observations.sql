-- FM-1020: RDAP and DNS observations recorded against Registry domain
-- entries (ADR 0016 point 9). Observations attach beside an entry and never
-- overwrite Fleet Git. Unlike the registry_* cache tables (0054) these rows
-- are NOT derived from the revision snapshot: they are the only copy of what
-- the public lookups saw, but they are disposable (a new lookup replaces
-- them) and hold no secret, only public registration and DNS data.
--
-- One row per entry, the latest observation. The key is the entry's natural
-- key, unique case-insensitively (FM-1010), so the lowercased form is the
-- primary key and the key as written is kept for display.
CREATE TABLE registry_observations (
    entry_type     TEXT NOT NULL,
    entry_key_norm TEXT NOT NULL,
    entry_key      TEXT NOT NULL,
    observed_at    INTEGER NOT NULL,
    observation_json TEXT NOT NULL,
    PRIMARY KEY (entry_type, entry_key_norm)
) STRICT;
