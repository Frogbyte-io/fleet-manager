-- FM-1030: the latest Coolify discovery snapshot of an external account.
-- One row per account. `snapshot` is the bounded JSON of the allow-listed,
-- translated resources with per-class attempt and success stamps; it never
-- carries provider-private fields, credentials, or response bodies.
-- `recorded_at` is when the row was last written (epoch millis). The row
-- goes with its account.
CREATE TABLE coolify_observations (
    account_id  TEXT PRIMARY KEY REFERENCES external_accounts (id) ON DELETE CASCADE,
    snapshot    TEXT NOT NULL,
    recorded_at INTEGER NOT NULL
) STRICT;
