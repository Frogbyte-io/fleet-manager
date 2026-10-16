-- FM-1042: DNS records Fleet last read through a Cloudflare account, kept as
-- observations beside the Registry. An observation never changes a Registry
-- entry: `registry_entry` only names the `domain/<key>` entry the records
-- matched when they were read. Rows are replaced per account, zone, and name
-- on each read, and removed with their account. Record data is public DNS
-- content; no token or credential lives here.
CREATE TABLE dns_record_observations (
    account_id     TEXT NOT NULL REFERENCES external_accounts (id) ON DELETE CASCADE,
    record_id      TEXT NOT NULL,
    zone_id        TEXT NOT NULL,
    zone_name      TEXT NOT NULL,
    name           TEXT NOT NULL,
    record_type    TEXT NOT NULL,
    content        TEXT NOT NULL,
    ttl            INTEGER NOT NULL,
    proxied        INTEGER NOT NULL CHECK (proxied IN (0, 1)),
    priority       INTEGER,
    registry_entry TEXT,
    observed_at    INTEGER NOT NULL,
    PRIMARY KEY (account_id, record_id)
) STRICT;

CREATE INDEX dns_record_observations_name ON dns_record_observations (name, record_type);
CREATE INDEX dns_record_observations_registry ON dns_record_observations (registry_entry)
    WHERE registry_entry IS NOT NULL;
