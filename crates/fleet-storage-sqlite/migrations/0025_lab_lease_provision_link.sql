-- FM-931: preserve the template TTL on each lease and attach the existing
-- provisioning saga to exactly one lease when provisioned from the lease API.
ALTER TABLE lab_leases
    ADD COLUMN ttl_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (ttl_seconds > 0);

ALTER TABLE lab_provisions
    ADD COLUMN lease_id TEXT REFERENCES lab_leases(id);

CREATE UNIQUE INDEX lab_provisions_lease
    ON lab_provisions (lease_id)
    WHERE lease_id IS NOT NULL;
