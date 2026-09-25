-- FM-931: retain the creation-relative absolute lease lifetime cap so
-- extensions cannot be stacked indefinitely and the bound survives restart.
ALTER TABLE lab_leases
    ADD COLUMN max_lifetime_at INTEGER NOT NULL DEFAULT 0;

UPDATE lab_leases
SET max_lifetime_at = created_at + 2592000000;
