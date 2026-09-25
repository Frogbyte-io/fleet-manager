-- FM-931: new leases persist their absolute lifetime cap. Older rows derive
-- the same fixed cap from created_at when read, avoiding a table-wide rewrite.
ALTER TABLE lab_leases
    ADD COLUMN max_lifetime_at INTEGER;
