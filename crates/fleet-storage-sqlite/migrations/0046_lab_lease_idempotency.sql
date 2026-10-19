-- #395: retry-safe lease creation. A caller-scoped `Idempotency-Key` and the
-- canonical fingerprint of the request that first used it ride on the lease
-- row. The partial unique index is the arbiter: of two concurrent creates
-- with one key, exactly one insert succeeds, and the other re-reads it.
ALTER TABLE lab_leases ADD COLUMN idempotency_key TEXT;
ALTER TABLE lab_leases ADD COLUMN idempotency_fingerprint TEXT;
CREATE UNIQUE INDEX lab_leases_idempotency ON lab_leases (idempotency_key)
    WHERE idempotency_key IS NOT NULL;
-- Lookup by owner and purpose.
CREATE INDEX lab_leases_owner_created ON lab_leases (owner, created_at DESC);
