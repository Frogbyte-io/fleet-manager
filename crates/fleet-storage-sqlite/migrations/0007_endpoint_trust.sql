-- Endpoint trust state: the fingerprint an operator confirmed for this
-- endpoint, and when. The Fleet known-hosts file is the enforcement store;
-- these columns are the reviewable record of what was confirmed and when.

ALTER TABLE machine_endpoints ADD COLUMN verified_fingerprint TEXT;
ALTER TABLE machine_endpoints ADD COLUMN verified_at INTEGER;
