-- Worker claim bookkeeping. The state machine stays the authority; these
-- columns record who claimed an operation and when, so a crashed worker's
-- claims can be recognized by their age rather than by trust.

ALTER TABLE operations ADD COLUMN claimed_at INTEGER;
ALTER TABLE operations ADD COLUMN worker_id TEXT;

CREATE INDEX operations_claimed ON operations (claimed_at) WHERE claimed_at IS NOT NULL;
