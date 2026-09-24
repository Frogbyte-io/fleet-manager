-- Tie each terminal outcome row to the accepted intent it completes. The
-- audit ledger stays append-only after this one-time, trigger-free backfill.
DROP TRIGGER audit_events_no_update;

ALTER TABLE audit_events
    ADD COLUMN intent_seq INTEGER REFERENCES audit_events(seq);

UPDATE audit_events AS completed
SET intent_seq = (
    SELECT pending.seq
    FROM audit_events AS pending
    WHERE pending.seq < completed.seq
      AND pending.outcome IS NULL
      AND pending.actor = completed.actor
      AND pending.action = completed.action
      AND pending.resource IS completed.resource
      AND pending.allowed = completed.allowed
      AND pending.reason = completed.reason
      AND pending.correlation_id IS completed.correlation_id
      AND pending.operation_id IS completed.operation_id
      AND pending.metadata_json = completed.metadata_json
      AND NOT EXISTS (
          SELECT 1 FROM audit_events AS prior
          WHERE prior.intent_seq = pending.seq
      )
    ORDER BY pending.seq DESC
    LIMIT 1
)
WHERE completed.outcome IS NOT NULL;

CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE INDEX audit_events_actor ON audit_events (actor, seq);
CREATE INDEX audit_events_action ON audit_events (action, seq);
CREATE INDEX audit_events_resource ON audit_events (resource, seq);
CREATE INDEX audit_events_allowed ON audit_events (allowed, seq);
CREATE INDEX audit_events_outcome ON audit_events (outcome, seq);
CREATE UNIQUE INDEX audit_events_one_outcome_per_intent
    ON audit_events (intent_seq)
    WHERE intent_seq IS NOT NULL;
