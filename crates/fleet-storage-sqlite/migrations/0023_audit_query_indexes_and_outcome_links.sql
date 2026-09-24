-- Tie future terminal outcome rows to the accepted intent they complete.
-- Historical outcomes do not always contain enough information to identify
-- their intent safely, so pending queries start at this migration boundary.
ALTER TABLE audit_events
    ADD COLUMN intent_seq INTEGER REFERENCES audit_events(seq);

CREATE TABLE audit_query_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    pending_since_seq INTEGER NOT NULL
) STRICT;

INSERT INTO audit_query_state (singleton, pending_since_seq)
SELECT 1, COALESCE(MAX(seq), 0) FROM audit_events;

CREATE INDEX audit_events_actor ON audit_events (actor, seq);
CREATE INDEX audit_events_action ON audit_events (action, seq);
CREATE INDEX audit_events_resource ON audit_events (resource, seq);
CREATE INDEX audit_events_allowed ON audit_events (allowed, seq);
CREATE INDEX audit_events_outcome ON audit_events (outcome, seq);
CREATE UNIQUE INDEX audit_events_one_outcome_per_intent
    ON audit_events (intent_seq)
    WHERE intent_seq IS NOT NULL;
