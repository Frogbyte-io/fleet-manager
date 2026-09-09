-- Draft idempotency (FM-213): a client replaying an import request with the
-- same idempotency key must get the same draft back, not a second one. The
-- key is unique across drafts when present; NULL keys (ordinary UI drafts)
-- are unrestricted.

ALTER TABLE onboarding_drafts ADD COLUMN idempotency_key TEXT;
CREATE UNIQUE INDEX idx_onboarding_drafts_idempotency
    ON onboarding_drafts (idempotency_key) WHERE idempotency_key IS NOT NULL;
