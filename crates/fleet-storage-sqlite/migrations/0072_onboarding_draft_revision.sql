-- #649: a draft's write revision. Test, discover and confirm each load a
-- draft, work for a while (a network probe, a pin), then write it back; a
-- write from a snapshot older than the stored row (an in-flight test landing
-- after a newer host-key confirmation) must be refused, not undo the newer
-- state. `OnboardingRepository::update` is a compare-and-set on this column
-- and bumps it in the same statement. Existing drafts start at 0.
ALTER TABLE onboarding_drafts ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
