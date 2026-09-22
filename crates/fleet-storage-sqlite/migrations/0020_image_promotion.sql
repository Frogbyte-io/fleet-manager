-- FM-701: manual promotion of built image versions. At most one promoted
-- version per recipe: promoting a second records the demotion of the
-- first in the audit ledger. The gate evidence (the successful build
-- operation) is verified against the operations table, not stored here.
ALTER TABLE image_recipe_versions ADD COLUMN promoted_at INTEGER;
ALTER TABLE image_recipe_versions ADD COLUMN promoted_by TEXT;
