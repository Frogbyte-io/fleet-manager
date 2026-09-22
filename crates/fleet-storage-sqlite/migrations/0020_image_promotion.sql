-- FM-701: manual promotion of built image versions. At most one promoted
-- version per recipe (a partial unique index enforces it in the schema);
-- the promote use case emits the promotion/demotion audit events. The
-- gate evidence (the successful build operation) is verified against the
-- operations table, not stored here.
ALTER TABLE image_recipe_versions ADD COLUMN promoted_at INTEGER;
ALTER TABLE image_recipe_versions ADD COLUMN promoted_by TEXT;

-- The at-most-one-promoted-version invariant, enforced by the schema:
-- another SQL writer cannot create two promoted rows for one recipe.
CREATE UNIQUE INDEX image_recipe_versions_promoted
    ON image_recipe_versions (recipe_id)
    WHERE promoted_at IS NOT NULL;
