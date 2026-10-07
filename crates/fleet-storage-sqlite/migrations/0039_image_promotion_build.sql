-- Issue #281: promotion pins the build record that justified it. Lab clones
-- a version's pinned build, so a later rebuild of a promoted version is only
-- evidence; changing what Lab clones requires a new promotion.
--
-- The pin is kept when the version is later demoted, so a lease pinned to
-- the version before the demotion keeps the same clone source. A re-promotion
-- replaces it. Versions promoted before this migration carry NULL; Lab falls
-- back to their newest successful build for them (documented in
-- docs/architecture/lab.md) until they are promoted again.
ALTER TABLE image_recipe_versions ADD COLUMN promoted_build_id TEXT REFERENCES image_build_records(id);

-- Another SQL writer cannot pin a build that belongs to another version,
-- did not succeed, or was built from other inputs, on insert or update.
CREATE TRIGGER image_recipe_versions_promoted_build_insert BEFORE INSERT ON image_recipe_versions
WHEN NEW.promoted_build_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM image_build_records
    WHERE id = NEW.promoted_build_id AND version_id = NEW.id AND outcome = 'succeeded'
      AND content_digest = NEW.content_digest AND template_vmid IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'a promotion pins a successful build of the same version'); END;
CREATE TRIGGER image_recipe_versions_promoted_build BEFORE UPDATE OF promoted_build_id ON image_recipe_versions
WHEN NEW.promoted_build_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM image_build_records
    WHERE id = NEW.promoted_build_id AND version_id = NEW.id AND outcome = 'succeeded'
      AND content_digest = NEW.content_digest AND template_vmid IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'a promotion pins a successful build of the same version'); END;
