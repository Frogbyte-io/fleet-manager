-- Build inputs are frozen at insertion. Only running -> terminal completion
-- can fill in probed versions and output; completed evidence cannot be edited.
CREATE TABLE image_build_records (
    id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL UNIQUE REFERENCES operations(id),
    recipe_id TEXT NOT NULL,
    version_id TEXT NOT NULL REFERENCES image_recipe_versions(id),
    content_digest TEXT NOT NULL,
    asset_digests TEXT NOT NULL CHECK (json_valid(asset_digests) AND json_type(asset_digests) = 'array'),
    account_id TEXT,
    node TEXT NOT NULL,
    storage_pool TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    outcome TEXT NOT NULL CHECK (outcome IN ('running', 'succeeded', 'failed', 'cancelled')),
    reason TEXT,
    packer_version TEXT,
    proxmox_plugin_version TEXT,
    template_node TEXT,
    template_vmid INTEGER CHECK (template_vmid BETWEEN 100 AND 999999999),
    template_name TEXT,
    CHECK ((outcome = 'running' AND ended_at IS NULL AND reason IS NULL) OR
           (outcome != 'running' AND ended_at IS NOT NULL AND ended_at >= started_at)),
    CHECK ((outcome = 'succeeded' AND template_node IS NOT NULL AND template_vmid IS NOT NULL AND template_name IS NOT NULL
            AND packer_version IS NOT NULL AND proxmox_plugin_version IS NOT NULL AND account_id IS NOT NULL) OR
           (outcome != 'succeeded' AND template_node IS NULL AND template_vmid IS NULL AND template_name IS NULL))
) STRICT;
CREATE INDEX image_build_records_history ON image_build_records(started_at DESC, id DESC);
CREATE INDEX image_build_records_version ON image_build_records(version_id, started_at DESC, id DESC);
CREATE INDEX image_build_records_recipe ON image_build_records(recipe_id, started_at DESC, id DESC);
CREATE TRIGGER image_build_records_insert BEFORE INSERT ON image_build_records
WHEN NEW.outcome != 'running' OR NEW.packer_version IS NOT NULL OR NEW.proxmox_plugin_version IS NOT NULL
 OR EXISTS (SELECT 1 FROM image_build_records WHERE id = NEW.id OR operation_id = NEW.operation_id)
 OR NOT EXISTS (SELECT 1 FROM image_recipe_versions WHERE id = NEW.version_id AND recipe_id = NEW.recipe_id
                AND content_digest = NEW.content_digest AND node = NEW.node AND storage_pool = NEW.storage_pool)
 OR NOT EXISTS (SELECT 1 FROM operations WHERE id = NEW.operation_id AND kind = 'image.build' AND state IN ('pending', 'running', 'cancelling'))
BEGIN SELECT RAISE(ABORT, 'build records must start running'); END;
CREATE TRIGGER image_build_records_update BEFORE UPDATE ON image_build_records
WHEN OLD.outcome != 'running' OR NEW.outcome = 'running'
 OR NEW.id IS NOT OLD.id OR NEW.operation_id IS NOT OLD.operation_id
 OR NEW.recipe_id IS NOT OLD.recipe_id OR NEW.version_id IS NOT OLD.version_id
 OR NEW.content_digest IS NOT OLD.content_digest OR NEW.asset_digests IS NOT OLD.asset_digests
 OR NEW.account_id IS NOT OLD.account_id OR NEW.node IS NOT OLD.node
 OR NEW.storage_pool IS NOT OLD.storage_pool OR NEW.started_at IS NOT OLD.started_at
BEGIN SELECT RAISE(ABORT, 'build records permit only completion'); END;
CREATE TRIGGER image_build_records_delete BEFORE DELETE ON image_build_records
BEGIN SELECT RAISE(ABORT, 'build records are append-only'); END;

-- Worker recovery/deadline handling may terminate an operation without
-- re-entering its executor. Preserve an honest interrupted outcome rather
-- than leaving its build record running forever. No output is inferred from
-- generic operation JSON. Normal executor completion has already frozen its
-- terminal build record, so this trigger does nothing on that path.
CREATE TRIGGER image_build_records_operation_terminal AFTER UPDATE OF state ON operations
WHEN NEW.kind = 'image.build' AND NEW.state IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'blocked_manual_approval')
BEGIN
    UPDATE image_build_records
    SET outcome = CASE WHEN NEW.state = 'cancelled' THEN 'cancelled' ELSE 'failed' END,
        reason = 'operation_terminal_without_build_completion',
        ended_at = MAX(started_at, NEW.updated_at)
    WHERE operation_id = NEW.id AND outcome = 'running';
END;
