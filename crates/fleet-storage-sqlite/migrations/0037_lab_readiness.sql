-- FM-714: retain SSH/project associations and honest readiness states.
-- Rebuild only the provision table to extend its CHECK; preserve every row,
-- external ID, lease link, and existing index.
CREATE TABLE lab_provisions_readiness (
    id TEXT PRIMARY KEY,
    template_version_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('provisioning', 'provisioned', 'booting', 'bootstrapping', 'ready', 'never_ready')),
    node TEXT,
    vmid INTEGER,
    clone_upid TEXT,
    guest_ipv4 TEXT,
    ready_at INTEGER,
    idempotency_key TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    lease_id TEXT REFERENCES lab_leases(id),
    machine_id TEXT REFERENCES machines(id) ON DELETE SET NULL,
    endpoint_id TEXT REFERENCES machine_endpoints(id) ON DELETE SET NULL,
    ready_project_operation_id TEXT REFERENCES operations(id),
    readiness_deadline_at INTEGER,
    failed_step TEXT
) STRICT;
INSERT INTO lab_provisions_readiness
    (id, template_version_id, state, node, vmid, clone_upid, guest_ipv4, ready_at,
     idempotency_key, created_at, updated_at, lease_id)
    SELECT id, template_version_id, state, node, vmid, clone_upid, guest_ipv4, ready_at,
           idempotency_key, created_at, updated_at, lease_id FROM lab_provisions;
DROP TABLE lab_provisions;
ALTER TABLE lab_provisions_readiness RENAME TO lab_provisions;
CREATE INDEX lab_provisions_created ON lab_provisions(created_at DESC);
CREATE UNIQUE INDEX lab_provisions_idempotency ON lab_provisions(idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX lab_provisions_lease ON lab_provisions(lease_id)
    WHERE lease_id IS NOT NULL;
CREATE UNIQUE INDEX lab_provisions_machine ON lab_provisions(machine_id)
    WHERE machine_id IS NOT NULL;

ALTER TABLE lab_templates ADD COLUMN ssh_user TEXT NOT NULL DEFAULT 'root';
ALTER TABLE lab_templates ADD COLUMN ssh_port INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535);
ALTER TABLE lab_templates ADD COLUMN ssh_trust_mode TEXT NOT NULL DEFAULT 'tofu' CHECK (ssh_trust_mode IN ('tofu', 'pinned'));
ALTER TABLE lab_templates ADD COLUMN ssh_fingerprint TEXT;
