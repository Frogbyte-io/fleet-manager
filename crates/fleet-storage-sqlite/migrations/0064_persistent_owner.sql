-- #496: who asked for a persistent machine, and why. Written only by the
-- machine.create executor, from the stamp the action broker put on the
-- reviewed payload; never from node-reported facts, which a node can forge.
-- Absent for a machine an operator created directly.
ALTER TABLE persistent_guests ADD COLUMN owner TEXT;
ALTER TABLE persistent_guests ADD COLUMN purpose TEXT;
ALTER TABLE persistent_guests ADD COLUMN request_id TEXT;

-- The `fleet` capability-fact namespace is Fleet's own and is no longer
-- accepted from reports; drop whatever an earlier build or a report left.
DELETE FROM machine_capabilities WHERE lower(namespace) = 'fleet';
