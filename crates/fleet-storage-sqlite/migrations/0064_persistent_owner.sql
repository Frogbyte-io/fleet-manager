-- #496: who asked for a persistent machine, and why. Written only by the
-- machine.create executor, from the stamp the action broker put on the
-- reviewed payload; never from node-reported facts, which a node can forge.
-- Absent for a machine an operator created directly.
ALTER TABLE persistent_guests ADD COLUMN owner TEXT;
ALTER TABLE persistent_guests ADD COLUMN purpose TEXT;
ALTER TABLE persistent_guests ADD COLUMN request_id TEXT;
