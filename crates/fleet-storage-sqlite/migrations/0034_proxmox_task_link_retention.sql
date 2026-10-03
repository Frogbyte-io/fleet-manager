-- FM-234: bounded retention for the FM-609 task links. Without it every
-- lifecycle and destructive task added a row forever. The repository
-- deletes links older than its retention window in small batches, oldest
-- first, from `record`; this index serves that range scan so the cleanup
-- never walks the whole table.
CREATE INDEX proxmox_task_links_recorded_at ON proxmox_task_links (recorded_at);
