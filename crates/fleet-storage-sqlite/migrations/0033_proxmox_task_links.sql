-- FM-609: which Fleet operation started which PVE task. Executors record a
-- row as soon as PVE returns a UPID; the task-history read joins on it.
--
-- operation_id deliberately carries no foreign key: migration 0014's note
-- says nothing may FK-reference `operations`, because a future rebuild of
-- that table would have to reorder around it. A link whose operation is
-- pruned simply stops resolving. The account FK cascades: removing an
-- account removes its task links with it.
CREATE TABLE proxmox_task_links (
    account_id   TEXT NOT NULL REFERENCES proxmox_accounts(id) ON DELETE CASCADE,
    upid         TEXT NOT NULL CHECK (length(upid) BETWEEN 1 AND 256),
    operation_id TEXT NOT NULL,
    recorded_at  INTEGER NOT NULL,
    PRIMARY KEY (account_id, upid)
) STRICT;

CREATE INDEX proxmox_task_links_operation ON proxmox_task_links (operation_id);
