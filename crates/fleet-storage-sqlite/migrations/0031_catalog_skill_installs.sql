-- Fleet's own verified record of the pinned catalog version installed per
-- machine and agent (FM-411). Written only by a verified catalog rollout and
-- pruned by the skills probe; never derived from Skills Manager's files.
CREATE TABLE catalog_skill_installs (
    machine_id TEXT NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    catalog_id TEXT NOT NULL,
    agent TEXT NOT NULL,
    version_id TEXT NOT NULL,
    skill_name TEXT NOT NULL,
    installed_at INTEGER NOT NULL,
    PRIMARY KEY (machine_id, catalog_id, agent)
) STRICT;
