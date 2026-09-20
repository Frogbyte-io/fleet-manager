-- FM-600 review round: the trust probe's last capture. confirm must match
-- this, so trust always flows through the observe step.
ALTER TABLE proxmox_accounts ADD COLUMN observed_fingerprint TEXT NOT NULL DEFAULT '';
