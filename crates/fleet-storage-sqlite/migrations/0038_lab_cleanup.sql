-- FM-713: durable Lab cleanup. A releasing lease records when its next
-- cleanup attempt is due (the backoff lives in the row, so it survives a
-- controller restart), and a provision record keeps the Proxmox account
-- its guest was cloned through, so cleanup destroys it through the same
-- account.
ALTER TABLE lab_leases ADD COLUMN cleanup_next_at INTEGER;
ALTER TABLE lab_provisions ADD COLUMN account_id TEXT;
