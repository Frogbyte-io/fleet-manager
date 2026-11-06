-- #596: why a device is `unsupported`, when the reason is an account-level
-- one the fixed reason text cannot carry (the token cannot be shown to audit
-- every guest). Reason text only, not a new reason: the enum stays as it is.
-- Additive and nullable; a refresh sets it with the status and clears it
-- otherwise.
ALTER TABLE hardware_devices
    ADD COLUMN status_detail TEXT CHECK (status_detail IS NULL OR length(status_detail) <= 1024);
