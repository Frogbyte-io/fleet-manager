-- Issue #284: image builds pin the Proxmox account's confirmed certificate
-- for Packer. A version may still build with `insecure_skip_tls_verify` only
-- through an explicit, audited opt-in at publication; the flag is part of
-- the version digest, so it can never be added to a published version.
--
-- Versions published before this migration carry 0. One whose recipe skips
-- TLS verification now fails its builds with `insecure_tls_not_allowed`;
-- the remedy is to drop the field (the build then pins the certificate) or
-- to publish again with the opt-in, which makes a new version.
ALTER TABLE image_recipe_versions ADD COLUMN allow_insecure_tls INTEGER NOT NULL DEFAULT 0
    CHECK (allow_insecure_tls IN (0, 1));
