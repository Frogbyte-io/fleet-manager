-- A Lab template's optional virtual audio device (issue #398): Proxmox
-- `audio0`'s model and driver, both set or both NULL. NULL leaves the clone
-- as the image has it. The allow-list is enforced in fleet-core; the CHECK
-- only keeps the pair whole.
ALTER TABLE lab_templates ADD COLUMN audio_device TEXT;
ALTER TABLE lab_templates ADD COLUMN audio_driver TEXT
    CHECK ((audio_device IS NULL) = (audio_driver IS NULL));
