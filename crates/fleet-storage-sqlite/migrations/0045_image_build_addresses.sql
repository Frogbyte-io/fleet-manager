-- #337: Fleet-assigned build addresses.
--
-- A `proxmox-clone` image build gets one address from the operator's pool,
-- which Fleet puts into the guest (cloud-init) and into the communicator
-- host of the recipe copy it hands to Packer, so the build guest no longer
-- chooses where the controller connects. One row per (operation, builder
-- slot). A held address belongs to one live operation: the partial unique
-- index makes a double allocation impossible, and the operation's own state
-- is authoritative (a held row whose operation is terminal or unknown no
-- longer counts, and the next allocation reclaims it). A released row stays
-- as history, orders reuse (least recently released first), and carries the
-- quarantine of an address whose VM may not be gone.
CREATE TABLE image_build_addresses (
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    slot         INTEGER NOT NULL CHECK (slot >= 0),
    address      TEXT NOT NULL CHECK (length(address) BETWEEN 7 AND 15),
    state        TEXT NOT NULL CHECK (state IN ('held', 'released')),
    created_at   INTEGER NOT NULL,
    released_at  INTEGER,
    -- Set when the build did not end verifiably (its VM may still hold the
    -- address): the address is not handed out again before this time.
    hold_until   INTEGER,
    PRIMARY KEY (operation_id, slot),
    CHECK ((state = 'released') = (released_at IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX image_build_addresses_held
    ON image_build_addresses (address) WHERE state = 'held';
CREATE INDEX image_build_addresses_address ON image_build_addresses (address, released_at);
