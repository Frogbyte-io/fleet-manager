-- FM-1101: hardware inventory and exclusive reservations (ADR 0019).
-- Additive: new tables only. A device is identified by (account, PVE
-- resource mapping), never by what it was last seen as.
CREATE TABLE hardware_devices (
    id                 TEXT PRIMARY KEY,
    account_id         TEXT NOT NULL CHECK (length(account_id) BETWEEN 1 AND 128),
    mapping_id         TEXT NOT NULL CHECK (length(mapping_id) BETWEEN 1 AND 128),
    kind               TEXT NOT NULL CHECK (kind IN ('usb')),
    status             TEXT NOT NULL CHECK (status IN (
        'available', 'reserved', 'externally_attached', 'missing', 'unsupported', 'quarantined')),
    -- Present exactly when the status is `unsupported`.
    unsupported_reason TEXT CHECK (unsupported_reason IS NULL OR unsupported_reason IN (
        'no_node_entry', 'ambiguous_mapping', 'token_lacks_mapping_use',
        'token_lacks_guest_hwtype', 'pve_too_old', 'usb_inventory_unreadable')),
    note               TEXT CHECK (note IS NULL OR length(note) <= 1024),
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    UNIQUE (account_id, mapping_id),
    CHECK ((status = 'unsupported') = (unsupported_reason IS NOT NULL))
) STRICT;

-- What each node last observed for a device. No serial: the PVE node
-- inventory does not return one.
CREATE TABLE hardware_device_entries (
    device_id    TEXT NOT NULL REFERENCES hardware_devices(id) ON DELETE CASCADE,
    node         TEXT NOT NULL CHECK (length(node) BETWEEN 1 AND 128),
    vendor_id    TEXT NOT NULL CHECK (length(vendor_id) BETWEEN 1 AND 16),
    product_id   TEXT NOT NULL CHECK (length(product_id) BETWEEN 1 AND 16),
    usbpath      TEXT CHECK (usbpath IS NULL OR length(usbpath) <= 64),
    manufacturer TEXT CHECK (manufacturer IS NULL OR length(manufacturer) <= 256),
    product      TEXT CHECK (product IS NULL OR length(product) <= 256),
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, node)
) STRICT;

-- One row per hold. The owner (a lease or a machine) is polymorphic, so
-- owner_id carries no foreign key. A device is never deleted while any
-- reservation, live or history, references it.
CREATE TABLE hardware_reservations (
    id            TEXT PRIMARY KEY,
    device_id     TEXT NOT NULL REFERENCES hardware_devices(id) ON DELETE RESTRICT,
    owner_kind    TEXT NOT NULL CHECK (owner_kind IN ('lease', 'machine')),
    owner_id      TEXT NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 128),
    state         TEXT NOT NULL CHECK (state IN (
        'held', 'attaching', 'attached', 'detaching', 'released',
        'attach_unknown', 'detach_failed')),
    guest_account TEXT CHECK (guest_account IS NULL OR length(guest_account) BETWEEN 1 AND 128),
    guest_node    TEXT CHECK (guest_node IS NULL OR length(guest_node) BETWEEN 1 AND 128),
    guest_vmid    INTEGER CHECK (guest_vmid IS NULL OR guest_vmid > 0),
    usb_slot      INTEGER CHECK (usb_slot IS NULL OR usb_slot BETWEEN 0 AND 4),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    released_at   INTEGER,
    CHECK ((state = 'released') = (released_at IS NOT NULL)),
    -- A slot only makes sense with its guest, and the guest is all or nothing.
    CHECK (usb_slot IS NULL OR guest_vmid IS NOT NULL),
    CHECK ((guest_account IS NULL) = (guest_node IS NULL)
       AND (guest_node IS NULL) = (guest_vmid IS NULL))
) STRICT;

-- A device has at most one live reservation: a double hold is impossible.
CREATE UNIQUE INDEX hardware_reservations_one_live_per_device
    ON hardware_reservations (device_id) WHERE state <> 'released';

CREATE INDEX hardware_reservations_live_owner
    ON hardware_reservations (owner_kind, owner_id) WHERE state <> 'released';
