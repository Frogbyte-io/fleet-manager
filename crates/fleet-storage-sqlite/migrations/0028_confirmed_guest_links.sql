-- Explicit operator-confirmed Proxmox associations. Provider identity is
-- account + kind + VMID; node records where the guest was seen on confirm.
CREATE TABLE confirmed_guest_links (
    machine_id TEXT PRIMARY KEY REFERENCES machines(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES proxmox_accounts(id) ON DELETE CASCADE,
    guest_kind TEXT NOT NULL CHECK (guest_kind IN ('qemu', 'lxc')),
    node TEXT NOT NULL,
    vmid INTEGER NOT NULL CHECK (vmid > 0),
    confirmed_at INTEGER NOT NULL,
    UNIQUE (account_id, guest_kind, vmid)
) STRICT;
