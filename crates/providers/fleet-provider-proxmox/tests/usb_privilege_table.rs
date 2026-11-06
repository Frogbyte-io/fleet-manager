//! The provider's own declaration of what the USB attach and detach calls ask
//! of the token (`USB_ATTACH_PRIVILEGES`, FM-1122) must agree with the rows of
//! the application's `PROXMOX_PRIVILEGE_TABLE` (FM-1111), which the token guide
//! and `fleetctl proxmox privileges` report. The provider crate may depend on
//! the application, not the reverse, so the comparison lives here.

use fleet_application::proxmox::privileges::{
    PROXMOX_PRIVILEGE_TABLE, PrivilegeMatch, PrivilegeTier, SUPPORTED_PVE_MAJORS,
};
use fleet_provider_proxmox::usb_attach::USB_ATTACH_PRIVILEGES;

#[test]
fn every_usb_attach_row_is_mirrored_in_the_privilege_table_as_an_opt_in_row() {
    for row in USB_ATTACH_PRIVILEGES {
        if row.id == "usb.read-guest" {
            // VM.Audit on the guest is the discover tier's existing required
            // `read.guest-config` row, not a USB-specific one.
            let existing = PROXMOX_PRIVILEGE_TABLE
                .iter()
                .find(|entry| entry.id == "read.guest-config")
                .expect("the guest config read row");
            assert_eq!(existing.privileges, row.privileges);
            assert_eq!(existing.scope.template(), row.path);
            continue;
        }
        for major in SUPPORTED_PVE_MAJORS {
            let mirrored = PROXMOX_PRIVILEGE_TABLE
                .iter()
                .find(|entry| entry.id == row.id && entry.applies_to(major))
                .unwrap_or_else(|| panic!("{} has no {major}.x row in the table", row.id));
            assert_eq!(mirrored.privileges, row.privileges, "{}", row.id);
            assert_eq!(mirrored.scope.template(), row.path, "{}", row.id);
            assert_eq!(mirrored.endpoint, row.endpoint, "{}", row.id);
            assert_eq!(mirrored.matching, PrivilegeMatch::All, "{}", row.id);
            assert!(!mirrored.required, "{} must be opt-in", row.id);
            assert_eq!(mirrored.tier, PrivilegeTier::Lab, "{}", row.id);
        }
    }
}

#[test]
fn the_table_has_no_usb_row_the_provider_does_not_declare() {
    for entry in PROXMOX_PRIVILEGE_TABLE
        .iter()
        .filter(|entry| entry.id.starts_with("usb."))
    {
        if entry.id == "usb.read-mappings" || entry.id == "usb.audit-all-guests" {
            // The listing and the guest scan are reads the inventory makes
            // (the second is the precondition for calling a device
            // available, #596), not attach calls.
            continue;
        }
        assert!(
            USB_ATTACH_PRIVILEGES.iter().any(|row| row.id == entry.id),
            "{} is in the table but not in USB_ATTACH_PRIVILEGES",
            entry.id
        );
    }
}
