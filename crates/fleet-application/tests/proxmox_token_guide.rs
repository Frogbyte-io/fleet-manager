//! FM-605: the least-privilege token guide (`docs/operations/proxmox-token.md`)
//! must agree with FM-604's [`PROXMOX_PRIVILEGE_TABLE`].
//!
//! The guide carries one machine-checked tier table per PVE major between
//! `<!-- privilege-table:begin major=N -->` and `<!-- privilege-table:end -->`,
//! and one `pveum role add` block per major between
//! `<!-- privilege-roles:begin major=N -->` and `<!-- privilege-roles:end -->`.
//! This test derives the expected cells from the table and fails, naming the
//! expected cell text, when the guide drifts:
//!
//! - **Required**: exactly the `required` rows of the tier, as
//!   "privilege on path" entries (`A` or `B` for `any` rows). An `any` row is
//!   left out when a required single-privilege entry on the same path already
//!   satisfies it (rollback is implied by `VM.Snapshot`, node storage by
//!   `Datastore.Audit`).
//! - **Opt-in**: exactly the tier's `required: false` rows.
//! - **Role**: the `pveum role add` lines for the tier's roles (one or more;
//!   8.x Lab adds `FleetAgent8` on its clone targets) together hold one
//!   privilege of every required entry, and every other privilege they grant
//!   is named in the "Also in the role" column ("`A`, `B`: why"). Any further
//!   role in a block may only grant opt-in privileges (`FleetCancelAnyTask`).
//! - **Pool ACLs**: no `pveum acl modify /pool/…` line grants a Lab role that
//!   holds `VM.Allocate`.

use std::collections::{BTreeMap, BTreeSet};

use fleet_application::proxmox::privileges::{
    PROXMOX_PRIVILEGE_TABLE, PrivilegeMatch, PrivilegeTier, SUPPORTED_PVE_MAJORS,
    requirements_for_major,
};

const GUIDE: &str = include_str!("../../../docs/operations/proxmox-token.md");

/// One "privileges on path" entry: the alternatives (one suffices) and the
/// ACL path template.
type Entry = (BTreeSet<String>, String);

#[derive(Debug)]
struct GuideRow {
    roles: Vec<String>,
    required: BTreeSet<Entry>,
    opt_in: BTreeSet<Entry>,
    also: BTreeSet<String>,
}

/// The text between a begin marker for `major` and the next end marker.
fn section(kind: &str, major: u8) -> &'static str {
    let begin = format!("<!-- {kind}:begin major={major} -->");
    let end = format!("<!-- {kind}:end -->");
    let start = GUIDE
        .find(&begin)
        .unwrap_or_else(|| panic!("the guide has no `{begin}` marker"))
        + begin.len();
    let length = GUIDE[start..]
        .find(&end)
        .unwrap_or_else(|| panic!("`{begin}` has no `{end}`"));
    assert_eq!(
        GUIDE.matches(&begin).count(),
        1,
        "`{begin}` appears more than once"
    );
    &GUIDE[start..start + length]
}

/// The backticked tokens of a cell, in order.
fn code_spans(cell: &str) -> Vec<String> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// Parses "`A` or `B` on `/path`, `C` on `/path`" ("—" is empty).
fn entries(cell: &str) -> BTreeSet<Entry> {
    let cell = cell.trim();
    if cell == "—" || cell.is_empty() {
        return BTreeSet::new();
    }
    cell.split(", ")
        .map(|item| {
            let (privileges, path) = item
                .split_once(" on ")
                .unwrap_or_else(|| panic!("{item:?} is not \"`privilege` on `path`\""));
            let privileges: BTreeSet<String> = privileges
                .split(" or ")
                .map(|privilege| {
                    let spans = code_spans(privilege);
                    assert_eq!(spans.len(), 1, "{item:?}: one privilege per alternative");
                    spans[0].clone()
                })
                .collect();
            let path = code_spans(path);
            assert_eq!(path.len(), 1, "{item:?}: one path");
            (privileges, path[0].clone())
        })
        .collect()
}

fn guide_rows(major: u8) -> BTreeMap<String, GuideRow> {
    let mut rows = BTreeMap::new();
    for line in section("privilege-table", major).lines() {
        let line = line.trim();
        if !line.starts_with('|') || line.starts_with("| Tier") || line.starts_with("|---") {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split(" | ").map(str::trim).collect();
        assert_eq!(cells.len(), 5, "{major}.x row {line:?} needs five cells");
        let roles = code_spans(cells[1]);
        assert!(!roles.is_empty(), "{major}.x row {line:?}: name a role");
        let previous = rows.insert(
            cells[0].to_owned(),
            GuideRow {
                roles,
                required: entries(cells[2]),
                opt_in: entries(cells[3]),
                // "`A`, `B`: why" — only the privileges before the reason.
                also: code_spans(
                    cells[4]
                        .split_once(": ")
                        .map_or(cells[4], |(names, _)| names),
                )
                .into_iter()
                .collect(),
            },
        );
        assert!(previous.is_none(), "{major}.x lists {} twice", cells[0]);
    }
    rows
}

/// Role name → privileges, from the `pveum role add` block.
fn guide_roles(major: u8) -> BTreeMap<String, BTreeSet<String>> {
    let mut roles = BTreeMap::new();
    for line in section("privilege-roles", major).lines() {
        let Some(rest) = line.trim().strip_prefix("pveum role add ") else {
            continue;
        };
        let (name, rest) = rest.trim().split_once(' ').expect("a role name");
        let Some((privileges, _)) = rest
            .split_once("--privs \"")
            .and_then(|(_, rest)| rest.split_once('"'))
        else {
            panic!("{line:?} has no --privs \"…\"");
        };
        let privileges: BTreeSet<String> =
            privileges.split(',').map(|p| p.trim().to_owned()).collect();
        assert!(
            roles.insert(name.to_owned(), privileges).is_none(),
            "{major}.x defines {name} twice"
        );
    }
    roles
}

/// The table's entries for one tier and major, required or opt-in.
fn table_entries(major: u8, tier: PrivilegeTier, required: bool) -> BTreeSet<Entry> {
    let mut entries = BTreeSet::new();
    for row in requirements_for_major(major)
        .filter(|row| row.tier == tier && row.required == required && !row.privileges.is_empty())
    {
        let path = row.scope.template().to_owned();
        match row.matching {
            PrivilegeMatch::All => {
                for privilege in row.privileges {
                    entries.insert((BTreeSet::from([(*privilege).to_owned()]), path.clone()));
                }
            }
            PrivilegeMatch::Any => {
                entries.insert((
                    row.privileges.iter().map(|p| (*p).to_owned()).collect(),
                    path,
                ));
            }
        }
    }
    // An alternatives entry is implied by a single-privilege entry on the
    // same path that is one of its alternatives.
    let singles: BTreeSet<Entry> = entries
        .iter()
        .filter(|(privileges, _)| privileges.len() == 1)
        .cloned()
        .collect();
    entries.retain(|(privileges, path)| {
        privileges.len() == 1
            || !singles
                .iter()
                .any(|(single, single_path)| single_path == path && single.is_subset(privileges))
    });
    entries
}

/// The cell text a set of entries should read as, for failure messages.
fn render(entries: &BTreeSet<Entry>) -> String {
    if entries.is_empty() {
        return "—".to_owned();
    }
    entries
        .iter()
        .map(|(privileges, path)| {
            let privileges: Vec<String> = privileges.iter().map(|p| format!("`{p}`")).collect();
            format!("{} on `{path}`", privileges.join(" or "))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[test]
fn the_guide_tier_tables_match_the_privilege_table() {
    for major in SUPPORTED_PVE_MAJORS {
        let rows = guide_rows(major);
        let tiers: BTreeSet<&str> = PrivilegeTier::ALL.iter().map(|t| t.id()).collect();
        assert_eq!(
            rows.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            tiers,
            "the {major}.x guide table must list exactly the tiers"
        );
        for tier in PrivilegeTier::ALL {
            let row = &rows[tier.id()];
            let required = table_entries(major, tier, true);
            assert_eq!(
                row.required,
                required,
                "{major}.x {}: the Required cell must read (in any order):\n{}",
                tier.id(),
                render(&required)
            );
            let opt_in = table_entries(major, tier, false);
            assert_eq!(
                row.opt_in,
                opt_in,
                "{major}.x {}: the Opt-in cell must read (in any order):\n{}",
                tier.id(),
                render(&opt_in)
            );
        }
    }
}

#[test]
fn the_guide_roles_grant_each_tier_and_label_every_extra() {
    for major in SUPPORTED_PVE_MAJORS {
        let rows = guide_rows(major);
        let roles = guide_roles(major);
        let mut tier_roles = BTreeSet::new();
        let mut opt_in_privileges = BTreeSet::new();
        for tier in PrivilegeTier::ALL {
            let row = &rows[tier.id()];
            let mut granted = BTreeSet::new();
            for role in &row.roles {
                granted.extend(roles.get(role).unwrap_or_else(|| {
                    panic!("{major}.x {}: the role block has no `{role}`", tier.id())
                }));
                tier_roles.insert(role.clone());
            }
            let granted: BTreeSet<String> = granted.into_iter().cloned().collect();
            for (alternatives, path) in &row.required {
                assert!(
                    !alternatives.is_disjoint(&granted),
                    "{major}.x {:?} do not grant {alternatives:?} (on {path})",
                    row.roles
                );
            }
            let required: BTreeSet<String> = row
                .required
                .iter()
                .flat_map(|(alternatives, _)| alternatives.iter().cloned())
                .collect();
            let extras: BTreeSet<String> = granted.difference(&required).cloned().collect();
            assert_eq!(
                extras, row.also,
                "{major}.x {:?}: the \"Also in the role\" cell must name exactly what the roles grant beyond the required privileges",
                row.roles
            );
            opt_in_privileges.extend(
                row.opt_in
                    .iter()
                    .flat_map(|(alternatives, _)| alternatives.iter().cloned()),
            );
        }
        let granted_anywhere: BTreeSet<&String> = roles.values().flatten().collect();
        for privilege in &opt_in_privileges {
            assert!(
                granted_anywhere.contains(privilege),
                "{major}.x: no role in the block grants the opt-in {privilege}"
            );
        }
        for (name, privileges) in &roles {
            if !tier_roles.contains(name) {
                assert!(
                    privileges.is_subset(&opt_in_privileges),
                    "{major}.x {name} is not a tier role, so it may grant only opt-in privileges, not {privileges:?}"
                );
            }
        }
    }
}

#[test]
fn no_pool_acl_in_the_guide_grants_a_lab_role_holding_vm_allocate() {
    // VM.Allocate on a pool reaches every member VM and also permits deleting
    // it. Lab needs it only on the reserved clone-target VMIDs, so the Lab
    // role granted on a pool must not carry it.
    for major in SUPPORTED_PVE_MAJORS {
        let roles = guide_roles(major);
        let lab = &guide_rows(major)[PrivilegeTier::Lab.id()];
        let mut pool_acls = 0;
        for line in GUIDE.lines() {
            let Some(rest) = line.trim().strip_prefix("pveum acl modify /pool/") else {
                continue;
            };
            pool_acls += 1;
            let Some((_, role)) = rest.split_once("--roles ") else {
                panic!("{line:?} has no --roles");
            };
            // `--roles` takes a comma-separated list: check every role in it.
            let list = role.split_whitespace().next().expect("a role name");
            for role in list.split(',') {
                if lab.roles.iter().any(|name| name == role) {
                    assert!(
                        !roles[role].contains("VM.Allocate"),
                        "{major}.x: {role} is granted on a pool but holds VM.Allocate"
                    );
                }
            }
        }
        assert!(pool_acls > 0, "the guide grants no pool ACLs");
    }
}

#[test]
fn the_guide_role_blocks_name_only_privileges_the_table_knows_for_that_major() {
    // `pveum role add` rejects unknown privilege names, and 8.x/9.x differ
    // (VM.Monitor vs the VM.GuestAgent.* split): a role privilege the table
    // never names for that major is a typo or a cross-major leak.
    let known: BTreeSet<&str> = PROXMOX_PRIVILEGE_TABLE
        .iter()
        .flat_map(|row| row.privileges.iter().copied())
        .collect();
    for major in SUPPORTED_PVE_MAJORS {
        let for_major: BTreeSet<&str> = requirements_for_major(major)
            .flat_map(|row| row.privileges.iter().copied())
            .collect();
        for (name, privileges) in guide_roles(major) {
            for privilege in &privileges {
                assert!(
                    known.contains(privilege.as_str()),
                    "{major}.x {name}: {privilege} is not in the privilege table"
                );
                assert!(
                    for_major.contains(privilege.as_str()),
                    "{major}.x {name}: {privilege} is not a {major}.x privilege in the table"
                );
            }
        }
    }
}
