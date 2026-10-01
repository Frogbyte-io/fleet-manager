//! The calling token's own effective permissions (FM-604).
//!
//! `GET /access/permissions` without parameters answers, for the calling
//! user or token, a map of ACL path → (privilege → propagate flag). The
//! map is *effective*: PVE has already applied propagation, `NoAccess`,
//! pool membership, and — for a privilege-separated token — the
//! intersection with its user. The listed paths are the top-level roots
//! (`/`, `/access`, `/nodes`, `/pool`, `/sdn`, `/storage`, `/vms`, …), every
//! path named in an ACL, and every pool member (`/vms/{id}`,
//! `/storage/{id}`); paths without any privilege are omitted. The method
//! is identical on PVE 8.x and 9.x (`PVE/API2/AccessControl.pm`
//! `permissions`, `PVE/RPCEnvironment.pm` `get_effective_permissions`).
//!
//! Normalization is tolerant and bounded: unknown privilege names are kept
//! (PVE adds and removes privileges between majors), malformed entries are
//! isolated into warnings, and the map is capped instead of growing with a
//! hostile or enormous answer.

use std::collections::BTreeMap;

use crate::PveApiError;

/// The most ACL paths kept from one answer; the rest is reported as
/// truncated.
pub const MAX_PERMISSION_PATHS: usize = 4096;

/// The most privileges kept per path. PVE defines fewer than 64.
pub const MAX_PRIVILEGES_PER_PATH: usize = 256;

/// The longest ACL path kept.
const MAX_PATH_CHARS: usize = 512;

/// The longest privilege name kept.
const MAX_PRIVILEGE_CHARS: usize = 64;

/// The most warnings kept; one summarizing warning follows when exceeded.
const MAX_WARNINGS: usize = 32;

/// The token's effective permissions with the PVE version they were read
/// from. Provider-owned shape; the composition translates it into the
/// application's types.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveTokenPermissions {
    /// The PVE version string, e.g. `9.2.2`.
    pub version: String,
    /// ACL path → privilege → propagate flag.
    pub paths: BTreeMap<String, BTreeMap<String, bool>>,
    /// Entries isolated as malformed, bounded.
    pub warnings: Vec<String>,
    /// Whether paths or privileges were dropped by the bounds.
    pub truncated: bool,
}

/// Normalizes one `/access/permissions` `data` value.
///
/// # Errors
///
/// Fails with [`PveApiError::InvalidPayload`] when `data` is neither an
/// object nor `null`.
#[allow(clippy::too_many_lines)]
pub fn normalize_token_permissions(
    version: String,
    data: &serde_json::Value,
) -> Result<PveTokenPermissions, PveApiError> {
    let mut result = PveTokenPermissions {
        version,
        ..PveTokenPermissions::default()
    };
    let entries = match data {
        // No privilege anywhere: PVE filters empty paths, and an empty map
        // may arrive as `{}` or `null`.
        serde_json::Value::Null => return Ok(result),
        serde_json::Value::Object(entries) => entries,
        other => {
            return Err(PveApiError::InvalidPayload {
                detail: format!(
                    "the permissions payload is not an object (it is a {})",
                    crate::type_name_of(other)
                ),
            });
        }
    };
    let mut warnings = Vec::new();
    let mut dropped_warnings = 0_usize;
    for (path, privileges) in entries {
        if result.paths.len() >= MAX_PERMISSION_PATHS {
            result.truncated = true;
            break;
        }
        if !valid_acl_path(path) {
            warn(
                &mut warnings,
                &mut dropped_warnings,
                format!(
                    "permissions path {:?}: not an ACL path; skipped",
                    bounded(path)
                ),
            );
            continue;
        }
        let privileges = match privileges {
            serde_json::Value::Object(privileges) => privileges,
            serde_json::Value::Null => continue,
            other => {
                warn(
                    &mut warnings,
                    &mut dropped_warnings,
                    format!(
                        "permissions path {path}: the privileges are not an object (it is a {}); skipped",
                        crate::type_name_of(other)
                    ),
                );
                continue;
            }
        };
        let mut kept = BTreeMap::new();
        for (privilege, propagate) in privileges {
            if kept.len() >= MAX_PRIVILEGES_PER_PATH {
                result.truncated = true;
                break;
            }
            if !valid_privilege(privilege) {
                warn(
                    &mut warnings,
                    &mut dropped_warnings,
                    format!(
                        "permissions path {path}: privilege {:?} is not a privilege name; skipped",
                        bounded(privilege)
                    ),
                );
                continue;
            }
            let propagate = match propagate {
                serde_json::Value::Bool(flag) => *flag,
                serde_json::Value::Number(number) => match number.as_u64() {
                    Some(0) => false,
                    Some(1) => true,
                    _ => {
                        warn(
                            &mut warnings,
                            &mut dropped_warnings,
                            format!(
                                "permissions path {path}: privilege {privilege} carries an unrecognized propagate flag {number}; treated as not propagating"
                            ),
                        );
                        false
                    }
                },
                serde_json::Value::String(text) => text == "1" || text == "true",
                // A privilege PVE reports with an odd flag is still held at
                // that path; only its propagation is uncertain, so the
                // conservative reading is "does not propagate".
                _ => {
                    warn(
                        &mut warnings,
                        &mut dropped_warnings,
                        format!(
                            "permissions path {path}: privilege {privilege} carries no propagate flag; treated as not propagating"
                        ),
                    );
                    false
                }
            };
            kept.insert(privilege.clone(), propagate);
        }
        if !kept.is_empty() {
            result.paths.insert(path.clone(), kept);
        }
    }
    if result.truncated {
        warn(
            &mut warnings,
            &mut dropped_warnings,
            format!(
                "the permissions answer exceeded the bounds ({MAX_PERMISSION_PATHS} paths, {MAX_PRIVILEGES_PER_PATH} privileges per path); the rest was dropped"
            ),
        );
    }
    if dropped_warnings > 0 {
        warnings.push(format!(
            "{dropped_warnings} more permission warnings were dropped"
        ));
    }
    result.warnings = warnings;
    Ok(result)
}

/// Keeps a warning while under the bound and counts the ones dropped, so a
/// hostile answer cannot grow the list while it is being processed.
fn warn(warnings: &mut Vec<String>, dropped: &mut usize, message: String) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(message);
    } else {
        *dropped += 1;
    }
}

/// An ACL path: absolute, bounded, printable, no empty or dot segments.
fn valid_acl_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    path.len() <= MAX_PATH_CHARS
        && path.starts_with('/')
        && !path.ends_with('/')
        && path[1..]
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && path
            .chars()
            .all(|c| c.is_ascii_graphic() && c != '\\' && c != '"')
}

/// A privilege name: PVE's are dotted ASCII words (`VM.GuestAgent.Audit`).
/// Unknown names in that shape are kept.
fn valid_privilege(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_PRIVILEGE_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A bounded, control-free excerpt for warnings.
fn bounded(value: &str) -> String {
    fleet_core::flatten_control_characters(&value.chars().take(64).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_full_map_normalizes_with_propagate_flags() {
        let data = json!({
            "/": {"Sys.Audit": 1, "VM.Audit": 1},
            "/vms/100": {"VM.PowerMgmt": 0, "VM.Audit": 1},
        });
        let result = normalize_token_permissions("9.2.2".to_owned(), &data).unwrap();
        assert_eq!(result.paths.len(), 2);
        assert!(result.paths["/"]["Sys.Audit"]);
        assert!(!result.paths["/vms/100"]["VM.PowerMgmt"]);
        assert!(result.warnings.is_empty());
        assert!(!result.truncated);
    }

    #[test]
    fn unknown_privileges_are_kept_and_malformed_entries_isolated() {
        let data = json!({
            "/": {"Some.Future.Privilege": 1, "bad name": 1, "VM.Audit": "1"},
            "relative": {"VM.Audit": 1},
            "/vms/../": {"VM.Audit": 1},
            "/nodes": ["Sys.Audit"],
            "/storage": {"Datastore.Audit": null},
        });
        let result = normalize_token_permissions("8.4.1".to_owned(), &data).unwrap();
        assert!(result.paths["/"]["Some.Future.Privilege"]);
        assert!(result.paths["/"]["VM.Audit"]);
        assert!(!result.paths["/"].contains_key("bad name"));
        assert!(!result.paths.contains_key("relative"));
        assert!(!result.paths.contains_key("/nodes"));
        assert!(!result.paths["/storage"]["Datastore.Audit"]);
        assert_eq!(result.warnings.len(), 5, "{:?}", result.warnings);
    }

    #[test]
    fn null_and_empty_are_no_privileges_and_lists_are_payload_errors() {
        for data in [json!(null), json!({})] {
            let result = normalize_token_permissions("9.0.0".to_owned(), &data).unwrap();
            assert!(result.paths.is_empty());
        }
        let error = normalize_token_permissions("9.0.0".to_owned(), &json!([])).unwrap_err();
        assert!(matches!(error, PveApiError::InvalidPayload { .. }));
    }

    #[test]
    fn the_map_is_bounded() {
        let mut entries = serde_json::Map::new();
        for vmid in 0..(MAX_PERMISSION_PATHS + 10) {
            entries.insert(format!("/vms/{}", 100 + vmid), json!({"VM.Audit": 1}));
        }
        let result =
            normalize_token_permissions("9.0.0".to_owned(), &serde_json::Value::Object(entries))
                .unwrap();
        assert_eq!(result.paths.len(), MAX_PERMISSION_PATHS);
        assert!(result.truncated);
        assert!(result.warnings.iter().any(|w| w.contains("exceeded")));
    }

    #[test]
    fn propagate_numbers_other_than_zero_and_one_do_not_propagate() {
        let data = json!({"/": {"VM.Audit": 2, "Sys.Audit": 1, "VM.Console": 0}});
        let result = normalize_token_permissions("9.0.0".to_owned(), &data).unwrap();
        assert!(!result.paths["/"]["VM.Audit"]);
        assert!(result.paths["/"]["Sys.Audit"]);
        assert!(!result.paths["/"]["VM.Console"]);
        assert_eq!(result.warnings.len(), 1, "{:?}", result.warnings);
    }

    #[test]
    fn warnings_are_bounded_while_processing() {
        let mut entries = serde_json::Map::new();
        for index in 0..(MAX_WARNINGS * 4) {
            entries.insert(format!("relative{index}"), json!({"VM.Audit": 1}));
        }
        let result =
            normalize_token_permissions("9.0.0".to_owned(), &serde_json::Value::Object(entries))
                .unwrap();
        assert_eq!(result.warnings.len(), MAX_WARNINGS + 1);
        assert!(result.warnings[MAX_WARNINGS].contains("96 more"));
    }
}
