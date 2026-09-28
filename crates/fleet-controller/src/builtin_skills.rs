//! The skills this controller release ships (FM-924): the official `fleet`
//! skill, embedded at build time and seeded into the skill catalog at
//! startup under its reserved identity (ADR 0011).

use std::sync::Arc;

use fleet_application::composition::{BuiltinSkillAssignment, DEFAULT_BUILTIN_SKILL_AGENTS};
use fleet_application::skill_catalog::{
    BuiltinSeed, SkillCatalog, SkillCatalogContent, SkillCatalogFile, SkillCatalogSource,
};
use sqlx::SqlitePool;

/// `skills/fleet/SKILL.md`, as this release ships it.
pub const FLEET_SKILL_MARKDOWN: &str = include_str!("../../../skills/fleet/SKILL.md");

/// Reads one single-line scalar from SKILL.md's frontmatter. The shipped
/// skill keeps `name` and `description` on one line each; the catalog's own
/// YAML validation then confirms they match what a YAML parser reads.
fn frontmatter_field<'a>(markdown: &'a str, key: &str) -> Option<&'a str> {
    let mut lines = markdown.lines();
    if lines.next() != Some("---") {
        return None;
    }
    lines
        .take_while(|line| *line != "---")
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
        .map(str::trim)
}

/// The catalog content of the built-in `fleet` skill.
///
/// # Errors
///
/// Fails when the embedded SKILL.md lacks a single-line name or description.
pub fn fleet_skill_content() -> Result<SkillCatalogContent, String> {
    let name = frontmatter_field(FLEET_SKILL_MARKDOWN, "name")
        .ok_or("the built-in fleet skill has no frontmatter name")?;
    let description = frontmatter_field(FLEET_SKILL_MARKDOWN, "description")
        .ok_or("the built-in fleet skill has no frontmatter description")?;
    Ok(SkillCatalogContent {
        name: name.to_owned(),
        description: description.to_owned(),
        files: vec![SkillCatalogFile {
            path: "SKILL.md".to_owned(),
            content: FLEET_SKILL_MARKDOWN.to_owned(),
        }],
        source: SkillCatalogSource::Authored,
    })
}

/// Makes the catalog carry this release's built-in skills. Safe to run on
/// every start: an unchanged release writes nothing.
///
/// # Errors
///
/// Fails when the embedded content is invalid or the catalog store fails.
pub async fn seed_builtin_skills(pool: &SqlitePool, now: i64) -> Result<BuiltinSeed, String> {
    let catalog = SkillCatalog::new(
        Arc::new(fleet_storage_sqlite::SkillCatalogRepository::new(
            pool.clone(),
        )),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
    );
    catalog
        .seed_builtin(
            fleet_core::BUILTIN_FLEET_SKILL_CATALOG_ID,
            fleet_skill_content()?,
            now,
        )
        .await
        .map_err(|error| error.to_string())
}

/// The implicit global assignment of the seeded `fleet` skill, for
/// desired-state composition (`with_builtin_assignments`). `None` when the
/// seed did not produce a version (an operator entry owns the name).
#[must_use]
pub fn fleet_skill_assignment(seed: &BuiltinSeed) -> Option<BuiltinSkillAssignment> {
    let version_id = match seed {
        BuiltinSeed::Current { version_id }
        | BuiltinSeed::Published { version_id }
        | BuiltinSeed::Updated { version_id } => version_id,
        BuiltinSeed::NameTaken { .. } => return None,
    };
    Some(BuiltinSkillAssignment {
        skill_id: "fleet".to_owned(),
        catalog_id: fleet_core::BUILTIN_FLEET_SKILL_CATALOG_ID.to_owned(),
        catalog_version_id: version_id.clone(),
        deploy_to: DEFAULT_BUILTIN_SKILL_AGENTS
            .iter()
            .map(|agent| (*agent).to_owned())
            .collect(),
    })
}

/// A one-line startup log of what seeding did.
#[must_use]
pub fn describe(seed: &BuiltinSeed) -> String {
    match seed {
        BuiltinSeed::Current { version_id } => {
            format!("built-in fleet skill is current ({version_id})")
        }
        BuiltinSeed::Published { version_id } => {
            format!("built-in fleet skill published {version_id}")
        }
        BuiltinSeed::Updated { version_id } => {
            format!("built-in fleet skill restored to {version_id}")
        }
        BuiltinSeed::NameTaken { detail } => format!(
            "built-in fleet skill not seeded: an operator catalog entry already uses its name ({detail})"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{fleet_skill_assignment, fleet_skill_content, frontmatter_field};

    #[test]
    fn the_shipped_skill_is_valid_catalog_content() {
        let content = fleet_skill_content().unwrap();
        assert_eq!(content.name, "fleet");
        // The catalog's own validation: frontmatter matches, no secrets, bounds.
        content.validate_and_digest().unwrap();
    }

    #[test]
    fn frontmatter_fields_are_read_only_inside_the_frontmatter() {
        let markdown = "---\nname: x\ndescription: y: z\n---\nname: not this\n";
        assert_eq!(frontmatter_field(markdown, "name"), Some("x"));
        assert_eq!(frontmatter_field(markdown, "description"), Some("y: z"));
        assert_eq!(frontmatter_field("no frontmatter", "name"), None);
    }

    #[test]
    fn an_operator_owned_name_yields_no_implicit_assignment() {
        let seed = fleet_application::skill_catalog::BuiltinSeed::NameTaken {
            detail: "taken".to_owned(),
        };
        assert!(fleet_skill_assignment(&seed).is_none());
    }
}
