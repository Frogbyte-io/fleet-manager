//! Versioned desired-resource schema generation and validation.

#![warn(missing_docs)]

use std::{
    collections::{BTreeSet, HashMap},
    fmt::{self, Write as _},
    path::{Path, PathBuf},
    str::FromStr,
};

use fleet_core::{ResourceId, Slug};
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
pub mod kinds;

use serde_json::Value;
use serde_saphyr::options::{DuplicateKeyPolicy, MergeKeyPolicy};

/// Current desired-resource API version.
pub const API_VERSION: &str = "fleet.frogbyte.io/v1alpha1";
/// Only resource kind registered by the generic-envelope milestone.
pub const FLEET_CONFIG_KIND: &str = "FleetConfig";
/// Repository-relative location of the generated schema.
pub const GENERATED_SCHEMA_PATH: &str = "schemas/generated/desired-resource.schema.json";

const RESOURCE_ID_PATTERN: &str =
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const SLUG_PATTERN: &str = r"^[a-z0-9]+(?:-[a-z0-9]+)*$";

/// The registered desired-resource API version.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
pub enum ApiVersion {
    /// Initial alpha desired-state contract.
    #[serde(rename = "fleet.frogbyte.io/v1alpha1")]
    FleetV1Alpha1,
}

/// Resource kinds currently published in the desired-state registry.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
pub enum ResourceKind {
    /// Controller-neutral repository settings.
    FleetConfig,
    /// Desired machine identity facts.
    Machine,
    /// The composition unit.
    Profile,
    /// Declared project tools and skills.
    Project,
    /// A pinned tool requirement.
    ToolRequirement,
    /// A skill preset deployment.
    SkillPreset,
    /// A bounded, reviewed command contract.
    Recipe,
    /// A named, parametrized recipe invocation.
    Action,
    /// M7's minimal versioned Lab contract.
    LabTemplate,
    /// A non-secret policy binding.
    PolicyBinding,
}

impl ResourceKind {
    /// The kind's stable string id.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::FleetConfig => "FleetConfig",
            Self::Machine => "Machine",
            Self::Profile => "Profile",
            Self::Project => "Project",
            Self::ToolRequirement => "ToolRequirement",
            Self::SkillPreset => "SkillPreset",
            Self::Recipe => "Recipe",
            Self::Action => "Action",
            Self::LabTemplate => "LabTemplate",
            Self::PolicyBinding => "PolicyBinding",
        }
    }
}

/// Generic desired-resource metadata.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// Stable opaque identity; renaming or moving a file does not change it.
    #[schemars(regex(pattern = RESOURCE_ID_PATTERN))]
    id: String,
    /// Mutable human-facing label.
    #[schemars(length(min = 1, max = 63), regex(pattern = SLUG_PATTERN))]
    name: String,
}

/// Minimal controller-neutral settings spec reserved for later extension.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FleetConfigSpec {}

/// The closed generic envelope for a desired resource. The spec stays a
/// raw object at the envelope level; per-kind validation selects the
/// spec's schema by the document's `kind`, so each kind's contract is
/// exact and the envelope never guesses.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DesiredResource {
    /// Version selecting the resource contract.
    api_version: ApiVersion,
    /// Resource type selecting the spec contract.
    kind: ResourceKind,
    /// Stable identity and mutable label.
    metadata: Metadata,
    /// Kind-specific non-secret desired configuration.
    spec: serde_json::Map<String, Value>,
}

/// One stable, caller-facing schema validation diagnostic.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Diagnostic {
    /// Stable machine-readable diagnostic code.
    pub code: &'static str,
    /// Source document and JSON-pointer-like location.
    pub location: String,
    /// Stable human-readable summary owned by Fleet.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} [{}] {}",
            self.location, self.code, self.message
        )
    }
}

/// An in-memory desired-state source supplied to [`validate_sources`].
#[derive(Clone, Debug)]
pub struct SourceDocument {
    /// Path used in diagnostics.
    pub path: PathBuf,
    /// UTF-8 YAML content, optionally containing multiple documents.
    pub yaml: String,
}

/// Generates the canonical Draft 2020-12 desired-resource schema: the
/// envelope plus an `allOf` of per-kind `if/then` pairs, so a document's
/// `kind` selects exactly one spec contract. One document means one
/// `$defs`, so every `$ref` resolves unambiguously.
///
/// # Panics
///
/// Panics only if Schemars emits a root schema that cannot be represented as a JSON object.
#[must_use]
pub fn generate_schema() -> Value {
    let envelope = serde_json::to_value(schema_for!(DesiredResource))
        .expect("Schemars output must serialize as JSON");
    let mut root = envelope;
    let root_object = root
        .as_object_mut()
        .expect("Schemars root schema must be an object");
    let mut all_of = Vec::new();
    for kind in [
        ResourceKind::FleetConfig,
        ResourceKind::Machine,
        ResourceKind::Profile,
        ResourceKind::Project,
        ResourceKind::ToolRequirement,
        ResourceKind::SkillPreset,
        ResourceKind::Recipe,
        ResourceKind::Action,
        ResourceKind::LabTemplate,
        ResourceKind::PolicyBinding,
    ] {
        let spec_schema = match kind {
            ResourceKind::FleetConfig => serde_json::to_value(schema_for!(FleetConfigSpec)),
            ResourceKind::Machine => serde_json::to_value(schema_for!(crate::kinds::MachineSpec)),
            ResourceKind::Profile => serde_json::to_value(schema_for!(crate::kinds::ProfileSpec)),
            ResourceKind::Project => serde_json::to_value(schema_for!(crate::kinds::ProjectSpec)),
            ResourceKind::ToolRequirement => {
                serde_json::to_value(schema_for!(crate::kinds::ToolRequirementSpec))
            }
            ResourceKind::SkillPreset => {
                serde_json::to_value(schema_for!(crate::kinds::SkillRequirementSpec))
            }
            ResourceKind::Recipe => serde_json::to_value(schema_for!(crate::kinds::RecipeSpec)),
            ResourceKind::Action => serde_json::to_value(schema_for!(crate::kinds::ActionSpec)),
            ResourceKind::LabTemplate => {
                serde_json::to_value(schema_for!(crate::kinds::LabTemplateSpec))
            }
            ResourceKind::PolicyBinding => {
                serde_json::to_value(schema_for!(crate::kinds::PolicyBindingSpec))
            }
        }
        .expect("Schemars output must serialize as JSON");
        // A spec schema carries its own $defs (nested types) and $schema;
        // both are hoisted/stripped so the spec's internal $refs resolve
        // against the ROOT document's $defs — the only $defs a JSON
        // Schema document can have.
        let mut spec_schema = spec_schema;
        if let Some(spec_object) = spec_schema.as_object_mut() {
            if let Some(defs) = spec_object.remove("$defs")
                && let Some(defs_object) = defs.as_object()
            {
                for (name, definition) in defs_object {
                    root_object.insert(format!("$defs:{name}"), definition.clone());
                }
            }
            spec_object.remove("$schema");
        }
        // Rewrite the spec schema's internal refs to the hoisted names.
        let rewritten =
            serde_json::to_string(&spec_schema).expect("the spec schema must serialize");
        let rewritten = rewritten.replace("#/$defs/", "#/$defs:");
        let spec_schema: Value =
            serde_json::from_str(&rewritten).expect("the rewritten spec schema must parse");
        all_of.push(serde_json::json!({
            "if": { "properties": { "kind": { "const": kind.id() } } },
            "then": { "properties": { "spec": spec_schema } },
        }));
    }
    root_object.insert("allOf".to_owned(), Value::Array(all_of));
    root
}

/// Returns the canonical pretty-printed checked-in schema text.
///
/// # Panics
///
/// Panics only if the generated schema cannot be serialized as JSON.
#[must_use]
pub fn generated_schema_text() -> String {
    let mut text = serde_json::to_string_pretty(&generate_schema())
        .expect("generated schema must serialize as JSON");
    text.push('\n');
    text
}

/// Validates YAML sources as one candidate desired-state collection.
///
/// # Panics
///
/// Panics only if the schema generated by this crate does not compile as Draft 2020-12.
#[must_use]
pub fn validate_sources(sources: &[SourceDocument]) -> Vec<Diagnostic> {
    let schema = generate_schema();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("the generated Draft 2020-12 schema must compile");
    let mut diagnostics = Vec::new();
    let mut identities: HashMap<String, String> = HashMap::new();

    for source in sources {
        let options = serde_saphyr::options! {
            duplicate_keys: DuplicateKeyPolicy::Error,
            merge_keys: MergeKeyPolicy::Error,
            strict_booleans: true,
            budget: serde_saphyr::budget! {
                max_nodes: 100_000,
                max_anchors: 1_000,
                max_aliases: 1_000,
                max_depth: 128,
            },
        };
        let documents: Vec<Value> =
            match serde_saphyr::from_multiple_with_options(&source.yaml, options) {
                Ok(documents) => documents,
                Err(error) => {
                    let mut location = source.path.display().to_string();
                    if let Some(position) = error.location() {
                        let _ = write!(location, ":{}:{}", position.line(), position.column());
                    }
                    diagnostics.push(Diagnostic {
                        code: "FM_SCHEMA_YAML_PARSE",
                        location,
                        message: "YAML could not be parsed under Fleet's strict input policy"
                            .to_owned(),
                    });
                    continue;
                }
            };

        for (index, document) in documents.iter().enumerate() {
            let base = format!("{}#document={}", source.path.display(), index + 1);
            validate_discriminator(document, &base, &mut diagnostics);

            if let Err(errors) = validator.validate(document) {
                for error in errors {
                    let instance_path = error.instance_path.to_string();
                    if has_specific_diagnostic(document, &instance_path) {
                        continue;
                    }
                    diagnostics.push(Diagnostic {
                        code: "FM_SCHEMA_INVALID",
                        location: format!("{base}{instance_path}"),
                        message: "document does not match the registered resource schema"
                            .to_owned(),
                    });
                }
            }

            if let Some(identity) = document.pointer("/metadata/id").and_then(Value::as_str)
                && ResourceId::from_str(identity).is_ok()
            {
                let location = format!("{base}/metadata/id");
                if let Some(first) = identities.get(identity) {
                    diagnostics.push(Diagnostic {
                        code: "FM_SCHEMA_DUPLICATE_ID",
                        location,
                        message: format!("resource identity was first declared at {first}"),
                    });
                } else {
                    identities.insert(identity.to_owned(), location);
                }
            }

            validate_core_values(document, &base, &mut diagnostics);
        }
    }

    let mut unique = BTreeSet::new();
    unique.extend(diagnostics);
    unique.into_iter().collect()
}

fn has_specific_diagnostic(document: &Value, pointer: &str) -> bool {
    match pointer {
        "/apiVersion" => document
            .get("apiVersion")
            .and_then(Value::as_str)
            .is_some_and(|version| version != API_VERSION),
        "/kind" => document
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| ResourceKind::deserialize(Value::String(kind.to_owned())).is_err()),
        "/metadata/id" => document
            .pointer(pointer)
            .and_then(Value::as_str)
            .is_some_and(|identity| ResourceId::from_str(identity).is_err()),
        "/metadata/name" => document
            .pointer(pointer)
            .and_then(Value::as_str)
            .is_some_and(|name| Slug::from_str(name).is_err()),
        _ => false,
    }
}

fn validate_discriminator(document: &Value, base: &str, diagnostics: &mut Vec<Diagnostic>) {
    if let Some(version) = document.get("apiVersion").and_then(Value::as_str)
        && version != API_VERSION
    {
        diagnostics.push(Diagnostic {
            code: "FM_SCHEMA_UNKNOWN_API_VERSION",
            location: format!("{base}/apiVersion"),
            message: format!("unsupported apiVersion {version:?}"),
        });
    }
    if let Some(kind) = document.get("kind").and_then(Value::as_str)
        && ResourceKind::deserialize(Value::String(kind.to_owned())).is_err()
    {
        diagnostics.push(Diagnostic {
            code: "FM_SCHEMA_UNKNOWN_KIND",
            location: format!("{base}/kind"),
            message: format!("unsupported kind {kind:?}"),
        });
    }
}

fn validate_core_values(document: &Value, base: &str, diagnostics: &mut Vec<Diagnostic>) {
    if let Some(identity) = document.pointer("/metadata/id").and_then(Value::as_str)
        && ResourceId::from_str(identity).is_err()
    {
        diagnostics.push(Diagnostic {
            code: "FM_SCHEMA_INVALID_ID",
            location: format!("{base}/metadata/id"),
            message: "metadata.id must be a lowercase, hyphenated UUIDv7".to_owned(),
        });
    }
    if let Some(name) = document.pointer("/metadata/name").and_then(Value::as_str)
        && Slug::from_str(name).is_err()
    {
        diagnostics.push(Diagnostic {
            code: "FM_SCHEMA_INVALID_NAME",
            location: format!("{base}/metadata/name"),
            message: "metadata.name must be a portable lowercase slug".to_owned(),
        });
    }
}

/// Reads and validates source paths as one candidate collection.
///
/// # Errors
///
/// Returns an I/O error when any source cannot be read.
pub fn validate_paths(paths: &[PathBuf]) -> std::io::Result<Vec<Diagnostic>> {
    let sources = paths
        .iter()
        .map(|path| {
            std::fs::read_to_string(path).map(|yaml| SourceDocument {
                path: path.clone(),
                yaml,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(validate_sources(&sources))
}

/// Returns the generated schema path under a repository root.
#[must_use]
pub fn generated_schema_path(root: &Path) -> PathBuf {
    root.join(GENERATED_SCHEMA_PATH)
}
