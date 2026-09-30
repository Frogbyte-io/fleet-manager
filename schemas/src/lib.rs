//! Versioned desired-resource schema generation and validation.

#![warn(missing_docs)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
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
/// The generic-envelope milestone's resource kind, retained for the
/// envelope's own diagnostics.
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
                serde_json::to_value(schema_for!(crate::kinds::SkillPresetSpec))
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
    root_object.insert(
        "$id".to_owned(),
        Value::String(
            "https://schemas.frogbyte.io/fleet/desired-resource-v1alpha1.json".to_owned(),
        ),
    );
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

/// The strict YAML input policy shared by validation and parsing.
fn strict_yaml_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        duplicate_keys: DuplicateKeyPolicy::Error,
        merge_keys: MergeKeyPolicy::Error,
        strict_booleans: true,
        budget: serde_saphyr::budget! {
            max_nodes: 100_000,
            max_anchors: 1_000,
            max_aliases: 1_000,
            max_depth: 128,
        },
    }
}

/// One validated desired resource, ready to persist as part of a snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedResource {
    /// The resource kind id.
    pub kind: String,
    /// The stable resource identity.
    pub id: String,
    /// The mutable human-facing label.
    pub name: String,
    /// The kind-specific non-secret spec.
    pub spec: Value,
}

/// Validates the sources as one candidate and returns their resources,
/// sorted by kind then identity. A collection with any diagnostic yields
/// no resources: an invalid document can never be parsed into a snapshot.
///
/// # Errors
///
/// Returns the rendered diagnostics when the collection is invalid.
pub fn parse_resources(sources: &[SourceDocument]) -> Result<Vec<ParsedResource>, Vec<String>> {
    let diagnostics = validate_sources(sources);
    if !diagnostics.is_empty() {
        return Err(diagnostics.iter().map(ToString::to_string).collect());
    }
    let mut resources = Vec::new();
    for source in sources {
        let documents: Vec<Value> =
            serde_saphyr::from_multiple_with_options(&source.yaml, strict_yaml_options())
                .map_err(|_| vec![format!("{} could not be parsed", source.path.display())])?;
        for document in documents {
            let text = |pointer: &str| {
                document
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            resources.push(ParsedResource {
                kind: text("/kind"),
                id: text("/metadata/id"),
                name: text("/metadata/name"),
                spec: document.get("spec").cloned().unwrap_or(Value::Null),
            });
        }
    }
    resources.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
    Ok(resources)
}

/// Reads the paths and parses them like [`parse_resources`].
///
/// # Errors
///
/// Returns the diagnostics, or a single message when a file is unreadable.
pub fn parse_paths(paths: &[PathBuf]) -> Result<Vec<ParsedResource>, Vec<String>> {
    let sources = paths
        .iter()
        .map(|path| {
            std::fs::read_to_string(path).map(|yaml| SourceDocument {
                path: path.clone(),
                yaml,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| vec![format!("a candidate file is unreadable: {error}")])?;
    parse_resources(&sources)
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
    let mut collection: Vec<(String, Value)> = Vec::new();

    for source in sources {
        let documents: Vec<Value> =
            match serde_saphyr::from_multiple_with_options(&source.yaml, strict_yaml_options()) {
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
            validate_semantics(document, &base, &mut diagnostics);
            collection.push((base, document.clone()));
        }
    }
    validate_references(&collection, &mut diagnostics);

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

/// Semantic validation beyond the schema: credential-bearing references
/// and remotes are refused before activation, because a schema-valid
/// document can still carry secrets in its string fields.
fn validate_semantics(document: &Value, base: &str, diagnostics: &mut Vec<Diagnostic>) {
    let kind = document
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if kind == "SkillPreset"
        && let Some(spec) = document.get("spec")
    {
        let catalog_id = spec.get("catalogId").and_then(Value::as_str);
        let catalog_version_id = spec.get("catalogVersionId").and_then(Value::as_str);
        match (catalog_id, catalog_version_id) {
            (Some(catalog), Some(version))
                if !catalog.trim().is_empty()
                    && !version.trim().is_empty()
                    && !catalog.contains('/')
                    && !version.contains('/')
                    && version
                        .strip_prefix(catalog)
                        .and_then(|suffix| suffix.strip_prefix('@'))
                        .is_some_and(|digest| {
                            digest.len() == 64
                                && digest.chars().all(|character| {
                                    character.is_ascii_digit() || ('a'..='f').contains(&character)
                                })
                        }) => {}
            (None, None) => {}
            _ => diagnostics.push(Diagnostic {
                code: "FM_SCHEMA_SEMANTIC_INVALID_SKILL_ASSIGNMENT",
                location: format!("{base}/spec"),
                message: "catalogId and catalogVersionId must both be omitted or a non-empty catalog ID and its generated <catalogId>@<sha256> version ID".to_owned(),
            }),
        }
        for field in ["skillId", "deployTo", "denyAgents"] {
            let values: Vec<(usize, &str)> = if field == "skillId" {
                spec.get(field)
                    .and_then(Value::as_str)
                    .map(|value| vec![(0, value)])
                    .unwrap_or_default()
            } else {
                spec.get(field)
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .enumerate()
                            .filter_map(|(index, item)| item.as_str().map(|value| (index, value)))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            for (index, value) in values {
                if value.trim().is_empty() || value.contains('/') {
                    let pointer = if field == "skillId" {
                        format!("{base}/spec/{field}")
                    } else {
                        format!("{base}/spec/{field}/{index}")
                    };
                    diagnostics.push(Diagnostic {
                        code: "FM_SCHEMA_SEMANTIC_INVALID_SKILL_ASSIGNMENT",
                        location: pointer,
                        message: "skill and agent IDs must be non-empty and contain no slash"
                            .to_owned(),
                    });
                }
            }
        }
    }
    // Machine endpoints: credential-bearing userinfo is refused.
    if kind == "Machine"
        && let Some(endpoints) = document
            .pointer("/spec/endpoints")
            .and_then(Value::as_array)
    {
        for (index, endpoint) in endpoints.iter().enumerate() {
            let Some(reference) = endpoint.get("reference").and_then(Value::as_str) else {
                continue;
            };
            let Some((userinfo, _authority)) = reference.split_once('@') else {
                continue;
            };
            if userinfo.contains(':') {
                diagnostics.push(Diagnostic {
                    code: "FM_SCHEMA_SEMANTIC_CREDENTIAL_REFERENCE",
                    location: format!("{base}/spec/endpoints/{index}/reference"),
                    message: "an endpoint reference must not carry credentials; reference the machine's secret records instead".to_owned(),
                });
            }
        }
    }
    // Project remotes: the normalized-remote grammar refuses
    // credential-bearing remotes before activation.
    if kind == "Project"
        && let Some(remote) = document.pointer("/spec/remote").and_then(Value::as_str)
        && let Err(detail) = fleet_core::NormalizedRemote::parse(remote)
    {
        diagnostics.push(Diagnostic {
            code: "FM_SCHEMA_SEMANTIC_INVALID_REMOTE",
            location: format!("{base}/spec/remote"),
            message: format!("the project remote is not a normalizable remote: {detail}"),
        });
    }
}

/// Collection-level semantic validation (ADR 0014): a machine's profile and
/// project bindings, and a profile's `extends`, must name resources in the
/// same candidate revision, and `extends` must not cycle. Resource names
/// are the reference key, so they must be unique within a bindable kind.
fn validate_references(collection: &[(String, Value)], diagnostics: &mut Vec<Diagnostic>) {
    let mut profiles: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut projects: BTreeSet<&str> = BTreeSet::new();
    let mut seen: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    for (base, document) in collection {
        let kind = document
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(name) = document.pointer("/metadata/name").and_then(Value::as_str) else {
            continue;
        };
        if !matches!(kind, "Machine" | "Profile" | "Project") {
            continue;
        }
        if let Some(first) = seen.insert((kind, name), base) {
            diagnostics.push(Diagnostic {
                code: "FM_SCHEMA_SEMANTIC_DUPLICATE_NAME",
                location: format!("{base}/metadata/name"),
                message: format!(
                    "the {kind} name {name:?} was first declared at {first}; bindings reference resources by name"
                ),
            });
            continue;
        }
        match kind {
            "Profile" => {
                let extends = string_items(document.pointer("/spec/extends"))
                    .into_iter()
                    .map(|(_, value)| value)
                    .collect();
                profiles.insert(name, extends);
            }
            "Project" => {
                projects.insert(name);
            }
            _ => {}
        }
    }
    for (base, document) in collection {
        let kind = document
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match kind {
            "Machine" => {
                for (field, known, noun) in [
                    ("profiles", None, "profile"),
                    ("projects", Some(&projects), "project"),
                ] {
                    for (index, name) in string_items(document.pointer(&format!("/spec/{field}"))) {
                        let resolved = known.map_or_else(
                            || profiles.contains_key(name),
                            |names| names.contains(name),
                        );
                        if !resolved {
                            diagnostics.push(Diagnostic {
                                code: "FM_SCHEMA_SEMANTIC_UNRESOLVED_REFERENCE",
                                location: format!("{base}/spec/{field}/{index}"),
                                message: format!(
                                    "no {noun} named {name:?} exists in this revision"
                                ),
                            });
                        }
                    }
                }
            }
            "Profile" => {
                let own = document
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                for (index, parent) in string_items(document.pointer("/spec/extends")) {
                    if !profiles.contains_key(parent) {
                        diagnostics.push(Diagnostic {
                            code: "FM_SCHEMA_SEMANTIC_UNRESOLVED_REFERENCE",
                            location: format!("{base}/spec/extends/{index}"),
                            message: format!("no profile named {parent:?} exists in this revision"),
                        });
                    } else if extends_reaches(&profiles, parent, own) {
                        diagnostics.push(Diagnostic {
                            code: "FM_SCHEMA_SEMANTIC_PROFILE_CYCLE",
                            location: format!("{base}/spec/extends/{index}"),
                            message: format!(
                                "profile {own:?} extending {parent:?} forms an extends cycle"
                            ),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

/// The string items of an optional JSON array, with their positions.
fn string_items(value: Option<&Value>) -> Vec<(usize, &str)> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .enumerate()
                .filter_map(|(index, item)| item.as_str().map(|text| (index, text)))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `target` is reachable from `start` through `extends` edges.
fn extends_reaches(profiles: &BTreeMap<&str, Vec<&str>>, start: &str, target: &str) -> bool {
    let mut visited = BTreeSet::new();
    let mut stack = vec![start];
    while let Some(name) = stack.pop() {
        if name == target {
            return true;
        }
        if !visited.insert(name) {
            continue;
        }
        if let Some(parents) = profiles.get(name) {
            stack.extend(parents.iter().copied());
        }
    }
    false
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
