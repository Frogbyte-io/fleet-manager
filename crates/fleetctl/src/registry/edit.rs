//! Registry entry editing in a local Fleet Git checkout.
//!
//! Every edit is computed on the entry's JSON model, validated as part of
//! the whole tree in memory, and only then written. Credential-looking
//! values, unknown fields, wrong value types, and a broken relation are all
//! refused by the same validator the controller runs, so nothing invalid is
//! written. No diagnostic or error here echoes a value an author supplied.
//!
//! YAML formatting: an existing file is patched in place with `yamlpatch`
//! (comments, key order, and untouched lines survive), and the patched text
//! is parsed back and compared with the intended model. When the patch
//! engine cannot honour a change exactly, the file is rewritten in the
//! canonical layout (comments are then lost, and the outcome says so). A
//! new file always uses the canonical layout.

use std::{borrow::Cow, collections::BTreeSet, path::Path};

use fleet_schema::{
    API_VERSION,
    kinds::{RegistryFieldSpec, RegistryScalarType, RegistryTypeSpec, RegistryValueType},
};
use serde_json::{Map, Value, json};
use yamlpatch::{Op, Patch};
use yamlpath::Component;

use super::tree::{self, REGISTRY_DIR, SourceFile};
use crate::CliError;

/// `<type>/<key>`, the address of one entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryRef {
    /// The Registry type name.
    pub entry_type: String,
    /// The natural key.
    pub key: String,
}

impl std::fmt::Display for EntryRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.entry_type, self.key)
    }
}

/// A lowercase slug of at most 63 characters, as a type or relation name.
pub(super) fn is_slug(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() && !c.is_ascii_uppercase())
        })
}

/// A natural key: at most 128 characters, starting with a letter or digit,
/// then letters, digits, and `. _ @ + -`. This is the validator's own rule,
/// and it makes the key a single safe path component (no `/`, no `..`).
pub(super) fn is_key(key: &str) -> bool {
    let mut chars = key.chars();
    key.len() <= 128
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '+' | '-'))
}

impl EntryRef {
    /// Parses `<type>/<key>`.
    ///
    /// # Errors
    ///
    /// Fails when the text is not a type slug and a path-safe key.
    pub fn parse(text: &str) -> Result<Self, CliError> {
        let bad = |why: &str| CliError {
            message: format!(
                "an entry is addressed as <type>/<key>, for example domain/example.com: {why}"
            ),
        };
        let (entry_type, key) = text.split_once('/').ok_or_else(|| bad("no `/` found"))?;
        if !is_slug(entry_type) {
            return Err(bad("the type must be a lowercase slug"));
        }
        if !is_key(key) {
            return Err(bad(
                "the key must start with a letter or digit and use only letters, digits, and . _ @ + -",
            ));
        }
        Ok(Self {
            entry_type: entry_type.to_owned(),
            key: key.to_owned(),
        })
    }

    /// The conventional path: `fleet/registry/<type>/<key>.yaml`, with the
    /// key lowercased so two spellings cannot collide on a case-insensitive
    /// file system.
    fn path(&self) -> String {
        format!(
            "{REGISTRY_DIR}/{}/{}.yaml",
            self.entry_type,
            self.key.to_ascii_lowercase()
        )
    }

    /// The `metadata.name` slug (`domain-example-com`).
    fn slug_name(&self) -> String {
        let mut name = String::new();
        for c in format!("{}-{}", self.entry_type, self.key).chars() {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() {
                name.push(c);
            } else if !name.ends_with('-') {
                name.push('-');
            }
        }
        name.truncate(63);
        name.trim_matches('-').to_owned()
    }
}

/// One edit to one entry.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Change {
    /// Create the entry or patch the named parts of it.
    Set {
        /// `--field name=value`, as typed.
        fields: Vec<(String, String)>,
        /// `--notes`, when given.
        notes: Option<String>,
        /// A JSON patch (`--from-json`).
        patch: Option<Value>,
    },
    /// Remove fields (and optionally the notes).
    Unset {
        /// Field names to remove.
        fields: Vec<String>,
        /// Whether to remove the notes.
        notes: bool,
    },
    /// Add or remove tags.
    Tags {
        /// `true` to add.
        add: bool,
        /// The tags.
        tags: Vec<String>,
    },
    /// Add or remove one relation.
    Relate {
        /// The relation type.
        relation: String,
        /// The target object, for example `{"registry": "service/x"}`.
        target: Value,
        /// `true` to remove it.
        remove: bool,
    },
}

/// What an edit did, for the command's output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Outcome {
    /// The checkout-relative path of the entry's file.
    pub path: String,
    /// Whether the file was created.
    pub created: bool,
    /// Whether anything changed.
    pub changed: bool,
    /// `new`, `preserved`, `canonical`, or `unchanged`.
    pub formatting: &'static str,
    /// New non-blocking diagnostics, rendered.
    pub warnings: Vec<String>,
}

/// A located entry document.
struct Located {
    file: usize,
    document: Value,
    documents_in_file: usize,
}

/// Finds the entry by type and key (compared case-insensitively) anywhere
/// in the file set: identity is metadata, the path is only a convention.
fn locate(
    files: &[SourceFile],
    types: &std::collections::BTreeMap<String, RegistryTypeSpec>,
    reference: &EntryRef,
) -> Result<Option<Located>, CliError> {
    let Some(key_field) = types
        .get(&reference.entry_type)
        .map(|spec| spec.key.as_str())
    else {
        return Err(unknown_type(types, &reference.entry_type));
    };
    let mut found: Option<Located> = None;
    for (index, file) in files.iter().enumerate() {
        let Ok(documents) = tree::parse_documents(&file.text) else {
            continue;
        };
        let count = documents.len();
        for document in documents {
            let matches = document.get("kind").and_then(Value::as_str) == Some("RegistryEntry")
                && document.pointer("/spec/type").and_then(Value::as_str)
                    == Some(reference.entry_type.as_str())
                && document
                    .pointer("/spec/fields")
                    .and_then(|fields| fields.get(key_field))
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case(&reference.key));
            if matches {
                if found.is_some() {
                    return Err(CliError {
                        message: format!(
                            "more than one entry is {reference}; run `fleetctl registry validate` and fix the duplicate first"
                        ),
                    });
                }
                found = Some(Located {
                    file: index,
                    document,
                    documents_in_file: count,
                });
            }
        }
    }
    Ok(found)
}

fn unknown_type(
    types: &std::collections::BTreeMap<String, RegistryTypeSpec>,
    name: &str,
) -> CliError {
    let known = types.keys().cloned().collect::<Vec<_>>().join(", ");
    CliError {
        message: format!(
            "no Registry type named {name:?} is built in or defined in this checkout (known: {known})"
        ),
    }
}

/// Parses one `--field name=value` value by the field's declared type.
/// Never echoes the value.
fn parse_field(name: &str, field: &RegistryFieldSpec, raw: &str) -> Result<Value, CliError> {
    let bad = |expected: &str| CliError {
        message: format!("field {name:?} expects {expected}"),
    };
    if raw.is_empty() {
        return Err(CliError {
            message: format!(
                "field {name:?} has an empty value; use `fleetctl registry unset` to remove it"
            ),
        });
    }
    let scalar = |kind: RegistryScalarType, text: &str| -> Result<Value, CliError> {
        match kind {
            RegistryScalarType::Boolean => match text {
                "true" => Ok(Value::Bool(true)),
                "false" => Ok(Value::Bool(false)),
                _ => Err(bad("true or false")),
            },
            RegistryScalarType::Number => {
                if let Ok(integer) = text.parse::<i64>() {
                    Ok(json!(integer))
                } else {
                    text.parse::<f64>()
                        .ok()
                        .and_then(serde_json::Number::from_f64)
                        .map(Value::Number)
                        .ok_or_else(|| bad("a number"))
                }
            }
            _ => Ok(Value::String(text.to_owned())),
        }
    };
    match field.value_type {
        RegistryValueType::List => {
            let item = field.items.unwrap_or(RegistryScalarType::String);
            if raw.starts_with('[') {
                let list: Vec<Value> = serde_json::from_str(raw)
                    .map_err(|_| bad("a comma-separated list or a JSON array"))?;
                return Ok(Value::Array(list));
            }
            let items = raw
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(|part| scalar(item, part))
                .collect::<Result<Vec<_>, _>>()?;
            if items.is_empty() {
                return Err(bad("at least one item"));
            }
            Ok(Value::Array(items))
        }
        other => scalar(other.scalar().unwrap_or(RegistryScalarType::String), raw),
    }
}

fn fields_mut(spec: &mut Map<String, Value>) -> &mut Map<String, Value> {
    if !spec.get("fields").is_some_and(Value::is_object) {
        spec.insert("fields".to_owned(), Value::Object(Map::new()));
    }
    spec.get_mut("fields")
        .and_then(Value::as_object_mut)
        .expect("fields was just ensured to be an object")
}

fn string_list(spec: &mut Map<String, Value>, name: &str) -> Vec<Value> {
    spec.get(name)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Applies a change to the entry's spec. `key_field` and `key` guard the
/// natural key: it is set at creation and never changed or removed.
#[allow(clippy::too_many_lines)]
fn apply_change(
    spec: &mut Map<String, Value>,
    type_spec: &RegistryTypeSpec,
    key: &str,
    change: &Change,
) -> Result<(), CliError> {
    let key_field = type_spec.key.as_str();
    match change {
        Change::Set {
            fields,
            notes,
            patch,
        } => {
            for (name, raw) in fields {
                let Some(definition) = type_spec.fields.get(name) else {
                    let known = type_spec
                        .fields
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(CliError {
                        message: format!("the type declares no field {name:?} (declared: {known})"),
                    });
                };
                let value = parse_field(name, definition, raw)?;
                if name == key_field {
                    if value.as_str().is_some_and(|v| v.eq_ignore_ascii_case(key)) {
                        continue;
                    }
                    return Err(CliError {
                        message: format!(
                            "{name:?} is the key field; it must match the key in the entry address"
                        ),
                    });
                }
                fields_mut(spec).insert(name.clone(), value);
            }
            if let Some(notes) = notes {
                spec.insert("notes".to_owned(), Value::String(notes.clone()));
            }
            if let Some(patch) = patch {
                apply_json_patch(spec, key_field, key, patch)?;
            }
        }
        Change::Unset { fields, notes } => {
            for name in fields {
                if name == key_field {
                    return Err(CliError {
                        message: format!(
                            "{name:?} is the key field and cannot be unset; use `fleetctl registry rm` to delete the entry"
                        ),
                    });
                }
                fields_mut(spec).remove(name);
            }
            if *notes {
                spec.remove("notes");
            }
        }
        Change::Tags { add, tags } => {
            let mut list = string_list(spec, "tags");
            for tag in tags {
                let present = list.iter().any(|item| item.as_str() == Some(tag));
                if *add && !present {
                    list.push(Value::String(tag.clone()));
                } else if !*add {
                    list.retain(|item| item.as_str() != Some(tag));
                }
            }
            spec.insert("tags".to_owned(), Value::Array(list));
        }
        Change::Relate {
            relation,
            target,
            remove,
        } => {
            let mut list = string_list(spec, "relations");
            let wanted = json!({"type": relation, "target": target});
            if *remove {
                list.retain(|item| *item != wanted);
            } else if !list.contains(&wanted) {
                list.push(wanted);
            }
            spec.insert("relations".to_owned(), Value::Array(list));
        }
    }
    Ok(())
}

/// `--from-json`: `fields` merge by name (`null` removes), and `tags`,
/// `links`, `relations`, and `notes` replace the whole property.
fn apply_json_patch(
    spec: &mut Map<String, Value>,
    key_field: &str,
    key: &str,
    patch: &Value,
) -> Result<(), CliError> {
    let Some(object) = patch.as_object() else {
        return Err(CliError {
            message: "--from-json expects a JSON object".to_owned(),
        });
    };
    for (name, value) in object {
        match name.as_str() {
            "fields" => {
                let Some(fields) = value.as_object() else {
                    return Err(CliError {
                        message: "\"fields\" in --from-json must be an object".to_owned(),
                    });
                };
                for (field, item) in fields {
                    if field == key_field {
                        if item.as_str().is_some_and(|v| v.eq_ignore_ascii_case(key)) {
                            continue;
                        }
                        return Err(CliError {
                            message: format!(
                                "{field:?} is the key field; it must match the key in the entry address"
                            ),
                        });
                    }
                    if item.is_null() {
                        fields_mut(spec).remove(field);
                    } else {
                        fields_mut(spec).insert(field.clone(), item.clone());
                    }
                }
            }
            "tags" | "links" | "relations" | "notes" => {
                if value.is_null() {
                    spec.remove(name);
                } else {
                    spec.insert(name.clone(), value.clone());
                }
            }
            other => {
                return Err(CliError {
                    message: format!(
                        "--from-json accepts fields, tags, links, notes, and relations, not {:?}",
                        if is_slug(other) {
                            other
                        } else {
                            "<invalid-name>"
                        }
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Drops empty optional properties, so an emptied list is absent from the
/// file rather than `null`.
fn normalize(document: &mut Value) {
    let Some(spec) = document.get_mut("spec").and_then(Value::as_object_mut) else {
        return;
    };
    for name in ["tags", "links", "relations"] {
        if spec
            .get(name)
            .is_some_and(|value| value.as_array().is_some_and(Vec::is_empty) || value.is_null())
        {
            spec.remove(name);
        }
    }
    if spec
        .get("notes")
        .is_some_and(|value| value.is_null() || value.as_str().is_some_and(str::is_empty))
    {
        spec.remove("notes");
    }
}

fn new_document(reference: &EntryRef, type_spec: &RegistryTypeSpec) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "kind": "RegistryEntry",
        "metadata": {
            "id": uuid::Uuid::now_v7().to_string(),
            "name": reference.slug_name(),
        },
        "spec": {
            "type": reference.entry_type,
            "fields": { type_spec.key.clone(): reference.key },
        },
    })
}

// --- YAML rendering -------------------------------------------------------

/// The key order of a canonical file, by path.
fn key_order(context: &str) -> &'static [&'static str] {
    match context {
        "" => &["apiVersion", "kind", "metadata", "spec"],
        "/metadata" => &["id", "name"],
        "/spec" => &["type", "fields", "tags", "links", "notes", "relations"],
        "/spec/links/*" => &["label", "url"],
        "/spec/relations/*" => &["type", "target"],
        _ => &[],
    }
}

fn ordered(value: &Value, context: &str) -> yaml_serde::Value {
    match value {
        Value::Object(map) => {
            let order = key_order(context);
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_key(|key| {
                (
                    order
                        .iter()
                        .position(|name| name == &key.as_str())
                        .unwrap_or(usize::MAX),
                    (*key).clone(),
                )
            });
            let mut mapping = yaml_serde::Mapping::new();
            for key in keys {
                mapping.insert(
                    yaml_serde::Value::String(key.clone()),
                    ordered(&map[key], &format!("{context}/{key}")),
                );
            }
            yaml_serde::Value::Mapping(mapping)
        }
        Value::Array(items) => yaml_serde::Value::Sequence(
            items
                .iter()
                .map(|item| ordered(item, &format!("{context}/*")))
                .collect(),
        ),
        leaf => yaml_serde::to_value(leaf).unwrap_or(yaml_serde::Value::Null),
    }
}

/// The canonical layout of an entry document.
fn canonical(document: &Value) -> Result<String, CliError> {
    let text = yaml_serde::to_string(&ordered(document, "")).map_err(|error| CliError {
        message: format!("the entry could not be formatted: {error}"),
    })?;
    // The canonical text must read back as exactly the intended model.
    if tree::parse_documents(&text).ok().as_deref() != Some(std::slice::from_ref(document)) {
        return Err(CliError {
            message: "the entry could not be written as YAML without changing a value".to_owned(),
        });
    }
    Ok(text)
}

fn route(path: &[Component<'static>]) -> yamlpath::Route<'static> {
    yamlpath::Route::from(path.to_vec())
}

/// Computes the patches that turn `old` into `new`.
fn diff(
    old: &Value,
    new: &Value,
    path: &mut Vec<Component<'static>>,
    patches: &mut Vec<Patch<'static>>,
) {
    if old == new {
        return;
    }
    match (old, new) {
        (Value::Object(before), Value::Object(after)) => {
            for key in before.keys().filter(|key| !after.contains_key(*key)) {
                path.push(Component::Key(Cow::Owned(key.clone())));
                patches.push(Patch {
                    route: route(path),
                    operation: Op::Remove,
                });
                path.pop();
            }
            for (key, value) in after {
                match before.get(key) {
                    None => patches.push(Patch {
                        route: route(path),
                        operation: Op::Add {
                            key: key.clone(),
                            value: yaml_serde::to_value(value).unwrap_or(yaml_serde::Value::Null),
                        },
                    }),
                    Some(previous) => {
                        path.push(Component::Key(Cow::Owned(key.clone())));
                        diff(previous, value, path, patches);
                        path.pop();
                    }
                }
            }
        }
        (Value::Array(before), Value::Array(after))
            if after.len() > before.len() && after[..before.len()] == before[..] =>
        {
            for item in &after[before.len()..] {
                patches.push(Patch {
                    route: route(path),
                    operation: Op::Append {
                        value: yaml_serde::to_value(item).unwrap_or(yaml_serde::Value::Null),
                    },
                });
            }
        }
        (Value::Array(before), Value::Array(after)) if after.len() + 1 == before.len() => {
            // One element removed: find which, when the rest is unchanged.
            let index = (0..before.len()).find(|index| {
                let mut rest = before.clone();
                rest.remove(*index);
                rest == *after
            });
            if let Some(index) = index {
                path.push(Component::Index(index));
                patches.push(Patch {
                    route: route(path),
                    operation: Op::Remove,
                });
                path.pop();
            } else {
                replace(new, path, patches);
            }
        }
        _ => replace(new, path, patches),
    }
}

fn replace(new: &Value, path: &[Component<'static>], patches: &mut Vec<Patch<'static>>) {
    patches.push(Patch {
        route: route(path),
        operation: Op::Replace(yaml_serde::to_value(new).unwrap_or(yaml_serde::Value::Null)),
    });
}

/// Patches `text` (one document, `old`) into `new`, or `None` when the
/// patch engine cannot reproduce the intended model exactly.
fn patched(text: &str, old: &Value, new: &Value) -> Option<String> {
    let mut patches = Vec::new();
    diff(old, new, &mut Vec::new(), &mut patches);
    if patches.is_empty() {
        return Some(text.to_owned());
    }
    let document = yamlpath::Document::new(text).ok()?;
    let result = yamlpatch::apply_yaml_patches(&document, &patches).ok()?;
    let result = result.source().to_owned();
    let reparsed = tree::parse_documents(&result).ok()?;
    (reparsed.as_slice() == std::slice::from_ref(new)).then_some(result)
}

/// Renders the new text of a file and says how it was produced.
fn render(
    existing: Option<(&str, &Value)>,
    new: &Value,
) -> Result<(String, &'static str), CliError> {
    match existing {
        None => Ok((canonical(new)?, "new")),
        Some((text, old)) if old == new => Ok((text.to_owned(), "unchanged")),
        Some((text, old)) => match patched(text, old, new) {
            Some(result) => Ok((result, "preserved")),
            None => Ok((canonical(new)?, "canonical")),
        },
    }
}

// --- the edit ---------------------------------------------------------------

fn write_file(root: &Path, rel: &str, text: &str) -> Result<(), CliError> {
    let path = root.join(rel);
    let io = |error: std::io::Error| CliError {
        message: format!("{rel} could not be written: {error}"),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    let temporary = path.with_extension("yaml.tmp");
    std::fs::write(&temporary, text).map_err(io)?;
    std::fs::rename(&temporary, &path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        io(error)
    })
}

/// Refuses an edit that would introduce a validation error, comparing the
/// whole tree before and after, and returns the new warnings.
fn check_tree(files: &[SourceFile], after: &[SourceFile]) -> Result<Vec<String>, CliError> {
    let before = tree::validate(files);
    let result = tree::validate(after);
    let known_errors: BTreeSet<_> = before.errors.iter().collect();
    let new_errors: Vec<String> = result
        .errors
        .iter()
        .filter(|error| !known_errors.contains(error))
        .map(ToString::to_string)
        .collect();
    if !new_errors.is_empty() {
        return Err(CliError {
            message: format!(
                "refusing to write: the change would introduce {} validation error(s); nothing was written\n  {}",
                new_errors.len(),
                new_errors.join("\n  ")
            ),
        });
    }
    let known_warnings: BTreeSet<_> = before.warnings.iter().collect();
    Ok(result
        .warnings
        .iter()
        .filter(|warning| !known_warnings.contains(warning))
        .map(ToString::to_string)
        .collect())
}

/// Applies `change` to the entry at `reference` in the checkout at `root`.
pub(super) fn apply(
    root: &Path,
    reference: &EntryRef,
    change: &Change,
) -> Result<Outcome, CliError> {
    let files = tree::load(root)?;
    let types = tree::type_definitions(&files);
    let type_spec = types
        .get(&reference.entry_type)
        .ok_or_else(|| unknown_type(&types, &reference.entry_type))?;
    let located = locate(&files, &types, reference)?;

    let (mut document, existing) = match &located {
        Some(found) => {
            if found.documents_in_file > 1 {
                return Err(CliError {
                    message: format!(
                        "{reference} lives in {}, which holds several documents; split it into one file per entry before editing",
                        files[found.file].rel
                    ),
                });
            }
            (found.document.clone(), Some(found))
        }
        None if matches!(change, Change::Set { .. }) => (new_document(reference, type_spec), None),
        None => {
            return Err(CliError {
                message: format!("there is no entry {reference} in this checkout"),
            });
        }
    };
    {
        let spec = document
            .get_mut("spec")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| CliError {
                message: format!("{reference} has no spec object"),
            })?;
        apply_change(spec, type_spec, &reference.key, change)?;
    }
    normalize(&mut document);

    #[allow(clippy::single_match_else)]
    let (rel, existing_text) = match existing {
        Some(found) => (
            files[found.file].rel.clone(),
            Some((files[found.file].text.as_str(), &found.document)),
        ),
        None => {
            let rel = reference.path();
            if files.iter().any(|file| file.rel == rel) {
                return Err(CliError {
                    message: format!(
                        "{rel} already holds a different document; resolve it before adding {reference}"
                    ),
                });
            }
            (rel, None)
        }
    };
    let created = existing_text.is_none();
    let (text, formatting) = render(existing_text, &document)?;
    if formatting == "unchanged" {
        return Ok(Outcome {
            path: rel,
            created: false,
            changed: false,
            formatting,
            warnings: Vec::new(),
        });
    }

    let mut after: Vec<SourceFile> = files.clone();
    match after.iter_mut().find(|file| file.rel == rel) {
        Some(file) => file.text.clone_from(&text),
        None => after.push(SourceFile {
            rel: rel.clone(),
            text: text.clone(),
        }),
    }
    let warnings = check_tree(&files, &after)?;
    write_file(root, &rel, &text)?;
    Ok(Outcome {
        path: rel,
        created,
        changed: true,
        formatting,
        warnings,
    })
}

/// The result of `rm`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Removal {
    /// The deleted file.
    pub path: String,
    /// Entries that still relate to the removed one.
    pub referenced_by: Vec<String>,
}

/// Deletes an entry's file. Relations that still point at it are reported,
/// not refused: a dangling relation is a warning everywhere else too.
pub(super) fn remove(root: &Path, reference: &EntryRef) -> Result<Removal, CliError> {
    let files = tree::load(root)?;
    let types = tree::type_definitions(&files);
    let found = locate(&files, &types, reference)?.ok_or_else(|| CliError {
        message: format!("there is no entry {reference} in this checkout"),
    })?;
    let file = &files[found.file];
    if found.documents_in_file > 1 {
        return Err(CliError {
            message: format!(
                "{reference} lives in {}, which holds several documents; remove it by hand",
                file.rel
            ),
        });
    }
    let target = format!(
        "{}/{}",
        reference.entry_type,
        reference.key.to_ascii_lowercase()
    );
    let mut referenced_by = Vec::new();
    for other in &files {
        if other.rel == file.rel {
            continue;
        }
        for document in tree::parse_documents(&other.text).unwrap_or_default() {
            let points_here = document
                .pointer("/spec/relations")
                .and_then(Value::as_array)
                .is_some_and(|relations| {
                    relations.iter().any(|relation| {
                        relation
                            .pointer("/target/registry")
                            .and_then(Value::as_str)
                            .is_some_and(|value| value.to_ascii_lowercase() == target)
                    })
                });
            if points_here {
                referenced_by.push(other.rel.clone());
            }
        }
    }
    let path = root.join(&file.rel);
    std::fs::remove_file(&path).map_err(|error| CliError {
        message: format!("{} could not be removed: {error}", file.rel),
    })?;
    // Leave no empty type directory behind; Git does not track it anyway.
    if let Some(parent) = path.parent()
        && parent != root
    {
        let _ = std::fs::remove_dir(parent);
    }
    referenced_by.sort();
    referenced_by.dedup();
    Ok(Removal {
        path: file.rel.clone(),
        referenced_by,
    })
}

/// Parses a relation target: `<type>/<key>`, `registry:<type>/<key>`,
/// `machine:<name>`, `project:<name>`, `coolify:<reference>`, or
/// `proxmoxGuest:<reference>` (also `proxmox-guest:`).
pub(super) fn parse_target(text: &str) -> Result<Value, CliError> {
    let bad = || {
        CliError {
        message: "a relation target is <type>/<key>, or machine:<name>, project:<name>, coolify:<reference>, or proxmoxGuest:<reference>".to_owned(),
    }
    };
    if text.is_empty() {
        return Err(bad());
    }
    if let Some((class, reference)) = text.split_once(':') {
        let class = match class {
            "registry" => "registry",
            "machine" => "machine",
            "project" => "project",
            "coolify" => "coolify",
            "proxmoxGuest" | "proxmox-guest" => "proxmoxGuest",
            _ => return Err(bad()),
        };
        if reference.is_empty() {
            return Err(bad());
        }
        if class == "registry" {
            EntryRef::parse(reference)?;
        }
        return Ok(json!({ class: reference }));
    }
    EntryRef::parse(text)?;
    Ok(json!({ "registry": text }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(yaml: &str) -> Value {
        tree::parse_documents(yaml).unwrap().remove(0)
    }

    const HAND_WRITTEN: &str = "# Managed by hand.\napiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d001\n  name: domain-example-com # keep\nspec:\n  type: domain\n  fields:\n    fqdn: example.com\n    # who sells it\n    registrar: Webhuset\n  tags:\n    - client-x\n  notes: Moved from GoDaddy.\n";

    #[test]
    fn a_patch_keeps_comments_and_order_and_touches_only_the_change() {
        let old = model(HAND_WRITTEN);
        let mut new = old.clone();
        new["spec"]["fields"]["dnsHost"] = json!("Cloudflare");
        new["spec"]["fields"]["registrar"] = json!("Porkbun");
        let result = patched(HAND_WRITTEN, &old, &new).expect("patched");
        assert!(result.starts_with("# Managed by hand.\n"), "{result}");
        assert!(
            result.contains("name: domain-example-com # keep"),
            "{result}"
        );
        assert!(result.contains("# who sells it"), "{result}");
        assert!(result.contains("registrar: Porkbun"), "{result}");
        assert!(result.contains("dnsHost: Cloudflare"), "{result}");
        assert!(result.find("fqdn").unwrap() < result.find("registrar").unwrap());
        assert_eq!(model(&result), new);
    }

    #[test]
    fn tags_append_and_remove_in_place() {
        let old = model(HAND_WRITTEN);
        let mut added = old.clone();
        added["spec"]["tags"] = json!(["client-x", "prod"]);
        let result = patched(HAND_WRITTEN, &old, &added).expect("append");
        assert_eq!(model(&result), added);
        assert!(result.contains("# who sells it"), "{result}");
        let mut removed = added.clone();
        removed["spec"]["tags"] = json!(["prod"]);
        let result = patched(&result, &added, &removed).expect("remove");
        assert_eq!(model(&result), removed);
    }

    #[test]
    fn an_unchanged_model_renders_the_file_untouched() {
        let old = model(HAND_WRITTEN);
        let (text, how) = render(Some((HAND_WRITTEN, &old)), &old.clone()).unwrap();
        assert_eq!(how, "unchanged");
        assert_eq!(text, HAND_WRITTEN);
    }

    #[test]
    fn canonical_layout_is_stable_and_reads_back() {
        let reference = EntryRef::parse("domain/example.com").unwrap();
        let types = tree::type_definitions(&[]);
        let mut document = new_document(&reference, &types["domain"]);
        document["spec"]["fields"]["registrar"] = json!("Webhuset");
        document["spec"]["fields"]["autoRenew"] = json!(true);
        document["spec"]["tags"] = json!(["client-x"]);
        let first = canonical(&document).unwrap();
        assert!(
            first.starts_with(
                "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata:\n  id: "
            ),
            "{first}"
        );
        assert_eq!(first, canonical(&document).unwrap());
        assert_eq!(model(&first), document);
        // A patch of the canonical text by its own model is a no-op.
        assert_eq!(patched(&first, &document, &document).unwrap(), first);
    }

    #[test]
    fn addresses_are_path_safe() {
        for good in ["domain/example.com", "service/aptabase", "domain/a+b@c_d-e"] {
            assert!(EntryRef::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "domain",
            "domain/",
            "/example.com",
            "domain/../etc",
            "domain/a/b",
            "domain/..",
            "domain/.hidden",
            "Domain/example.com",
            "domain/a b",
            "domain/a\\b",
        ] {
            assert!(EntryRef::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            EntryRef::parse("domain/Example.COM").unwrap().path(),
            "fleet/registry/domain/example.com.yaml"
        );
        assert_eq!(
            EntryRef::parse("domain/example.com").unwrap().slug_name(),
            "domain-example-com"
        );
    }

    #[test]
    fn field_values_follow_the_declared_type() {
        let types = tree::type_definitions(&[]);
        let domain = &types["domain"];
        let parse = |name: &str, raw: &str| parse_field(name, &domain.fields[name], raw);
        assert_eq!(parse("autoRenew", "true").unwrap(), json!(true));
        assert!(parse("autoRenew", "yes").is_err());
        assert_eq!(
            parse("nameservers", "ns1.example.com, ns2.example.com").unwrap(),
            json!(["ns1.example.com", "ns2.example.com"])
        );
        assert_eq!(parse("registrar", "Webhuset").unwrap(), json!("Webhuset"));
        let error = parse("autoRenew", "hunter2-secret").unwrap_err().message;
        assert!(!error.contains("hunter2"), "{error}");
        assert!(parse("registrar", "").is_err());
    }

    #[test]
    fn relation_targets_parse_by_class() {
        assert_eq!(
            parse_target("service/aptabase").unwrap(),
            json!({"registry": "service/aptabase"})
        );
        assert_eq!(
            parse_target("machine:build-1").unwrap(),
            json!({"machine": "build-1"})
        );
        assert_eq!(
            parse_target("proxmox-guest:pve/101").unwrap(),
            json!({"proxmoxGuest": "pve/101"})
        );
        assert!(parse_target("nonsense:x").is_err());
        assert!(parse_target("service").is_err());
    }
}
