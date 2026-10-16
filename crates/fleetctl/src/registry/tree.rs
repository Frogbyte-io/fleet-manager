//! The local Fleet Git checkout: discovery, the YAML file set, and
//! validation.
//!
//! Validation here is the controller's own: [`fleet_schema`] with the
//! built-in Registry types, over the same file set the controller reads for
//! a candidate (every `*.yaml` under the checkout, never `.git`). Nothing
//! here talks to the controller.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use fleet_schema::{
    Diagnostic, SourceDocument, ValidationReport, kinds::RegistryTypeSpec,
    registry::RegistryContext, validate_sources_report,
};
use serde_json::Value;
use serde_saphyr::options::{DuplicateKeyPolicy, MergeKeyPolicy};

use crate::CliError;

/// The directory Registry entries live in by convention.
pub(super) const REGISTRY_DIR: &str = "fleet/registry";

/// Directory depth the file walk refuses to pass; a Fleet repository is
/// shallow, and this bounds a pathological tree.
const MAX_DEPTH: usize = 32;

/// One YAML file of the checkout.
#[derive(Clone, Debug)]
pub(super) struct SourceFile {
    /// The path relative to the checkout, with `/` separators.
    pub rel: String,
    /// The UTF-8 content.
    pub text: String,
}

/// Finds the checkout: the nearest directory at or above `repo` (or the
/// working directory) that holds a `.git` entry.
pub(super) fn discover(repo: Option<&Path>) -> Result<PathBuf, CliError> {
    let start = match repo {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().map_err(|error| CliError {
            message: format!("the working directory is unreadable: {error}"),
        })?,
    };
    let start = start.canonicalize().map_err(|error| CliError {
        message: format!("{} is not readable: {error}", start.display()),
    })?;
    for directory in start.ancestors() {
        if directory.join(".git").exists() {
            return Ok(directory.to_path_buf());
        }
    }
    Err(CliError {
        message: format!(
            "{} is not inside a Git checkout; run this in a checkout of the Fleet Git repository or pass --repo <path>",
            start.display()
        ),
    })
}

/// Reads every `*.yaml` file under the checkout, sorted by path.
pub(super) fn load(root: &Path) -> Result<Vec<SourceFile>, CliError> {
    let mut files = Vec::new();
    walk(root, root, 0, &mut files)?;
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(files)
}

fn walk(
    root: &Path,
    directory: &Path,
    depth: usize,
    files: &mut Vec<SourceFile>,
) -> Result<(), CliError> {
    if depth > MAX_DEPTH {
        return Err(CliError {
            message: format!("the checkout is nested deeper than {MAX_DEPTH} directories"),
        });
    }
    let entries = std::fs::read_dir(directory).map_err(|error| CliError {
        message: format!("{} is not readable: {error}", directory.display()),
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        // `file_type` does not follow symlinks, so a link can neither loop
        // the walk nor pull in a file from outside the checkout.
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if entry.file_name() != ".git" {
                walk(root, &path, depth + 1, files)?;
            }
        } else if kind.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "yaml")
        {
            let rel = relative(root, &path);
            let text = std::fs::read_to_string(&path).map_err(|error| CliError {
                message: format!("{rel} is not readable UTF-8 text: {error}"),
            })?;
            files.push(SourceFile { rel, text });
        }
    }
    Ok(())
}

/// The checkout-relative path with `/` separators.
pub(super) fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// The strict YAML input policy the controller applies.
fn yaml_options() -> serde_saphyr::Options {
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

/// Parses every document of a YAML text under the strict policy.
pub(super) fn parse_documents(text: &str) -> Result<Vec<Value>, String> {
    serde_saphyr::from_multiple_with_options(text, yaml_options())
        .map_err(|_| "the file is not valid YAML under Fleet's strict input policy".to_owned())
}

/// Validates the file set as one candidate, like the controller.
pub(super) fn validate(files: &[SourceFile]) -> ValidationReport {
    let sources: Vec<SourceDocument> = files
        .iter()
        .map(|file| SourceDocument {
            path: PathBuf::from(&file.rel),
            yaml: file.text.clone(),
        })
        .collect();
    validate_sources_report(&sources, &RegistryContext::default())
}

/// The Registry types in scope: the built-ins plus every `RegistryType`
/// document in the file set, by name.
pub(super) fn type_definitions(files: &[SourceFile]) -> BTreeMap<String, RegistryTypeSpec> {
    let mut types: BTreeMap<String, RegistryTypeSpec> = RegistryContext::default()
        .builtin_types
        .into_iter()
        .map(|built| (built.name, built.spec))
        .collect();
    for file in files {
        let Ok(documents) = parse_documents(&file.text) else {
            continue;
        };
        for document in documents {
            if document.get("kind").and_then(Value::as_str) != Some("RegistryType") {
                continue;
            }
            let Some(name) = document.pointer("/metadata/name").and_then(Value::as_str) else {
                continue;
            };
            if types.contains_key(name) {
                // A repository cannot redefine a built-in; validation
                // reports it, and editing keeps using the built-in.
                continue;
            }
            if let Some(spec) = document
                .get("spec")
                .and_then(|spec| serde_json::from_value::<RegistryTypeSpec>(spec.clone()).ok())
            {
                types.insert(name.to_owned(), spec);
            }
        }
    }
    types
}

/// One diagnostic as JSON: code, location, message.
pub(super) fn diagnostic_json(diagnostic: &Diagnostic) -> Value {
    serde_json::json!({
        "code": diagnostic.code,
        "location": diagnostic.location,
        "message": diagnostic.message,
    })
}
