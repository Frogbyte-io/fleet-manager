//! `fleetctl registry` (FM-1013, ADR 0016): read the Registry through the
//! controller API, and edit it as YAML in a local Fleet Git checkout.
//!
//! Reads (`types`, `list`, `find`, `get`) are plain calls to
//! `/api/v1/registry/...`. Everything else runs locally and offline: the
//! controller never writes to Git, and `validate` is the same validator the
//! controller runs on a candidate. Only `publish` talks to the controller,
//! and only to read the `registry.changeMode` setting.
//!
//! Adding a verb: add its grammar to [`parse`] (a self-contained module such
//! as `suggest` plugs in as one more arm), its usage line to [`USAGE`], and
//! either a read request in [`request`] or a local runner in [`run_local`].

use std::path::PathBuf;

use serde_json::{Value, json};

use crate::{CliError, Command, Invocation, Output, RequestShape};

mod edit;
mod publish;
mod tree;

pub use edit::EntryRef;
pub use publish::ChangeMode;

/// The usage lines of the group, one per form. They are part of the
/// top-level usage text, and `registry <verb> --help` prints its own.
pub(crate) const USAGE: &[&str] = &[
    "registry types [--output json|text]",
    "registry list [--type <type>] [--tag <tag>] [--query <text>] [--target <class:reference>] [--relation <type>] [--limit <n>] [--cursor <c>] [--output json|text]",
    "registry find <query> [--type <type>] [--tag <tag>] [--limit <n>] [--cursor <c>] [--output json|text]",
    "registry get <type>/<key> [--output json|text]",
    "registry set <type>/<key> [--field <name>=<value>]... [--notes <text>] [--from-json -|<file>] [--repo <path>]",
    "registry unset <type>/<key> [--field <name>]... [--notes] [--repo <path>]",
    "registry rm <type>/<key> [--repo <path>]",
    "registry relate <from> <relation> <to> [--remove] [--repo <path>] (<to> is <type>/<key>, machine:<name>, project:<name>, coolify:<ref>, or proxmoxGuest:<ref>)",
    "registry tags add|rm <type>/<key> <tag>... [--repo <path>]",
    "registry validate [--repo <path>] [--output json|text]",
    "registry publish -m <message> [--change-mode direct|pull-request] [--base <branch>] [--branch <name>] [--repo <path>] [--output json|text]",
];

/// The usage lines as a block, for the top-level usage text.
pub(crate) fn usage_block() -> String {
    USAGE
        .iter()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One `registry` subcommand.
#[derive(Clone, Debug, PartialEq)]
pub enum RegistryAction {
    /// List the Registry types.
    Types,
    /// List or search entries (`list`, and `find <query>`).
    List {
        /// Only entries of this type.
        entry_type: Option<String>,
        /// Only entries carrying this tag.
        tag: Option<String>,
        /// A substring over keys, names, values, tags, and notes.
        query: Option<String>,
        /// Only entries with a relation to this target.
        target: Option<String>,
        /// With `target`, only this relation type.
        relation: Option<String>,
        /// The page size.
        limit: Option<u32>,
        /// The previous page's `nextCursor`.
        cursor: Option<String>,
    },
    /// Read one entry.
    Get {
        /// The entry.
        reference: EntryRef,
    },
    /// Create an entry or patch the named parts of it.
    Set {
        /// The entry.
        reference: EntryRef,
        /// `--field name=value`, as typed.
        fields: Vec<(String, String)>,
        /// `--notes`.
        notes: Option<String>,
        /// `--from-json`: `-` for stdin, or a file path.
        from_json: Option<String>,
        /// The checkout.
        repo: Option<PathBuf>,
    },
    /// Remove fields from an entry.
    Unset {
        /// The entry.
        reference: EntryRef,
        /// The fields to remove.
        fields: Vec<String>,
        /// Whether to remove the notes.
        notes: bool,
        /// The checkout.
        repo: Option<PathBuf>,
    },
    /// Delete an entry's file.
    Remove {
        /// The entry.
        reference: EntryRef,
        /// The checkout.
        repo: Option<PathBuf>,
    },
    /// Add or remove one relation.
    Relate {
        /// The entry the relation starts at.
        from: EntryRef,
        /// The relation type.
        relation: String,
        /// The target, as typed.
        target: String,
        /// Remove the relation instead of adding it.
        remove: bool,
        /// The checkout.
        repo: Option<PathBuf>,
    },
    /// Add or remove tags.
    Tags {
        /// `true` for `tags add`.
        add: bool,
        /// The entry.
        reference: EntryRef,
        /// The tags.
        tags: Vec<String>,
        /// The checkout.
        repo: Option<PathBuf>,
    },
    /// Validate the checkout like the controller.
    Validate {
        /// The checkout.
        repo: Option<PathBuf>,
    },
    /// Commit the Registry changes and push or open a pull request.
    Publish {
        /// The commit message.
        message: String,
        /// Overrides the controller's `registry.changeMode`.
        change_mode: Option<ChangeMode>,
        /// The default branch, when `origin/HEAD` is not set.
        base: Option<String>,
        /// The pull request branch.
        branch: Option<String>,
        /// The checkout.
        repo: Option<PathBuf>,
    },
}

impl RegistryAction {
    /// Whether the action runs on the local checkout instead of calling
    /// the controller.
    #[must_use]
    pub fn is_local(&self) -> bool {
        !matches!(self, Self::Types | Self::List { .. } | Self::Get { .. })
    }
}

// --- grammar ----------------------------------------------------------------

/// The scanned arguments of one verb.
struct Flags<'a> {
    verb: &'a str,
    positional: Vec<&'a str>,
    values: Vec<(&'static str, String)>,
    switches: Vec<&'static str>,
}

impl Flags<'_> {
    fn usage(&self) -> CliError {
        usage_error(self.verb)
    }

    fn many(&self, name: &str) -> Vec<String> {
        self.values
            .iter()
            .filter(|(flag, _)| *flag == name)
            .map(|(_, value)| value.clone())
            .collect()
    }

    fn one(&self, name: &str) -> Result<Option<String>, CliError> {
        let mut all = self.many(name);
        if all.len() > 1 {
            return Err(CliError {
                message: format!("{name} was given more than once"),
            });
        }
        Ok(all.pop())
    }

    fn switch(&self, name: &str) -> bool {
        self.switches.contains(&name)
    }

    fn repo(&self) -> Result<Option<PathBuf>, CliError> {
        Ok(self.one("--repo")?.map(PathBuf::from))
    }

    fn number(&self, name: &str) -> Result<Option<u32>, CliError> {
        self.one(name)?
            .map(|raw| {
                raw.parse().map_err(|_| CliError {
                    message: format!("{name} must be a number"),
                })
            })
            .transpose()
    }

    /// Exactly `count` positionals.
    fn positionals(&self, count: usize) -> Result<&[&str], CliError> {
        if self.positional.len() == count {
            Ok(&self.positional)
        } else {
            Err(self.usage())
        }
    }
}

fn usage_error(verb: &str) -> CliError {
    let lines: Vec<String> = USAGE
        .iter()
        .filter(|line| line.split_whitespace().nth(1) == Some(verb))
        .map(|line| format!("  fleetctl {line}"))
        .collect();
    CliError {
        message: if lines.is_empty() {
            format!("usage:\n{}", usage_block())
        } else {
            format!("usage:\n{}", lines.join("\n"))
        },
    }
}

/// Splits the words after the verb into positionals, valued flags, and
/// switches. A flag not in either list is an error.
fn scan<'a>(
    verb: &'a str,
    words: &[&'a str],
    valued: &[&'static str],
    switches: &[&'static str],
    output: &mut Output,
) -> Result<Flags<'a>, CliError> {
    let mut flags = Flags {
        verb,
        positional: Vec::new(),
        values: Vec::new(),
        switches: Vec::new(),
    };
    let mut words = words.iter().copied();
    while let Some(word) = words.next() {
        if word == "--output" {
            let value = words.next().ok_or_else(|| CliError {
                message: "--output requires json or text".to_owned(),
            })?;
            *output = match value {
                "json" => Output::Json,
                "text" => Output::Text,
                other => {
                    return Err(CliError {
                        message: format!("--output must be json or text, not {other:?}"),
                    });
                }
            };
        } else if let Some(name) = valued.iter().find(|name| **name == word) {
            // The value is whatever follows, even when it starts with `-`
            // (a commit message, `--from-json -`).
            let value = words.next().ok_or_else(|| CliError {
                message: format!("{name} requires a value"),
            })?;
            flags.values.push((name, value.to_owned()));
        } else if let Some(name) = switches.iter().find(|name| **name == word) {
            flags.switches.push(name);
        } else if word.starts_with('-') {
            return Err(CliError {
                message: format!(
                    "unknown flag {word:?} for registry {verb}\n{}",
                    usage_error(verb).message
                ),
            });
        } else {
            flags.positional.push(word);
        }
    }
    Ok(flags)
}

const FIND_FLAGS: &[&str] = &["--type", "--tag", "--limit", "--cursor"];
const LIST_FLAGS: &[&str] = &[
    "--type",
    "--tag",
    "--limit",
    "--cursor",
    "--query",
    "--target",
    "--relation",
];

/// Parses `registry <verb> ...`.
#[allow(clippy::too_many_lines)]
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((verb, words)) = rest.split_first() else {
        return Err(CliError {
            message: format!("usage:\n{}", usage_block()),
        });
    };
    let action = match *verb {
        "types" => {
            let flags = scan(verb, words, &[], &[], output)?;
            flags.positionals(0)?;
            RegistryAction::Types
        }
        "list" | "find" => {
            let valued = if *verb == "list" {
                LIST_FLAGS
            } else {
                FIND_FLAGS
            };
            let flags = scan(verb, words, valued, &[], output)?;
            let query = if *verb == "find" {
                Some(flags.positionals(1)?[0].to_owned())
            } else {
                flags.positionals(0)?;
                flags.one("--query")?
            };
            RegistryAction::List {
                entry_type: flags.one("--type")?,
                tag: flags.one("--tag")?,
                query,
                target: flags.one("--target")?,
                relation: flags.one("--relation")?,
                limit: flags.number("--limit")?,
                cursor: flags.one("--cursor")?,
            }
        }
        "get" => {
            let flags = scan(verb, words, &[], &[], output)?;
            RegistryAction::Get {
                reference: EntryRef::parse(flags.positionals(1)?[0])?,
            }
        }
        "set" => {
            let flags = scan(
                verb,
                words,
                &["--field", "--notes", "--from-json", "--repo"],
                &[],
                output,
            )?;
            let reference = EntryRef::parse(flags.positionals(1)?[0])?;
            let fields = flags
                .many("--field")
                .into_iter()
                .map(|raw| {
                    raw.split_once('=')
                        .map(|(name, value)| (name.to_owned(), value.to_owned()))
                        .ok_or_else(|| CliError {
                            message: "--field expects <name>=<value>".to_owned(),
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (notes, from_json) = (flags.one("--notes")?, flags.one("--from-json")?);
            RegistryAction::Set {
                reference,
                fields,
                notes,
                from_json,
                repo: flags.repo()?,
            }
        }
        "unset" => {
            let flags = scan(verb, words, &["--field", "--repo"], &["--notes"], output)?;
            let reference = EntryRef::parse(flags.positionals(1)?[0])?;
            let fields = flags.many("--field");
            let notes = flags.switch("--notes");
            if fields.is_empty() && !notes {
                return Err(flags.usage());
            }
            RegistryAction::Unset {
                reference,
                fields,
                notes,
                repo: flags.repo()?,
            }
        }
        "rm" => {
            let flags = scan(verb, words, &["--repo"], &[], output)?;
            RegistryAction::Remove {
                reference: EntryRef::parse(flags.positionals(1)?[0])?,
                repo: flags.repo()?,
            }
        }
        "relate" => {
            let flags = scan(verb, words, &["--repo"], &["--remove"], output)?;
            let [from, relation, target] = flags.positionals(3)? else {
                return Err(flags.usage());
            };
            if !edit::is_slug(relation) {
                return Err(CliError {
                    message: "a relation type is a lowercase slug, for example used-by".to_owned(),
                });
            }
            // Reject a malformed target before any file is touched.
            edit::parse_target(target)?;
            RegistryAction::Relate {
                from: EntryRef::parse(from)?,
                relation: (*relation).to_owned(),
                target: (*target).to_owned(),
                remove: flags.switch("--remove"),
                repo: flags.repo()?,
            }
        }
        "tags" => {
            let Some((action, words)) = words.split_first() else {
                return Err(usage_error(verb));
            };
            let add = match *action {
                "add" => true,
                "rm" => false,
                _ => return Err(usage_error(verb)),
            };
            let flags = scan(verb, words, &["--repo"], &[], output)?;
            let Some((reference, tags)) = flags.positional.split_first() else {
                return Err(flags.usage());
            };
            if tags.is_empty() {
                return Err(flags.usage());
            }
            RegistryAction::Tags {
                add,
                reference: EntryRef::parse(reference)?,
                tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
                repo: flags.repo()?,
            }
        }
        "validate" => {
            let flags = scan(verb, words, &["--repo"], &[], output)?;
            flags.positionals(0)?;
            RegistryAction::Validate {
                repo: flags.repo()?,
            }
        }
        "publish" => {
            let flags = scan(
                verb,
                words,
                &[
                    "-m",
                    "--message",
                    "--change-mode",
                    "--base",
                    "--branch",
                    "--repo",
                ],
                &[],
                output,
            )?;
            flags.positionals(0)?;
            let message = match (flags.one("-m")?, flags.one("--message")?) {
                (Some(message), None) | (None, Some(message)) => message,
                (None, None) => {
                    return Err(CliError {
                        message: "publish needs a commit message: -m <message>".to_owned(),
                    });
                }
                (Some(_), Some(_)) => {
                    return Err(CliError {
                        message: "give the message once, with -m or --message".to_owned(),
                    });
                }
            };
            RegistryAction::Publish {
                message,
                change_mode: flags
                    .one("--change-mode")?
                    .map(|mode| ChangeMode::parse(&mode))
                    .transpose()?,
                base: flags.one("--base")?,
                branch: flags.one("--branch")?,
                repo: flags.repo()?,
            }
        }
        // FM-1020: `"suggest" => suggest::parse(words, output)?` plugs in here.
        _ => {
            return Err(CliError {
                message: format!(
                    "unknown registry command {verb:?}\n\nusage:\n{}",
                    usage_block()
                ),
            });
        }
    };
    Ok(Command::Registry(action))
}

// --- reads ------------------------------------------------------------------

/// Percent-encodes one path segment.
fn encode(segment: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// The controller request of a read action.
pub(crate) fn request(action: &RegistryAction) -> RequestShape {
    let get = |path: String, query: Vec<(&'static str, String)>| {
        (reqwest::Method::GET, path, query, None)
    };
    match action {
        RegistryAction::Types => get("/api/v1/registry/types".to_owned(), Vec::new()),
        RegistryAction::List {
            entry_type,
            tag,
            query,
            target,
            relation,
            limit,
            cursor,
        } => {
            let mut params: Vec<(&'static str, String)> = Vec::new();
            for (name, value) in [
                ("type", entry_type),
                ("tag", tag),
                ("q", query),
                ("target", target),
                ("relation", relation),
                ("cursor", cursor),
            ] {
                if let Some(value) = value {
                    params.push((name, value.clone()));
                }
            }
            if let Some(limit) = limit {
                params.push(("limit", limit.to_string()));
            }
            get("/api/v1/registry/entries".to_owned(), params)
        }
        RegistryAction::Get { reference } => get(
            format!(
                "/api/v1/registry/entries/{}/{}",
                encode(&reference.entry_type),
                encode(&reference.key)
            ),
            Vec::new(),
        ),
        _ => unreachable!("local registry actions never reach the controller"),
    }
}

fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn text_of(value: &Value) -> String {
    clean(value.as_str().unwrap_or("-"))
}

fn render_entry(entry: &Value) -> String {
    let mut lines = vec![format!(
        "{}/{}  ({})",
        text_of(&entry["type"]),
        text_of(&entry["key"]),
        text_of(&entry["name"])
    )];
    if let Some(fields) = entry["fields"].as_object() {
        for (name, value) in fields {
            let shown = match value {
                Value::String(text) => clean(text),
                other => clean(&other.to_string()),
            };
            lines.push(format!("  {}: {shown}", clean(name)));
        }
    }
    let tags = entry["tags"]
        .as_array()
        .map(|tags| tags.iter().map(text_of).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    if !tags.is_empty() {
        lines.push(format!("  tags: {tags}"));
    }
    if let Some(notes) = entry["notes"].as_str() {
        lines.push(format!("  notes: {}", clean(notes)));
    }
    for relation in entry["relations"].as_array().into_iter().flatten() {
        lines.push(format!(
            "  {} -> {}:{}",
            text_of(&relation["type"]),
            text_of(&relation["target"]["class"]),
            text_of(&relation["target"]["reference"])
        ));
    }
    if let Some(path) = entry["sourcePath"].as_str() {
        lines.push(format!("  file: {}", clean(path)));
    }
    lines.join("\n")
}

/// Renders a read result as human text.
pub(crate) fn render(payload: &Value) -> String {
    let Some(items) = payload.get("items").and_then(Value::as_array) else {
        return render_entry(payload);
    };
    if payload["revision"].is_null() && items.is_empty() {
        return "No active revision, so the Registry is empty.".to_owned();
    }
    if items.is_empty() {
        return "(no matching Registry data)".to_owned();
    }
    let mut lines = Vec::new();
    for item in items {
        if item.get("entryCount").is_some() {
            lines.push(format!(
                "{:<16} {:<8} key={:<12} {:>4} entries  {}",
                text_of(&item["name"]),
                text_of(&item["origin"]),
                text_of(&item["keyField"]),
                item["entryCount"].as_i64().unwrap_or(0),
                text_of(&item["displayName"]),
            ));
        } else {
            lines.push(format!(
                "{}/{}  {}",
                text_of(&item["type"]),
                text_of(&item["key"]),
                item["tags"]
                    .as_array()
                    .map(|tags| tags.iter().map(text_of).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default()
            ));
        }
    }
    if let Some(cursor) = payload["page"]["nextCursor"].as_str() {
        lines.push(format!(
            "more: --cursor '{}'",
            clean(cursor).replace('\'', "'\\''")
        ));
    }
    lines.join("\n")
}

// --- local runs -----------------------------------------------------------------

fn changed_json(action: &str, reference: &EntryRef, outcome: &edit::Outcome) -> Value {
    json!({
        "action": action,
        "entry": reference.to_string(),
        "path": outcome.path,
        "created": outcome.created,
        "changed": outcome.changed,
        "formatting": outcome.formatting,
        "warnings": outcome.warnings,
    })
}

fn changed_text(reference: &EntryRef, outcome: &edit::Outcome) -> String {
    let mut text = if outcome.created {
        format!("created {reference} in {}", outcome.path)
    } else if outcome.changed {
        format!("updated {reference} in {}", outcome.path)
    } else {
        format!("{reference} is already up to date ({})", outcome.path)
    };
    if outcome.formatting == "canonical" {
        text.push_str(
            "\nnote: the file was rewritten in the canonical layout; its comments could not be kept",
        );
    }
    for warning in &outcome.warnings {
        text.push_str("\nwarning: ");
        text.push_str(warning);
    }
    text
}

fn read_json_patch(source: &str) -> Result<Value, CliError> {
    let text = if source == "-" {
        crate::read_stdin_to_end("the JSON patch")?
    } else {
        std::fs::read_to_string(source).map_err(|error| CliError {
            message: format!("{source} is not readable: {error}"),
        })?
    };
    serde_json::from_str(&text).map_err(|error| CliError {
        message: format!("--from-json is not valid JSON: {error}"),
    })
}

/// The controller's `registry.changeMode`.
fn controller_change_mode(invocation: &Invocation) -> Result<ChangeMode, CliError> {
    let client = crate::http_client()?;
    let body = crate::send(
        &client,
        invocation,
        reqwest::Method::GET,
        "/api/v1/desired/settings",
        &[],
        None,
        uuid::Uuid::now_v7().to_string(),
    )
    .map_err(|error| CliError {
        message: format!(
            "the registry.changeMode setting could not be read ({}); pass --change-mode direct|pull-request to decide yourself",
            error.message
        ),
    })?;
    let mode = body["data"]["changeMode"]
        .as_str()
        .or_else(|| body["changeMode"].as_str())
        .unwrap_or_default();
    ChangeMode::parse(mode).map_err(|_| CliError {
        message: "the controller reported no usable registry.changeMode; pass --change-mode direct|pull-request".to_owned(),
    })
}

fn render_validation(
    report: &fleet_schema::ValidationReport,
    files: usize,
    output: Output,
) -> String {
    let valid = report.errors.is_empty();
    match output {
        Output::Json => serde_json::to_string_pretty(&json!({
            "valid": valid,
            "files": files,
            "errors": report.errors.iter().map(tree::diagnostic_json).collect::<Vec<_>>(),
            "warnings": report.warnings.iter().map(tree::diagnostic_json).collect::<Vec<_>>(),
        }))
        .unwrap_or_default(),
        Output::Text => {
            let mut lines: Vec<String> = report
                .errors
                .iter()
                .map(|diagnostic| format!("error: {diagnostic}"))
                .collect();
            lines.extend(
                report
                    .warnings
                    .iter()
                    .map(|diagnostic| format!("warning: {diagnostic}")),
            );
            lines.push(format!(
                "{}: {} error(s), {} warning(s) in {files} YAML file(s)",
                if valid { "valid" } else { "invalid" },
                report.errors.len(),
                report.warnings.len()
            ));
            lines.join("\n")
        }
    }
}

fn render_publish(result: &Value) -> String {
    if result["published"] != Value::Bool(true) {
        return format!(
            "nothing published: {}",
            result["reason"].as_str().unwrap_or("no Registry changes")
        );
    }
    let mut lines = vec![format!(
        "published {} ({}) to {}",
        result["commit"]
            .as_str()
            .unwrap_or("?")
            .get(..12)
            .unwrap_or("?"),
        result["mode"].as_str().unwrap_or("?"),
        result["branch"].as_str().unwrap_or("?")
    )];
    if let Some(url) = result["pullRequest"].as_str() {
        lines.push(format!("pull request: {url}"));
    } else if let Some(url) = result["compareUrl"].as_str() {
        lines.push(format!("open a pull request: {url}"));
    } else if result["mode"] == "pull-request" {
        lines.push(format!(
            "pushed branch {}; open a pull request from it on your Git host",
            result["branch"].as_str().unwrap_or("?")
        ));
    }
    lines.join("\n")
}

/// Runs a local action. Returns the output text and the exit code.
#[allow(clippy::too_many_lines)]
pub(crate) fn run_local(
    action: &RegistryAction,
    invocation: &Invocation,
) -> Result<(String, u8), CliError> {
    let json_output = invocation.output == Output::Json;
    let pretty = |value: &Value| serde_json::to_string_pretty(value).unwrap_or_default();
    match action {
        RegistryAction::Validate { repo } => {
            let root = tree::discover(repo.as_deref())?;
            let files = tree::load(&root)?;
            let report = tree::validate(&files);
            let code = u8::from(!report.errors.is_empty());
            Ok((
                render_validation(&report, files.len(), invocation.output),
                code,
            ))
        }
        RegistryAction::Set {
            reference,
            fields,
            notes,
            from_json,
            repo,
        } => {
            let root = tree::discover(repo.as_deref())?;
            let patch = from_json.as_deref().map(read_json_patch).transpose()?;
            let outcome = edit::apply(
                &root,
                reference,
                &edit::Change::Set {
                    fields: fields.clone(),
                    notes: notes.clone(),
                    patch,
                },
            )?;
            Ok(done("set", reference, &outcome, json_output))
        }
        RegistryAction::Unset {
            reference,
            fields,
            notes,
            repo,
        } => {
            let root = tree::discover(repo.as_deref())?;
            let outcome = edit::apply(
                &root,
                reference,
                &edit::Change::Unset {
                    fields: fields.clone(),
                    notes: *notes,
                },
            )?;
            Ok(done("unset", reference, &outcome, json_output))
        }
        RegistryAction::Tags {
            add,
            reference,
            tags,
            repo,
        } => {
            let root = tree::discover(repo.as_deref())?;
            let outcome = edit::apply(
                &root,
                reference,
                &edit::Change::Tags {
                    add: *add,
                    tags: tags.clone(),
                },
            )?;
            Ok(done(
                if *add { "tags add" } else { "tags rm" },
                reference,
                &outcome,
                json_output,
            ))
        }
        RegistryAction::Relate {
            from,
            relation,
            target,
            remove,
            repo,
        } => {
            let root = tree::discover(repo.as_deref())?;
            let outcome = edit::apply(
                &root,
                from,
                &edit::Change::Relate {
                    relation: relation.clone(),
                    target: edit::parse_target(target)?,
                    remove: *remove,
                },
            )?;
            Ok(done("relate", from, &outcome, json_output))
        }
        RegistryAction::Remove { reference, repo } => {
            let root = tree::discover(repo.as_deref())?;
            let removal = edit::remove(&root, reference)?;
            let text = if json_output {
                pretty(&json!({
                    "action": "rm",
                    "entry": reference.to_string(),
                    "path": removal.path,
                    "referencedBy": removal.referenced_by,
                }))
            } else {
                let mut text = format!("removed {reference} ({})", removal.path);
                if !removal.referenced_by.is_empty() {
                    text.push_str("\nwarning: still referenced by relations in ");
                    text.push_str(&removal.referenced_by.join(", "));
                }
                text
            };
            Ok((text, 0))
        }
        RegistryAction::Publish {
            message,
            change_mode,
            base,
            branch,
            repo,
        } => {
            let root = tree::discover(repo.as_deref())?;
            let result = publish::publish(
                &root,
                &publish::PublishRequest {
                    message: message.clone(),
                    change_mode: *change_mode,
                    base: base.clone(),
                    branch: branch.clone(),
                },
                || controller_change_mode(invocation),
            )?;
            let text = if json_output {
                pretty(&result)
            } else {
                render_publish(&result)
            };
            Ok((text, 0))
        }
        RegistryAction::Types | RegistryAction::List { .. } | RegistryAction::Get { .. } => {
            unreachable!("registry reads go to the controller")
        }
    }
}

fn done(
    verb: &str,
    reference: &EntryRef,
    outcome: &edit::Outcome,
    json_output: bool,
) -> (String, u8) {
    let text = if json_output {
        serde_json::to_string_pretty(&changed_json(verb, reference, outcome)).unwrap_or_default()
    } else {
        changed_text(reference, outcome)
    };
    (text, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(words: &[&str]) -> RegistryAction {
        let mut output = Output::Text;
        match parse(words, &mut output).unwrap() {
            Command::Registry(action) => action,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn reads_become_registry_api_requests() {
        let (method, path, query, body) = request(&action(&["types"]));
        assert_eq!(method, reqwest::Method::GET);
        assert_eq!(path, "/api/v1/registry/types");
        assert!(query.is_empty() && body.is_none());
        let (_, path, query, _) = request(&action(&[
            "find", "apt", "--type", "service", "--limit", "5",
        ]));
        assert_eq!(path, "/api/v1/registry/entries");
        assert_eq!(
            query,
            vec![
                ("type", "service".to_owned()),
                ("q", "apt".to_owned()),
                ("limit", "5".to_owned())
            ]
        );
        let (_, path, _, _) = request(&action(&["get", "service/a+b@c"]));
        assert_eq!(path, "/api/v1/registry/entries/service/a%2Bb%40c");
    }
}
