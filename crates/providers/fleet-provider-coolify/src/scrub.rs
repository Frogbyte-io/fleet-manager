//! Scrubbing for recorded contract fixtures (FM-1030).
//!
//! A fixture recorded from a real Coolify instance must carry the response
//! shape and nothing of the instance. The scrubber is default-deny:
//!
//! * a key that can hold a secret (password, secret, token, key, env,
//!   compose, logs, command, label, script, url) is removed entirely;
//! * object keys that are not plain `snake_case` words (a map keyed by a
//!   service or host name, say) are replaced by `key-N`;
//! * identities and names become stable pseudonyms (the same real value
//!   maps to the same pseudonym across files, so references still line up);
//! * hostnames become `*.example.test`, addresses become TEST-NET-1
//!   (192.0.2.0/24), image names are never kept;
//! * a short allow-list of enumerations (status, build pack, proxy type,
//!   service type) and all numbers and booleans pass through;
//! * every other string becomes `[scrubbed]`.
//!
//! [`capture`] fetches the read-only routes a discovery run requests
//! (bounded) and returns the scrubbed bodies under the file names the
//! contract tests read; [`ensure_clean`] refuses output that still carries
//! the token, the instance host, a credential shape, a hostname outside
//! `.example.test`, or an address outside 192.0.2.0/24; [`check_fixture_dir`]
//! applies the same check to a committed fixture directory. The ignored test
//! `tests/capture.rs` drives capture for an operator.

use std::collections::HashMap;
use std::path::Path;

use serde_json::{Map, Value};

use crate::discovery::{Limits, Route, Run};

/// Key fragments whose values are never kept.
const DROP_FRAGMENTS: [&str; 18] = [
    "password",
    "secret",
    "token",
    "private",
    "key",
    "environment_variable",
    "envs",
    "compose_raw",
    "docker_compose",
    "logs",
    "command",
    "label",
    "script",
    "url",
    "dockerfile",
    "snapshot",
    "diff",
    "credential",
];

/// Enumerations that are shape, not identity.
const VERBATIM_KEYS: [&str; 8] = [
    "status",
    "build_pack",
    "proxy_type",
    "type",
    "service_type",
    "database_type",
    "created_at",
    "updated_at",
];

/// How many projects, services, and applications are expanded.
const EXPAND: usize = 3;

/// The stable pseudonym table for one capture session.
#[derive(Debug, Default)]
pub struct FixtureScrubber {
    names: HashMap<(String, String), usize>,
}

impl FixtureScrubber {
    /// A fresh scrubber.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn pseudonym(&mut self, class: &str, real: &str) -> usize {
        let next = self.names.len() + 1;
        *self
            .names
            .entry((class.to_owned(), real.to_owned()))
            .or_insert(next)
    }

    /// The pseudonym a real Coolify uuid gets in every scrubbed file.
    pub fn uuid_for(&mut self, real: &str) -> String {
        let n = self.pseudonym("uuid", real);
        format!("uuid{n:020}")
    }

    /// Scrubs one JSON document.
    pub fn scrub(&mut self, value: &Value) -> Value {
        self.value(None, value)
    }

    /// A kept object key must be a plain `snake_case` word.
    fn key(&mut self, name: &str) -> String {
        if !name.is_empty()
            && name.len() <= 40
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            name.to_owned()
        } else {
            let n = self.pseudonym("key", name);
            format!("key-{n}")
        }
    }

    fn value(&mut self, key: Option<&str>, value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut out = Map::new();
                for (name, inner) in map {
                    let lower = name.to_ascii_lowercase();
                    if DROP_FRAGMENTS
                        .iter()
                        .any(|fragment| lower.contains(fragment))
                        && lower != "docker_compose_domains"
                    {
                        continue;
                    }
                    let kept = self.key(name);
                    out.insert(kept, self.value(Some(&lower), inner));
                }
                Value::Object(out)
            }
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| self.value(key, item)).collect())
            }
            Value::String(text) => Value::String(self.string(key.unwrap_or(""), text)),
            other => other.clone(),
        }
    }

    /// `service -> {domain}` with service names replaced and domains
    /// pseudonymized.
    fn compose_domains(&mut self, parsed: &Value) -> Value {
        let entries: Vec<&Value> = match parsed {
            Value::Object(map) => map.values().collect(),
            Value::Array(items) => items.iter().collect(),
            _ => Vec::new(),
        };
        let mut out = Map::new();
        for (index, entry) in entries.into_iter().enumerate() {
            let domain = entry
                .get("domain")
                .and_then(Value::as_str)
                .map(|domain| self.string("domain", domain))
                .unwrap_or_default();
            out.insert(
                format!("service-{index}"),
                serde_json::json!({ "domain": domain }),
            );
        }
        Value::Object(out)
    }

    fn string(&mut self, key: &str, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        if VERBATIM_KEYS.contains(&key) {
            return text.chars().take(60).collect();
        }
        if key == "docker_compose_domains" {
            // A JSON string of service -> {domain}.
            return match serde_json::from_str::<Value>(text) {
                Ok(parsed) => self.compose_domains(&parsed).to_string(),
                Err(_) => "[scrubbed]".to_owned(),
            };
        }
        match key {
            "uuid" | "deployment_uuid" | "parent_deployment_uuid" => self.uuid_for(text),
            "name" | "application_name" | "server_name" => {
                let n = self.pseudonym("name", text);
                format!("name-{n}")
            }
            "description" | "commit_message" => {
                let n = self.pseudonym("text", text);
                format!("{key}-{n}")
            }
            "fqdn" | "domain" => text
                .split(',')
                .map(|host| {
                    let n = self.pseudonym("host", host.trim());
                    format!("https://app-{n}.example.test")
                })
                .collect::<Vec<_>>()
                .join(","),
            "ip" => {
                let n = self.pseudonym("ip", text);
                format!("192.0.2.{}", n % 250 + 1)
            }
            "git_repository" => {
                let n = self.pseudonym("repo", text);
                format!("example-org/repo-{n}")
            }
            "git_branch" => "main".to_owned(),
            "commit" => {
                let n = self.pseudonym("commit", text);
                format!("{n:040x}")
            }
            "docker_registry_image_name" => {
                let n = self.pseudonym("image", text);
                format!("registry.example.test/image-{n}")
            }
            "docker_registry_image_tag" => "latest".to_owned(),
            // The name can identify a private project; keep at most the tag.
            "image" => match text.rsplit_once(':') {
                Some((_, tag)) if !tag.contains('/') && tag.len() <= 40 => {
                    format!("[scrubbed]:{tag}")
                }
                _ => "[scrubbed]".to_owned(),
            },
            _ => "[scrubbed]".to_owned(),
        }
    }
}

/// Refuses scrubbed output that still carries the token, the instance host,
/// a credential shape, a hostname outside `.example.test`, or an address
/// outside 192.0.2.0/24.
///
/// # Errors
///
/// Fails with a description that never includes the offending text.
pub fn ensure_clean(output: &str, token: &str, instance_host: Option<&str>) -> Result<(), String> {
    if !token.is_empty() && output.contains(token) {
        return Err("the scrubbed output still contains the token".to_owned());
    }
    if let Some(host) = instance_host.filter(|host| !host.is_empty())
        && output
            .to_ascii_lowercase()
            .contains(&host.to_ascii_lowercase())
    {
        return Err("the scrubbed output still contains the instance host".to_owned());
    }
    if fleet_core::redact_credentials(output) != output {
        return Err("the scrubbed output still contains a credential shape".to_owned());
    }
    for word in output.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        let word = word.trim_matches(|c| c == '.' || c == '-');
        if !word.contains('.') {
            continue;
        }
        let labels: Vec<&str> = word.split('.').collect();
        if labels.iter().any(|label| label.is_empty()) {
            continue;
        }
        if labels.len() == 4
            && labels
                .iter()
                .all(|label| label.parse::<u8>().is_ok() && !label.is_empty())
        {
            if !word.starts_with("192.0.2.") {
                return Err("the scrubbed output has an address outside 192.0.2.0/24".to_owned());
            }
            continue;
        }
        let last = labels[labels.len() - 1];
        if last.len() >= 2 && last.chars().all(|c| c.is_ascii_alphabetic()) {
            let ours = word == "example.test" || word.ends_with(".example.test");
            if !ours {
                return Err(
                    "the scrubbed output has a hostname that does not end in .example.test"
                        .to_owned(),
                );
            }
        }
    }
    Ok(())
}

/// Checks every file of a fixture directory the way capture checks its own
/// output, and validates `version.txt`.
///
/// # Errors
///
/// Fails on an unreadable directory, a bad version file, or a file that is
/// not clean.
pub fn check_fixture_dir(dir: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|error| error.to_string())?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let body = std::fs::read_to_string(&path).map_err(|error| format!("{name}: {error}"))?;
        if name == "version.txt" && !crate::looks_like_version(&body) {
            return Err("version.txt is not a Coolify version".to_owned());
        }
        ensure_clean(&body, "", None).map_err(|error| format!("{name}: {error}"))?;
    }
    Ok(())
}

/// The instance host of a base URL.
fn host_of(base_url: &str) -> Option<String> {
    let rest = base_url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
    (!host.is_empty()).then(|| host.to_owned())
}

/// The uuids of the first `count` items of a raw list.
fn uuids_of(raw: &str, count: usize) -> Vec<String> {
    serde_json::from_str::<Value>(raw)
        .ok()
        .map(|value| {
            let items = match &value {
                Value::Array(items) => items.iter().collect::<Vec<_>>(),
                Value::Object(map) => map.values().collect(),
                _ => Vec::new(),
            };
            items
                .into_iter()
                .filter_map(|item| item.get("uuid")?.as_str().map(str::to_owned))
                .take(count)
                .collect()
        })
        .unwrap_or_default()
}

/// Fetches the read-only routes a discovery run requests, expanding at most
/// three projects, services, and applications, and returns `(file name,
/// scrubbed body)` pairs for a fixture directory, named the way the
/// contract tests read them (`project-environments-<uuid>.json`,
/// `service-applications-<uuid>.json`, `application-deployments-<uuid>.json`
/// with pseudonymized uuids).
///
/// # Errors
///
/// Fails when a route cannot be read or the scrubbed output is not clean.
pub async fn capture(base_url: &str, token: &str) -> Result<Vec<(String, String)>, String> {
    let limits = Limits::default();
    let client = reqwest::Client::builder()
        .timeout(limits.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "the HTTP client could not start".to_owned())?;
    let run = Run::new(client, base_url, token, limits);
    let mut scrubber = FixtureScrubber::new();
    let mut files: Vec<(String, String)> = Vec::new();
    let version = run
        .raw(Route::Version)
        .await
        .map_err(|failure| format!("version: {}", failure.detail))?;
    files.push(("version.txt".to_owned(), version.trim().to_owned()));
    let mut raw_bodies = Vec::new();
    for (name, route) in [
        ("servers.json", Route::Servers),
        ("projects.json", Route::Projects),
        ("applications.json", Route::Applications),
        ("services.json", Route::Services),
        ("databases.json", Route::Databases),
        ("deployments-active.json", Route::ActiveDeployments),
    ] {
        let body = run
            .raw(route)
            .await
            .map_err(|failure| format!("{name}: {}", failure.detail))?;
        files.push((name.to_owned(), scrub_text(&mut scrubber, &body)?));
        raw_bodies.push(body);
    }
    // The real uuids come from the raw lists; the file names carry their
    // pseudonyms, which match the scrubbed lists.
    for real in uuids_of(&raw_bodies[1], EXPAND) {
        let body = run
            .raw(Route::ProjectEnvironments(&real))
            .await
            .map_err(|failure| format!("project environments: {}", failure.detail))?;
        let name = format!("project-environments-{}.json", scrubber.uuid_for(&real));
        files.push((name, scrub_text(&mut scrubber, &body)?));
    }
    for real in uuids_of(&raw_bodies[3], EXPAND) {
        match run.raw(Route::ServiceApplications(&real)).await {
            Ok(body) => {
                let name = format!("service-applications-{}.json", scrubber.uuid_for(&real));
                files.push((name, scrub_text(&mut scrubber, &body)?));
            }
            // Before Coolify v4.2.0 the route does not exist; discovery
            // tolerates that, so capture does too.
            Err(failure) if failure.kind == fleet_application::coolify::FailureKind::NotFound => {}
            Err(failure) => return Err(format!("service applications: {}", failure.detail)),
        }
    }
    for real in uuids_of(&raw_bodies[2], EXPAND) {
        let body = run
            .raw(Route::ApplicationDeployments(&real))
            .await
            .map_err(|failure| format!("application deployments: {}", failure.detail))?;
        let name = format!("application-deployments-{}.json", scrubber.uuid_for(&real));
        files.push((name, scrub_text(&mut scrubber, &body)?));
    }
    let host = host_of(base_url);
    for (name, body) in &files {
        if name == "version.txt" && !crate::looks_like_version(body) {
            return Err("version.txt: not a Coolify version".to_owned());
        }
        ensure_clean(body, token, host.as_deref()).map_err(|error| format!("{name}: {error}"))?;
    }
    Ok(files)
}

fn scrub_text(scrubber: &mut FixtureScrubber, body: &str) -> Result<String, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| "a response was not JSON".to_owned())?;
    serde_json::to_string_pretty(&scrubber.scrub(&value))
        .map_err(|_| "the scrubbed output could not be rendered".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secrets_are_dropped_and_identities_become_stable_pseudonyms() {
        let mut scrubber = FixtureScrubber::new();
        let input = json!({
            "uuid": "abc123real",
            "name": "prod-api",
            "ip": "10.1.2.3",
            "fqdn": "https://api.real-company.com,https://x.real-company.com",
            "status": "running:healthy",
            "image": "registry.real-company.com/team/secret-app:1.2",
            "postgres_password": "hunter2",
            "manual_webhook_secret_github": "whsec",
            "docker_compose_raw": "services: {}",
            "environment_variables": [{"key": "A", "value": "B"}],
            "logs": "token=abc",
            "settings": {"is_reachable": true, "api_token": "t"},
            "unknown_field": "free text with real-company.com",
            "real-company.com": {"x": "y"},
            "port": 22,
        });
        let out = scrubber.scrub(&input);
        let rendered = out.to_string();
        for leak in [
            "abc123real",
            "prod-api",
            "10.1.2.3",
            "real-company",
            "hunter2",
            "whsec",
            "services",
            "token=abc",
            "secret-app",
        ] {
            assert!(!rendered.contains(leak), "{leak} leaked: {rendered}");
        }
        assert_eq!(out["status"], "running:healthy");
        assert_eq!(out["port"], 22);
        assert_eq!(out["image"], "[scrubbed]:1.2");
        assert_eq!(out["settings"]["is_reachable"], true);
        assert_eq!(out["unknown_field"], "[scrubbed]");
        assert!(out.get("postgres_password").is_none());
        assert!(
            out.as_object()
                .unwrap()
                .keys()
                .any(|key| key.starts_with("key-")),
            "hostname keys are pseudonyms"
        );
        // Stable across files, and the same as the file-name pseudonym.
        let again = scrubber.scrub(&json!({"uuid": "abc123real"}));
        assert_eq!(again["uuid"], out["uuid"]);
        assert_eq!(again["uuid"], scrubber.uuid_for("abc123real"));
    }

    #[test]
    fn ensure_clean_refuses_the_token_hosts_addresses_and_credential_shapes() {
        let ok = |text: &str| ensure_clean(text, "tok-123", Some("coolify.corp.com"));
        assert!(ok("{\"a\": \"https://app-1.example.test\", \"ip\": \"192.0.2.9\"}").is_ok());
        assert!(ok("{\"version\": \"4.4.6\", \"at\": \"2026-01-15T10:00:00.000000Z\"}").is_ok());
        assert!(ok("x tok-123 y").is_err());
        assert!(ok("see https://user:hunter2@example.test/x").is_err());
        assert!(ok("https://COOLIFY.corp.com/api").is_err());
        assert!(ok("https://app.other.com/x").is_err());
        assert!(ok("ip 10.0.0.5").is_err());
        assert!(ok("ip 198.51.100.7").is_err());
        assert!(ok("host example.test.evil.org").is_err());
    }

    #[test]
    fn the_instance_host_is_read_from_the_base_url() {
        assert_eq!(
            host_of("https://user@coolify.corp.com:8443/x").as_deref(),
            Some("coolify.corp.com")
        );
        assert_eq!(host_of("http://127.0.0.1:9").as_deref(), Some("127.0.0.1"));
    }
}
