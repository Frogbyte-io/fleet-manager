//! Scrubbing for recorded contract fixtures (FM-1030).
//!
//! A fixture recorded from a real Coolify instance must carry the response
//! shape and nothing of the instance. The scrubber is default-deny:
//!
//! * a key that can hold a secret (password, secret, token, key, env,
//!   compose, logs, command, label, script, url) is removed entirely;
//! * identities and names become stable pseudonyms (the same real value
//!   maps to the same pseudonym across files, so references still line up);
//! * hostnames become `*.example.test`, addresses become TEST-NET-1;
//! * a short allow-list of enumerations (status, build pack, proxy type,
//!   service type) and all numbers and booleans pass through;
//! * every other string becomes `[scrubbed]`.
//!
//! [`capture`] fetches the read-only routes of a live instance and returns
//! the scrubbed bodies; [`ensure_clean`] refuses output that still carries
//! the token or a credential shape. The ignored test
//! `tests/capture.rs` drives them for an operator.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::discovery::{Route, Run};

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

/// The stable pseudonym table for one capture session.
#[derive(Debug, Default)]
pub struct FixtureScrubber {
    names: HashMap<(String, String), String>,
}

impl FixtureScrubber {
    /// A fresh scrubber.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn pseudonym(&mut self, class: &str, real: &str) -> usize {
        let next = self.names.len() + 1;
        let entry = self
            .names
            .entry((class.to_owned(), real.to_owned()))
            .or_insert_with(|| next.to_string());
        entry.parse().unwrap_or(0)
    }

    /// Scrubs one JSON document.
    pub fn scrub(&mut self, value: &Value) -> Value {
        self.value(None, value)
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
                    out.insert(name.clone(), self.value(Some(&lower), inner));
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
            "uuid" | "deployment_uuid" | "parent_deployment_uuid" => {
                let n = self.pseudonym("uuid", text);
                format!("uuid{n:020}")
            }
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
            "image" => text
                .rsplit('/')
                .next()
                .unwrap_or("image")
                .chars()
                .take(60)
                .collect(),
            _ => "[scrubbed]".to_owned(),
        }
    }
}

/// Refuses scrubbed output that still carries the token or a credential
/// shape.
///
/// # Errors
///
/// Fails with a description that never includes the offending text.
pub fn ensure_clean(output: &str, token: &str) -> Result<(), String> {
    if !token.is_empty() && output.contains(token) {
        return Err("the scrubbed output still contains the token".to_owned());
    }
    if fleet_core::redact_credentials(output) != output {
        return Err("the scrubbed output still contains a credential shape".to_owned());
    }
    Ok(())
}

/// Fetches the read-only routes of a live instance and returns
/// `(file name, scrubbed body)` pairs for a fixture directory. One project,
/// service, and application are expanded to keep the set small.
///
/// # Errors
///
/// Fails when a route cannot be read or the scrubbed output is not clean.
pub async fn capture(base_url: &str, token: &str) -> Result<Vec<(String, String)>, String> {
    let client = reqwest::Client::builder()
        .timeout(crate::REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "the HTTP client could not start".to_owned())?;
    let run = Run::new(client, base_url, token);
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
    // One project, service, and application are expanded; the uuids are the
    // real ones, so they are read from the raw lists before scrubbing.
    let first_uuid = |raw: &str| {
        serde_json::from_str::<Value>(raw)
            .ok()
            .and_then(|value| value.as_array()?.first().cloned())
            .and_then(|item| item.get("uuid")?.as_str().map(str::to_owned))
    };
    let projects = first_uuid(&raw_bodies[1]);
    let applications = first_uuid(&raw_bodies[2]);
    let services = first_uuid(&raw_bodies[3]);
    for (name, route) in [
        (
            "project-environments.json",
            projects.as_deref().map(Route::ProjectEnvironments),
        ),
        (
            "service-applications.json",
            services.as_deref().map(Route::ServiceApplications),
        ),
        (
            "application-deployments.json",
            applications.as_deref().map(Route::ApplicationDeployments),
        ),
    ] {
        if let Some(route) = route {
            let body = run
                .raw(route)
                .await
                .map_err(|failure| format!("{name}: {}", failure.detail))?;
            files.push((name.to_owned(), scrub_text(&mut scrubber, &body)?));
        }
    }
    for (name, body) in &files {
        ensure_clean(body, token).map_err(|error| format!("{name}: {error}"))?;
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
            "postgres_password": "hunter2",
            "manual_webhook_secret_github": "whsec",
            "docker_compose_raw": "services: {}",
            "environment_variables": [{"key": "A", "value": "B"}],
            "logs": "token=abc",
            "settings": {"is_reachable": true, "api_token": "t"},
            "unknown_field": "free text with real-company.com",
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
        ] {
            assert!(!rendered.contains(leak), "{leak} leaked: {rendered}");
        }
        assert_eq!(out["status"], "running:healthy");
        assert_eq!(out["port"], 22);
        assert_eq!(out["settings"]["is_reachable"], true);
        assert_eq!(out["unknown_field"], "[scrubbed]");
        assert!(out.get("postgres_password").is_none());
        // Stable across files.
        let again = scrubber.scrub(&json!({"uuid": "abc123real"}));
        assert_eq!(again["uuid"], out["uuid"]);
    }

    #[test]
    fn ensure_clean_refuses_the_token_and_credential_shapes() {
        assert!(ensure_clean("{\"a\": \"b\"}", "tok-123").is_ok());
        assert!(ensure_clean("x tok-123 y", "tok-123").is_err());
        assert!(ensure_clean("https://user:hunter2@example.test/x", "tok").is_err());
    }
}
