//! The translation boundary: Coolify JSON in, Fleet types out.
//!
//! Every function reads an explicit allow-list of fields. A field that is
//! not named here (environment variable values, database passwords, raw
//! Compose files, webhook secrets, basic-auth passwords, deployment logs,
//! nested server credentials, anything Coolify adds later) never leaves
//! this module, whatever the token's abilities and whatever the instance
//! returns. Text that is kept is bounded, stripped of control characters,
//! and scrubbed for credential shapes.

use fleet_application::coolify::{
    CoolifyApplication, CoolifyDatabase, CoolifyDeployment, CoolifyEnvironment, CoolifyProject,
    CoolifyServer, CoolifyService,
};
use fleet_core::{flatten_control_characters, redact_credentials, redact_url_credentials};
use serde_json::Value;

const SHORT: usize = 200;
const LONG: usize = 500;
const MAX_FQDNS: usize = 50;

pub(crate) fn clean(text: &str, bound: usize) -> String {
    let flat = flatten_control_characters(&redact_credentials(&redact_url_credentials(text)));
    flat.chars().take(bound).collect()
}

fn text(object: &Value, key: &str, bound: usize) -> Option<String> {
    let value = object.get(key)?.as_str()?;
    let value = clean(value, bound);
    (!value.is_empty()).then_some(value)
}

fn text_or_empty(object: &Value, key: &str, bound: usize) -> String {
    text(object, key, bound).unwrap_or_default()
}

fn int(object: &Value, key: &str) -> Option<i64> {
    let value = object.get(key)?;
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

fn flag(object: &Value, key: &str) -> Option<bool> {
    let value = object.get(key)?;
    value
        .as_bool()
        .or_else(|| value.as_i64().map(|n| n != 0))
        .or_else(|| match value.as_str() {
            Some("true" | "1") => Some(true),
            Some("false" | "0") => Some(false),
            _ => None,
        })
}

/// Splits Coolify's comma-separated `fqdn`.
fn fqdns_of(raw: Option<&str>) -> Vec<String> {
    raw.map(|raw| {
        raw.split(',')
            .map(|entry| clean(entry.trim(), SHORT))
            .filter(|entry| !entry.is_empty())
            .take(MAX_FQDNS)
            .collect()
    })
    .unwrap_or_default()
}

/// The domains a Compose application declares in `docker_compose_domains`
/// (a JSON string or object of `service -> {domain}`).
fn compose_domains(application: &Value) -> Vec<String> {
    let parsed;
    let map = match application.get("docker_compose_domains") {
        Some(Value::String(raw)) => {
            parsed = serde_json::from_str::<Value>(raw).unwrap_or(Value::Null);
            &parsed
        }
        Some(other) => other,
        None => return Vec::new(),
    };
    let entries: Vec<&Value> = match map {
        Value::Object(services) => services.values().collect(),
        Value::Array(entries) => entries.iter().collect(),
        _ => Vec::new(),
    };
    let mut domains = Vec::new();
    for entry in entries {
        if let Some(domain) = entry.get("domain").and_then(Value::as_str) {
            domains.extend(fqdns_of(Some(domain)));
        }
    }
    domains
}

fn push_unique(into: &mut Vec<String>, more: Vec<String>) {
    for item in more {
        if into.len() < MAX_FQDNS && !into.contains(&item) {
            into.push(item);
        }
    }
}

/// A server. `None` without a uuid.
pub(crate) fn server(value: &Value) -> Option<CoolifyServer> {
    let uuid = text(value, "uuid", SHORT)?;
    let settings = value.get("settings").unwrap_or(&Value::Null);
    let proxy_type = text(value, "proxy_type", 40)
        .or_else(|| value.get("proxy").and_then(|proxy| text(proxy, "type", 40)));
    Some(CoolifyServer {
        uuid,
        name: text_or_empty(value, "name", SHORT),
        description: text_or_empty(value, "description", LONG),
        address: text_or_empty(value, "ip", SHORT),
        proxy_type,
        reachable: flag(settings, "is_reachable"),
        usable: flag(settings, "is_usable"),
    })
}

/// A project without its environments.
pub(crate) fn project(value: &Value) -> Option<CoolifyProject> {
    Some(CoolifyProject {
        uuid: text(value, "uuid", SHORT)?,
        name: text_or_empty(value, "name", SHORT),
        description: text_or_empty(value, "description", LONG),
        environments: Vec::new(),
        details_stale: false,
    })
}

/// An environment. `None` without a numeric id.
pub(crate) fn environment(value: &Value) -> Option<CoolifyEnvironment> {
    Some(CoolifyEnvironment {
        id: int(value, "id")?,
        name: text_or_empty(value, "name", SHORT),
        description: text_or_empty(value, "description", LONG),
    })
}

/// An application. Reads no environment variables, no Compose content, no
/// webhook secrets, and no basic-auth credentials.
pub(crate) fn application(value: &Value) -> Option<CoolifyApplication> {
    let mut fqdns = fqdns_of(value.get("fqdn").and_then(Value::as_str));
    push_unique(&mut fqdns, compose_domains(value));
    let image = text(value, "docker_registry_image_name", SHORT).map(|name| {
        match text(value, "docker_registry_image_tag", 100) {
            Some(tag) => format!("{name}:{tag}"),
            None => name,
        }
    });
    Some(CoolifyApplication {
        uuid: text(value, "uuid", SHORT)?,
        name: text_or_empty(value, "name", SHORT),
        description: text_or_empty(value, "description", LONG),
        status: text_or_empty(value, "status", 60),
        fqdns,
        environment_id: int(value, "environment_id"),
        build_pack: text(value, "build_pack", 40),
        git_repository: text(value, "git_repository", SHORT),
        git_branch: text(value, "git_branch", SHORT),
        docker_image: image,
        created_at: text(value, "created_at", 40),
        updated_at: text(value, "updated_at", 40),
    })
}

/// A service. Reads no Compose content.
pub(crate) fn service(value: &Value) -> Option<CoolifyService> {
    Some(CoolifyService {
        uuid: text(value, "uuid", SHORT)?,
        name: text_or_empty(value, "name", SHORT),
        description: text_or_empty(value, "description", LONG),
        status: text(value, "status", 60),
        service_type: text(value, "service_type", 100),
        environment_id: int(value, "environment_id"),
        fqdns: Vec::new(),
        details_stale: false,
        created_at: text(value, "created_at", 40),
        updated_at: text(value, "updated_at", 40),
    })
}

/// The public hostnames of a service's applications
/// (`/services/{uuid}/applications` items).
pub(crate) fn service_fqdns(applications: &Value) -> Vec<String> {
    let mut all = Vec::new();
    if let Some(items) = applications.as_array() {
        for item in items {
            push_unique(&mut all, fqdns_of(item.get("fqdn").and_then(Value::as_str)));
        }
    }
    all
}

/// A database. Reads no passwords, URLs, init scripts, or backup configs.
pub(crate) fn database(value: &Value) -> Option<CoolifyDatabase> {
    let image = text(value, "image", SHORT);
    let engine = text(value, "database_type", 60)
        .or_else(|| text(value, "type", 60))
        .map(|kind| kind.strip_prefix("standalone-").unwrap_or(&kind).to_owned())
        .or_else(|| {
            let image = image.as_deref()?;
            let name = image.rsplit('/').next()?.split(':').next()?;
            (!name.is_empty()).then(|| name.to_owned())
        });
    Some(CoolifyDatabase {
        uuid: text(value, "uuid", SHORT)?,
        name: text_or_empty(value, "name", SHORT),
        description: text_or_empty(value, "description", LONG),
        status: text_or_empty(value, "status", 60),
        engine,
        image,
        environment_id: int(value, "environment_id"),
        is_public: flag(value, "is_public"),
        public_port: int(value, "public_port"),
    })
}

/// A deployment. Never reads `logs`, `configuration_snapshot`, or
/// `configuration_diff`.
pub(crate) fn deployment(
    value: &Value,
    application_uuid: Option<&str>,
) -> Option<CoolifyDeployment> {
    let message = text(value, "commit_message", 400)
        .map(|message| message.lines().next().unwrap_or_default().to_owned())
        .filter(|message| !message.is_empty());
    Some(CoolifyDeployment {
        deployment_uuid: text(value, "deployment_uuid", SHORT)?,
        application_name: text(value, "application_name", SHORT),
        application_uuid: application_uuid.map(|uuid| clean(uuid, SHORT)),
        server_name: text(value, "server_name", SHORT),
        status: text_or_empty(value, "status", 40),
        commit: text(value, "commit", 80),
        commit_message: message,
        is_webhook: flag(value, "is_webhook"),
        is_api: flag(value, "is_api"),
        pull_request_id: int(value, "pull_request_id"),
        created_at: text(value, "created_at", 40),
        updated_at: text(value, "updated_at", 40),
    })
}
