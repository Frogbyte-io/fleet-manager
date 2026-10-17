//! Settings calls over Coolify's REST API (FM-1034): environment variables,
//! domains, and the health check.
//!
//! A separate client surface from read discovery ([`crate::discovery`],
//! GET-only) and from lifecycle ([`crate::lifecycle`]); they share the
//! sender, so the same rules hold: https only (a loopback address excepted),
//! no redirects, a bounded body, classified failures. The set of requests is
//! closed: a [`Route`] is a variant, and the only interpolated parts are
//! Coolify uuids checked against a strict character set.
//!
//! # Routes (coollabsio/coolify `routes/api.php`, v4.2.0 to v4.4.6)
//!
//! | call | request | ability |
//! | --- | --- | --- |
//! | list variables | `GET /{applications,services}/{uuid}/envs` | `read` |
//! | create variable | `POST /{applications,services}/{uuid}/envs` | `write` |
//! | update variable | `PATCH /{applications,services}/{uuid}/envs` | `write` |
//! | delete variable | `DELETE /{applications,services}/{uuid}/envs/{env_uuid}` | `write` |
//! | read application | `GET /applications/{uuid}` | `read` |
//! | change application | `PATCH /applications/{uuid}` | `write` |
//!
//! # Values
//!
//! Coolify's `EnvironmentVariable` model lists `value` and `real_value` in
//! `$hidden`; a controller makes them visible only for a token with
//! `read:sensitive` whose user is a team admin. Fleet never asks for that
//! ability. The listing parser here has no value field at all, so even a
//! token that was given the ability cannot make a value leave this module.
//! A variable is written with the full set of flags every time: Coolify's
//! `PATCH` overwrites a flag the body leaves out.
//!
//! A write that carries a value reports a failure by status only (the
//! `quiet` sender mode): a validation message from Coolify could quote the
//! input. Redirects are not followed, because that could carry the token to
//! another origin.

use std::time::Duration;

use async_trait::async_trait;
use fleet_application::coolify::lifecycle::{
    LifecycleFailure, LifecycleFailureClass, LifecycleResource,
};
use fleet_application::coolify::settings::{
    ApplicationPatch, CoolifySettingsPort, EnvFlags, EnvWrite, HealthSettings, RemoteApplication,
    RemoteEnv,
};
use fleet_core::SensitiveString;
use serde_json::{Map, Value, json};

use crate::REQUEST_TIMEOUT;
use crate::lifecycle::{Request, send_request};

/// The most bytes read from a settings answer.
const BODY: usize = 2 * 1024 * 1024;
/// How long a write may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The only requests this client sends.
#[derive(Clone, Copy, Debug)]
pub enum Route<'a> {
    /// `GET /{family}/{uuid}/envs`.
    ListEnvs(LifecycleResource, &'a str),
    /// `POST /{family}/{uuid}/envs`.
    CreateEnv(LifecycleResource, &'a str),
    /// `PATCH /{family}/{uuid}/envs`.
    UpdateEnv(LifecycleResource, &'a str),
    /// `DELETE /{family}/{uuid}/envs/{env_uuid}`.
    DeleteEnv(LifecycleResource, &'a str, &'a str),
    /// `GET /applications/{uuid}`.
    Application(&'a str),
    /// `PATCH /applications/{uuid}`.
    PatchApplication(&'a str),
}

fn safe_id(id: &str) -> Option<&str> {
    (!id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
    .then_some(id)
}

/// Variables exist on applications and services only.
const fn family(resource: LifecycleResource) -> Option<&'static str> {
    match resource {
        LifecycleResource::Application => Some("applications"),
        LifecycleResource::Service => Some("services"),
        LifecycleResource::Database => None,
    }
}

impl Route<'_> {
    /// The HTTP method.
    #[must_use]
    pub fn method(&self) -> reqwest::Method {
        match self {
            Self::ListEnvs(..) | Self::Application(_) => reqwest::Method::GET,
            Self::CreateEnv(..) => reqwest::Method::POST,
            Self::UpdateEnv(..) | Self::PatchApplication(_) => reqwest::Method::PATCH,
            Self::DeleteEnv(..) => reqwest::Method::DELETE,
        }
    }

    /// The request path, or `None` for an unsafe identifier or a resource
    /// kind with no such route.
    #[must_use]
    pub fn path(&self) -> Option<String> {
        let base = "/api/v1";
        Some(match self {
            Self::ListEnvs(resource, uuid)
            | Self::CreateEnv(resource, uuid)
            | Self::UpdateEnv(resource, uuid) => {
                format!("{base}/{}/{}/envs", family(*resource)?, safe_id(uuid)?)
            }
            Self::DeleteEnv(resource, uuid, env) => format!(
                "{base}/{}/{}/envs/{}",
                family(*resource)?,
                safe_id(uuid)?,
                safe_id(env)?
            ),
            Self::Application(uuid) | Self::PatchApplication(uuid) => {
                format!("{base}/applications/{}", safe_id(uuid)?)
            }
        })
    }

    fn is_write(&self) -> bool {
        !matches!(self, Self::ListEnvs(..) | Self::Application(_))
    }
}

/// The settings client over HTTP.
#[derive(Debug, Default)]
pub struct CoolifyHttpSettings;

fn failure(class: LifecycleFailureClass, detail: &str) -> LifecycleFailure {
    LifecycleFailure::new(class, detail)
}

async fn call(
    base_url: &str,
    token: &SensitiveString,
    route: Route<'_>,
    body: Option<String>,
    quiet: bool,
) -> Result<String, LifecycleFailure> {
    let Some(path) = route.path() else {
        return Err(failure(
            LifecycleFailureClass::Invalid,
            "the identifier has an unexpected shape, or the resource has no such setting",
        ));
    };
    send_request(
        base_url,
        token,
        &Request {
            method: route.method(),
            path,
            body,
            timeout: if route.is_write() {
                WRITE_TIMEOUT
            } else {
                REQUEST_TIMEOUT
            },
            needs: if route.is_write() {
                "changing settings needs the write ability"
            } else {
                "reading settings needs the read ability"
            },
            quiet,
        },
        BODY,
    )
    .await
}

fn json_of(text: &str) -> Result<Value, LifecycleFailure> {
    serde_json::from_str(text).map_err(|_| {
        failure(
            LifecycleFailureClass::Unavailable,
            "the answer is not the documented JSON",
        )
    })
}

/// A boolean Coolify may carry as a bool, `0`/`1`, or a string.
fn bool_of(value: Option<&Value>, default: bool) -> bool {
    match value {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_i64().is_some_and(|n| n != 0),
        Some(Value::String(text)) => matches!(text.trim(), "1" | "true"),
        _ => default,
    }
}

fn uint_of(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn text_of(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Translates one listed variable. Only the key, the id, and the flags are
/// read: there is deliberately no path to `value` or `real_value`.
fn env_of(item: &Value) -> Option<RemoteEnv> {
    let uuid = item.get("uuid")?.as_str().and_then(safe_id)?.to_owned();
    let key = item.get("key")?.as_str()?.to_owned();
    Some(RemoteEnv {
        uuid,
        key,
        is_preview: bool_of(item.get("is_preview"), false),
        is_shared: bool_of(item.get("is_shared"), false),
        flags: EnvFlags {
            is_buildtime: bool_of(item.get("is_buildtime"), true),
            is_runtime: bool_of(item.get("is_runtime"), true),
            is_multiline: bool_of(item.get("is_multiline"), false),
            is_literal: bool_of(item.get("is_literal"), false),
            is_shown_once: bool_of(item.get("is_shown_once"), false),
        },
    })
}

fn health_of(value: &Value) -> HealthSettings {
    let small = |name: &str, default: u32| {
        uint_of(value.get(name))
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(default)
    };
    HealthSettings {
        check_type: text_of(value.get("health_check_type")).unwrap_or_else(|| "http".to_owned()),
        enabled: bool_of(value.get("health_check_enabled"), false),
        path: text_of(value.get("health_check_path")).unwrap_or_else(|| "/".to_owned()),
        port: uint_of(value.get("health_check_port")).and_then(|n| u16::try_from(n).ok()),
        host: text_of(value.get("health_check_host")),
        method: text_of(value.get("health_check_method")).unwrap_or_else(|| "GET".to_owned()),
        scheme: text_of(value.get("health_check_scheme")).unwrap_or_else(|| "http".to_owned()),
        return_code: uint_of(value.get("health_check_return_code"))
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(200),
        response_text: text_of(value.get("health_check_response_text")),
        interval: small("health_check_interval", 5),
        timeout: small("health_check_timeout", 5),
        retries: small("health_check_retries", 10),
        start_period: small("health_check_start_period", 5),
    }
}

/// The JSON body of a variable write: the value and the full flag set.
fn env_body(resource: LifecycleResource, write: &EnvWrite<'_>) -> String {
    let mut body = Map::new();
    body.insert("key".to_owned(), json!(write.key));
    body.insert("value".to_owned(), json!(write.value.expose()));
    body.insert("is_literal".to_owned(), json!(write.flags.is_literal));
    body.insert("is_multiline".to_owned(), json!(write.flags.is_multiline));
    body.insert("is_shown_once".to_owned(), json!(write.flags.is_shown_once));
    if resource == LifecycleResource::Application {
        // A service's variables have no preview, build, or runtime scope.
        body.insert("is_preview".to_owned(), json!(write.is_preview));
        body.insert("is_runtime".to_owned(), json!(write.flags.is_runtime));
        body.insert("is_buildtime".to_owned(), json!(write.flags.is_buildtime));
    }
    Value::Object(body).to_string()
}

/// The JSON body of an application change.
fn patch_body(patch: &ApplicationPatch) -> String {
    let mut body = Map::new();
    if let Some(domains) = &patch.domains {
        // An empty list clears the domains (Coolify reads a null as blank).
        body.insert(
            "domains".to_owned(),
            if domains.is_empty() {
                Value::Null
            } else {
                json!(domains.join(","))
            },
        );
    }
    if let Some(health) = &patch.health {
        let mut put = |name: &str, value: Option<Value>| {
            if let Some(value) = value {
                body.insert(name.to_owned(), value);
            }
        };
        put("health_check_enabled", health.enabled.map(|v| json!(v)));
        put("health_check_path", health.path.as_ref().map(|v| json!(v)));
        put("health_check_port", health.port.map(|v| json!(v)));
        put("health_check_host", health.host.as_ref().map(|v| json!(v)));
        put(
            "health_check_method",
            health.method.as_ref().map(|v| json!(v)),
        );
        put(
            "health_check_return_code",
            health.return_code.map(|v| json!(v)),
        );
        put(
            "health_check_scheme",
            health.scheme.as_ref().map(|v| json!(v)),
        );
        put(
            "health_check_response_text",
            health.response_text.as_ref().map(|v| json!(v)),
        );
        put("health_check_interval", health.interval.map(|v| json!(v)));
        put("health_check_timeout", health.timeout.map(|v| json!(v)));
        put("health_check_retries", health.retries.map(|v| json!(v)));
        put(
            "health_check_start_period",
            health.start_period.map(|v| json!(v)),
        );
        // A cleared field is sent as null (Coolify reads it as blank).
        for (name, field) in [
            ("port", "health_check_port"),
            ("host", "health_check_host"),
            ("responseText", "health_check_response_text"),
        ] {
            if health.clear.iter().any(|cleared| cleared == name) {
                put(field, Some(Value::Null));
            }
        }
    }
    Value::Object(body).to_string()
}

#[async_trait]
impl CoolifySettingsPort for CoolifyHttpSettings {
    async fn read_envs(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
    ) -> Result<Vec<RemoteEnv>, LifecycleFailure> {
        let text = call(
            base_url,
            token,
            Route::ListEnvs(resource, uuid),
            None,
            false,
        )
        .await?;
        let value = json_of(&text)?;
        let items = value.as_array().ok_or_else(|| {
            failure(
                LifecycleFailureClass::Unavailable,
                "the variable list is not the documented JSON array",
            )
        })?;
        Ok(items.iter().filter_map(env_of).collect())
    }

    async fn read_application(
        &self,
        base_url: &str,
        token: &SensitiveString,
        uuid: &str,
    ) -> Result<RemoteApplication, LifecycleFailure> {
        let text = call(base_url, token, Route::Application(uuid), None, false).await?;
        let value = json_of(&text)?;
        if !value.is_object() {
            return Err(failure(
                LifecycleFailureClass::Unavailable,
                "the application is not the documented JSON object",
            ));
        }
        let domains = text_of(value.get("fqdn"))
            .map(|fqdn| {
                fqdn.split(',')
                    .map(str::trim)
                    .filter(|domain| !domain.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(RemoteApplication {
            build_pack: text_of(value.get("build_pack")).unwrap_or_default(),
            domains,
            health: health_of(&value),
        })
    }

    async fn create_env(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
        write: &EnvWrite<'_>,
    ) -> Result<(), LifecycleFailure> {
        call(
            base_url,
            token,
            Route::CreateEnv(resource, uuid),
            Some(env_body(resource, write)),
            true,
        )
        .await
        .map(|_| ())
    }

    async fn update_env(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
        write: &EnvWrite<'_>,
    ) -> Result<(), LifecycleFailure> {
        call(
            base_url,
            token,
            Route::UpdateEnv(resource, uuid),
            Some(env_body(resource, write)),
            true,
        )
        .await
        .map(|_| ())
    }

    async fn delete_env(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
        env_uuid: &str,
    ) -> Result<(), LifecycleFailure> {
        call(
            base_url,
            token,
            Route::DeleteEnv(resource, uuid, env_uuid),
            None,
            true,
        )
        .await
        .map(|_| ())
    }

    async fn patch_application(
        &self,
        base_url: &str,
        token: &SensitiveString,
        uuid: &str,
        patch: &ApplicationPatch,
    ) -> Result<(), LifecycleFailure> {
        call(
            base_url,
            token,
            Route::PatchApplication(uuid),
            Some(patch_body(patch)),
            false,
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_application::coolify::settings::HealthPatch;

    #[test]
    fn the_route_set_is_closed_and_paths_are_exact() {
        let app = LifecycleResource::Application;
        let svc = LifecycleResource::Service;
        assert_eq!(
            Route::ListEnvs(app, "abc").path().as_deref(),
            Some("/api/v1/applications/abc/envs")
        );
        assert_eq!(
            Route::CreateEnv(svc, "abc").path().as_deref(),
            Some("/api/v1/services/abc/envs")
        );
        assert_eq!(
            Route::DeleteEnv(app, "abc", "e-1").path().as_deref(),
            Some("/api/v1/applications/abc/envs/e-1")
        );
        assert_eq!(
            Route::PatchApplication("abc").path().as_deref(),
            Some("/api/v1/applications/abc")
        );
        // A database has no variable routes; an odd id has no path at all.
        assert_eq!(
            Route::ListEnvs(LifecycleResource::Database, "abc").path(),
            None
        );
        assert_eq!(Route::Application("a/../b").path(), None);
        assert_eq!(Route::DeleteEnv(app, "abc", "x?y").path(), None);
        // Methods and which routes write.
        assert_eq!(Route::ListEnvs(app, "a").method(), reqwest::Method::GET);
        assert_eq!(Route::UpdateEnv(app, "a").method(), reqwest::Method::PATCH);
        assert_eq!(
            Route::DeleteEnv(app, "a", "b").method(),
            reqwest::Method::DELETE
        );
        assert!(Route::PatchApplication("a").is_write());
        assert!(!Route::Application("a").is_write());
    }

    #[test]
    fn a_listing_yields_keys_and_flags_and_never_a_value() {
        // A token with read:sensitive would have `value` here; the parser
        // has no path to it.
        let item = json!({
            "uuid": "env-1", "key": "DATABASE_URL", "value": "postgres://u:p@h/db",
            "real_value": "postgres://u:p@h/db", "is_preview": false, "is_buildtime": 1,
            "is_runtime": true, "is_multiline": false, "is_literal": 0,
            "is_shown_once": true, "is_shared": false
        });
        let env = env_of(&item).expect("parses");
        assert_eq!(env.key, "DATABASE_URL");
        assert!(env.flags.is_shown_once && env.flags.is_buildtime);
        assert!(!format!("{env:?}").contains("postgres"));
        // A malformed entry is skipped, not guessed at.
        assert!(env_of(&json!({"key": "X"})).is_none());
        assert!(env_of(&json!({"uuid": "a b", "key": "X"})).is_none());
    }

    #[test]
    fn health_reads_tolerate_strings_and_missing_fields() {
        let health = health_of(&json!({
            "health_check_enabled": "1", "health_check_path": "/up",
            "health_check_port": "8080", "health_check_return_code": 204,
            "health_check_interval": "30"
        }));
        assert!(health.enabled);
        assert_eq!(health.path, "/up");
        assert_eq!(health.port, Some(8080));
        assert_eq!(health.return_code, 204);
        assert_eq!(health.interval, 30);
        assert_eq!(health.retries, 10);
        assert_eq!(health.host, None);
    }

    #[test]
    fn bodies_carry_the_full_flag_set_and_only_the_named_fields() {
        let value = SensitiveString::new("s3cret-value");
        let write = EnvWrite {
            key: "API_KEY",
            value: &value,
            is_preview: true,
            flags: EnvFlags {
                is_buildtime: false,
                ..EnvFlags::default()
            },
        };
        let body: Value =
            serde_json::from_str(&env_body(LifecycleResource::Application, &write)).unwrap();
        assert_eq!(body["key"], "API_KEY");
        assert_eq!(body["value"], "s3cret-value");
        assert_eq!(body["is_preview"], true);
        assert_eq!(body["is_buildtime"], false);
        assert_eq!(body["is_runtime"], true);
        assert!(body.get("is_multiline").is_some() && body.get("is_literal").is_some());
        let service: Value =
            serde_json::from_str(&env_body(LifecycleResource::Service, &write)).unwrap();
        assert!(service.get("is_preview").is_none() && service.get("is_buildtime").is_none());
        assert!(!format!("{write:?}").contains("s3cret"));

        let body: Value = serde_json::from_str(&patch_body(&ApplicationPatch {
            domains: Some(vec![
                "https://a.example.com".to_owned(),
                "https://b.example.com".to_owned(),
            ]),
            health: Some(HealthPatch {
                retries: Some(3),
                ..HealthPatch::default()
            }),
        }))
        .unwrap();
        assert_eq!(
            body["domains"],
            "https://a.example.com,https://b.example.com"
        );
        assert_eq!(body["health_check_retries"], 3);
        assert!(body.get("health_check_path").is_none());
        assert!(body.get("instant_deploy").is_none());
        let cleared: Value = serde_json::from_str(&patch_body(&ApplicationPatch {
            domains: Some(Vec::new()),
            health: None,
        }))
        .unwrap();
        assert!(cleared["domains"].is_null());
    }
}
