//! Lifecycle calls over Coolify's REST API (FM-1033).
//!
//! This is a separate client surface from read discovery
//! ([`crate::discovery`], which is GET-only and refuses every lifecycle
//! path). The set of requests is closed: a [`Route`] is a variant, the only
//! interpolated parts are Coolify uuids checked against a strict character
//! set, and the mutating routes are exactly the ones below.
//!
//! # Routes (coollabsio/coolify `routes/api.php`, v4.2.0 to v4.4.6)
//!
//! | call | request | ability |
//! | --- | --- | --- |
//! | start, stop, restart | `POST /{applications,services,databases}/{uuid}/{start,stop,restart}` | `deploy` |
//! | application redeploy | `POST /deploy?uuid={uuid}&force=false` | `deploy` |
//! | status re-read | `GET /{applications,services,databases}/{uuid}` | `read` |
//! | newest deployment | `GET /deployments/applications/{uuid}?skip=0&take=1` | `read` |
//! | one deployment | `GET /deployments/{uuid}` | `read` (`logs` need `read:sensitive`) |
//!
//! Before v4.2.0 the same paths accepted `GET` as well as `POST`; from
//! v4.2.0 a `GET` answers HTTP 405 ("This endpoint has changed to a POST
//! request"). This client sends `POST` only, and the use case refuses
//! versions older than v4.2.0 from the probed `/version`, so no `GET` on a
//! lifecycle path is ever sent. Redirects are not followed, because that
//! could carry the bearer token to another origin; the token never travels
//! over plain http except to a loopback address.

use std::time::Duration;

use async_trait::async_trait;
use fleet_application::coolify::lifecycle::{
    CoolifyLifecyclePort, LifecycleAck, LifecycleFailure, LifecycleFailureClass, LifecycleResource,
    LifecycleVerb, RawDeployment,
};
use fleet_core::SensitiveString;
use serde_json::Value;

use crate::{
    REQUEST_TIMEOUT, location_host, looks_like_version, message_of, redirect_hint,
    transport_category,
};

/// The most bytes read from a lifecycle or status answer.
const SMALL_BODY: usize = 256 * 1024;
/// The most bytes read from a deployment answer (it carries the log).
const DEPLOYMENT_BODY: usize = 16 * 1024 * 1024;
/// The longest `Retry-After` reported, in seconds.
const MAX_RETRY_AFTER: u64 = 3600;

/// The only requests this client sends.
#[derive(Clone, Copy, Debug)]
pub enum Route<'a> {
    /// `GET /version`.
    Version,
    /// `GET /{kind}/{uuid}`.
    Status(LifecycleResource, &'a str),
    /// `POST /{kind}/{uuid}/{start|stop|restart}`.
    Lifecycle(LifecycleResource, &'a str, LifecycleVerb),
    /// `POST /deploy?uuid={uuid}&force=false`.
    Deploy(&'a str),
    /// `GET /deployments/applications/{uuid}?skip=0&take=1`.
    LatestDeployment(&'a str),
    /// `GET /deployments/{uuid}`.
    Deployment(&'a str),
}

fn family(resource: LifecycleResource) -> &'static str {
    match resource {
        LifecycleResource::Application => "applications",
        LifecycleResource::Service => "services",
        LifecycleResource::Database => "databases",
    }
}

fn safe_id(id: &str) -> Option<&str> {
    (!id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
    .then_some(id)
}

impl Route<'_> {
    /// The HTTP method.
    #[must_use]
    pub fn method(&self) -> reqwest::Method {
        match self {
            Self::Lifecycle(..) | Self::Deploy(_) => reqwest::Method::POST,
            _ => reqwest::Method::GET,
        }
    }

    /// The request path and query, or `None` for an unsafe identifier or a
    /// verb with no route of its own (`redeploy` is [`Route::Deploy`]).
    #[must_use]
    pub fn path(&self) -> Option<String> {
        let base = "/api/v1";
        Some(match self {
            Self::Version => format!("{base}/version"),
            Self::Status(resource, uuid) => {
                format!("{base}/{}/{}", family(*resource), safe_id(uuid)?)
            }
            Self::Lifecycle(resource, uuid, verb) => {
                let verb = match verb {
                    LifecycleVerb::Start => "start",
                    LifecycleVerb::Stop => "stop",
                    LifecycleVerb::Restart => "restart",
                    LifecycleVerb::Redeploy => return None,
                };
                format!("{base}/{}/{}/{verb}", family(*resource), safe_id(uuid)?)
            }
            Self::Deploy(uuid) => format!("{base}/deploy?uuid={}&force=false", safe_id(uuid)?),
            Self::LatestDeployment(uuid) => format!(
                "{base}/deployments/applications/{}?skip=0&take=1",
                safe_id(uuid)?
            ),
            Self::Deployment(uuid) => format!("{base}/deployments/{}", safe_id(uuid)?),
        })
    }
}

/// The lifecycle client over HTTP.
#[derive(Debug, Default)]
pub struct CoolifyHttpLifecycle;

fn failure(class: LifecycleFailureClass, detail: &str) -> LifecycleFailure {
    LifecycleFailure::new(class, detail)
}

async fn send(
    base_url: &str,
    token: &SensitiveString,
    route: Route<'_>,
    body_limit: usize,
) -> Result<String, LifecycleFailure> {
    // The bearer token never travels over plain http, except to a literal
    // loopback address (a local stub).
    if base_url.starts_with("http://") && !fleet_core::base_url_is_loopback(base_url) {
        return Err(failure(
            LifecycleFailureClass::Unavailable,
            "the base URL uses http; the token is only sent over https (edit the account to use https)",
        ));
    }
    let Some(path) = route.path() else {
        return Err(failure(
            LifecycleFailureClass::Invalid,
            "the identifier has an unexpected shape",
        ));
    };
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| {
            failure(
                LifecycleFailureClass::Unavailable,
                "the HTTP client could not start",
            )
        })?;
    let mut response = client
        .request(route.method(), format!("{base_url}{path}"))
        .bearer_auth(token.expose())
        .header("Accept", "application/json")
        .timeout(request_timeout(route))
        .send()
        .await
        .map_err(|error| {
            failure(
                LifecycleFailureClass::Unavailable,
                transport_category(&error),
            )
        })?;
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        let host = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .and_then(location_host);
        let hint = redirect_hint(base_url);
        return Err(failure(
            LifecycleFailureClass::Unavailable,
            &match host {
                Some(host) => format!("redirected to {host}; {hint}"),
                None => format!("redirected; {hint}"),
            },
        ));
    }
    if status == 429 {
        let after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map_or(0, |seconds| seconds.min(MAX_RETRY_AFTER));
        return Err(failure(
            LifecycleFailureClass::RateLimited,
            &format!("Coolify's rate limit applies; retry after {after} seconds"),
        ));
    }
    let mut buffer = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                buffer.extend_from_slice(&chunk);
                if buffer.len() > body_limit {
                    return Err(failure(
                        LifecycleFailureClass::Unavailable,
                        "the response is larger than the limit",
                    ));
                }
            }
            Ok(None) => break,
            Err(_) => {
                return Err(failure(
                    LifecycleFailureClass::Unavailable,
                    "the response ended early",
                ));
            }
        }
    }
    let text = String::from_utf8_lossy(&buffer).into_owned();
    if (200..300).contains(&status) {
        Ok(text)
    } else {
        Err(classify_error(status, &text))
    }
}

/// A call may take longer than a read: a lifecycle call queues work.
fn request_timeout(route: Route<'_>) -> Duration {
    match route {
        Route::Lifecycle(..) | Route::Deploy(_) => Duration::from_secs(30),
        _ => REQUEST_TIMEOUT,
    }
}

fn classify_error(status: u16, body: &str) -> LifecycleFailure {
    let message = message_of(body);
    match status {
        401 => failure(
            LifecycleFailureClass::Auth,
            "the token was refused (HTTP 401)",
        ),
        403 if message
            .to_ascii_lowercase()
            .contains("missing required permissions") =>
        {
            failure(
                LifecycleFailureClass::Permission,
                "the token is valid but lacks the ability for this call (lifecycle actions need the deploy ability; reading deployment logs needs read:sensitive)",
            )
        }
        403 => failure(
            LifecycleFailureClass::Auth,
            &format!("the request was refused (HTTP 403): {message}"),
        ),
        404 => failure(
            LifecycleFailureClass::NotFound,
            &format!("Coolify answered not found: {message}"),
        ),
        405 => failure(
            LifecycleFailureClass::Unsupported,
            "this Coolify answered 405 for the route; its API does not match the version it reported",
        ),
        400 | 409 | 422 => failure(
            LifecycleFailureClass::Invalid,
            &format!("Coolify refused the request (HTTP {status}): {message}"),
        ),
        other => failure(
            LifecycleFailureClass::Unavailable,
            &format!("unexpected HTTP status {other}"),
        ),
    }
}

fn json_of(text: &str) -> Result<Value, LifecycleFailure> {
    serde_json::from_str(text).map_err(|_| {
        failure(
            LifecycleFailureClass::Unavailable,
            "the answer is not the documented JSON",
        )
    })
}

/// The deployment uuid a lifecycle or deploy answer names, if any.
fn deployment_uuid_of(value: &Value) -> Option<String> {
    let direct = value.get("deployment_uuid").and_then(Value::as_str);
    let nested = value
        .get("deployments")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("deployment_uuid"))
        .and_then(Value::as_str);
    direct.or(nested).and_then(safe_id).map(str::to_owned)
}

#[async_trait]
impl CoolifyLifecyclePort for CoolifyHttpLifecycle {
    async fn version(
        &self,
        base_url: &str,
        token: &SensitiveString,
    ) -> Result<String, LifecycleFailure> {
        let text = send(base_url, token, Route::Version, 512).await?;
        if looks_like_version(&text) {
            Ok(text.trim().trim_matches('"').to_owned())
        } else {
            Err(failure(
                LifecycleFailureClass::Unavailable,
                "the answer is not a Coolify API; check the base URL",
            ))
        }
    }

    async fn run(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
        verb: LifecycleVerb,
    ) -> Result<LifecycleAck, LifecycleFailure> {
        let route = if verb == LifecycleVerb::Redeploy {
            if resource != LifecycleResource::Application {
                return Err(failure(
                    LifecycleFailureClass::Invalid,
                    "only an application can be redeployed",
                ));
            }
            Route::Deploy(uuid)
        } else {
            Route::Lifecycle(resource, uuid, verb)
        };
        let text = send(base_url, token, route, SMALL_BODY).await?;
        let value = json_of(&text).unwrap_or(Value::Null);
        Ok(LifecycleAck {
            deployment_uuid: deployment_uuid_of(&value),
        })
    }

    async fn status(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
    ) -> Result<String, LifecycleFailure> {
        let text = send(
            base_url,
            token,
            Route::Status(resource, uuid),
            SMALL_BODY * 8,
        )
        .await?;
        let value = json_of(&text)?;
        Ok(value
            .get("status")
            .and_then(Value::as_str)
            .map_or_else(|| "unknown".to_owned(), str::to_owned))
    }

    async fn latest_deployment(
        &self,
        base_url: &str,
        token: &SensitiveString,
        application_uuid: &str,
    ) -> Result<Option<String>, LifecycleFailure> {
        // The per-application list carries `logs` for a sensitive token, so
        // the bound is the deployment bound.
        let text = send(
            base_url,
            token,
            Route::LatestDeployment(application_uuid),
            DEPLOYMENT_BODY,
        )
        .await?;
        let value = json_of(&text)?;
        let items = value
            .get("deployments")
            .and_then(Value::as_array)
            .or_else(|| value.as_array());
        Ok(items
            .and_then(|items| items.first())
            .and_then(|item| item.get("deployment_uuid"))
            .and_then(Value::as_str)
            .and_then(safe_id)
            .map(str::to_owned))
    }

    async fn deployment(
        &self,
        base_url: &str,
        token: &SensitiveString,
        deployment_uuid: &str,
    ) -> Result<RawDeployment, LifecycleFailure> {
        let text = send(
            base_url,
            token,
            Route::Deployment(deployment_uuid),
            DEPLOYMENT_BODY,
        )
        .await?;
        let value = json_of(&text)?;
        // `logs` is hidden from a token without read:sensitive: the key is
        // absent then. Present but null is a deployment with no output yet.
        let logs = value.get("logs").map(|logs| match logs {
            Value::String(text) => text.clone(),
            Value::Null => "[]".to_owned(),
            other => other.to_string(),
        });
        Ok(RawDeployment {
            status: value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            logs,
        })
    }
}
