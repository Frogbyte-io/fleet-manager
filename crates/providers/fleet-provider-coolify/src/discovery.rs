//! Read discovery over Coolify's REST API (FM-1030).
//!
//! The client is GET-only and addresses a closed set of [`Route`]s, so no
//! caller can reach `/enable`, `/deploy`, `/start`, `/restart`, an `/envs`
//! route, or any other path: a route is a variant, and the only
//! interpolated parts are Coolify UUIDs checked against a strict character
//! set. It never asks for `read:sensitive` values (Coolify decides that
//! from the token; the [`crate::translate`] allow-list drops them anyway).
//! Redirects are not followed, because following one could carry the bearer
//! token to another origin.
//!
//! The run is bounded: [`REQUEST_TIMEOUT`] per request, [`RUN_BUDGET`] for
//! the whole run, [`BODY_LIMIT`] bytes per response, and a cap on the
//! per-project, per-service, and per-application follow-up requests.
//! Coolify's list endpoints are not paginated (only the per-application
//! deployment list takes `skip` and `take`), so the bound is the item cap.
//!
//! Each resource class reports for itself: a class that fails does not stop
//! the others, except that a failed `/version` (unreachable, refused, or
//! not Coolify) fails every class with the same reason without sending the
//! rest of the requests.

use std::time::Duration;

use async_trait::async_trait;
use fleet_application::coolify::{
    ClassFailure, ClassResult, CoolifyApplication, CoolifyDeployment, CoolifyProject,
    CoolifyService, CoolifySource, FailureKind, MAX_ITEMS_PER_CLASS, RawCoolifyDiscovery,
};
use fleet_core::SensitiveString;
use serde_json::Value;
use tokio::time::Instant;

use crate::{
    REQUEST_TIMEOUT, location_host, looks_like_version, message_of, redirect_hint, translate,
};

/// How long a whole run may take.
pub const RUN_BUDGET: Duration = Duration::from_secs(90);
/// The most response bytes read per request.
pub const BODY_LIMIT: usize = 8 * 1024 * 1024;
/// The most projects whose environments are fetched.
pub const MAX_PROJECTS: usize = 200;
/// The most services whose applications (hostnames) are fetched.
pub const MAX_SERVICE_LOOKUPS: usize = 100;
/// The most applications whose recent deployments are fetched.
pub const MAX_DEPLOYMENT_APPS: usize = 50;
/// How many deployments are taken per application.
pub const DEPLOYMENTS_PER_APP: u32 = 5;

/// The only requests discovery sends. All are `GET`.
#[derive(Clone, Copy, Debug)]
pub enum Route<'a> {
    /// `/version`.
    Version,
    /// `/servers`.
    Servers,
    /// `/projects`.
    Projects,
    /// `/projects/{uuid}/environments`.
    ProjectEnvironments(&'a str),
    /// `/applications`.
    Applications,
    /// `/services`.
    Services,
    /// `/services/{uuid}/applications`.
    ServiceApplications(&'a str),
    /// `/databases`.
    Databases,
    /// `/deployments` (queued and in-progress).
    ActiveDeployments,
    /// `/deployments/applications/{uuid}?skip=0&take=N`.
    ApplicationDeployments(&'a str),
}

impl Route<'_> {
    /// The request path and query, or `None` for an unsafe identifier.
    #[must_use]
    pub fn path(&self) -> Option<String> {
        let base = "/api/v1";
        Some(match self {
            Self::Version => format!("{base}/version"),
            Self::Servers => format!("{base}/servers"),
            Self::Projects => format!("{base}/projects"),
            Self::ProjectEnvironments(uuid) => {
                format!("{base}/projects/{}/environments", safe_id(uuid)?)
            }
            Self::Applications => format!("{base}/applications"),
            Self::Services => format!("{base}/services"),
            Self::ServiceApplications(uuid) => {
                format!("{base}/services/{}/applications", safe_id(uuid)?)
            }
            Self::Databases => format!("{base}/databases"),
            Self::ActiveDeployments => format!("{base}/deployments"),
            Self::ApplicationDeployments(uuid) => format!(
                "{base}/deployments/applications/{}?skip=0&take={DEPLOYMENTS_PER_APP}",
                safe_id(uuid)?
            ),
        })
    }
}

/// Coolify UUIDs are short alphanumeric strings (CUID-like); anything else
/// is refused instead of interpolated.
fn safe_id(id: &str) -> Option<&str> {
    (!id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
    .then_some(id)
}

/// The discovery source over HTTP.
#[derive(Debug, Default)]
pub struct CoolifyHttpSource;

#[async_trait]
impl CoolifySource for CoolifyHttpSource {
    async fn discover(&self, base_url: &str, token: &SensitiveString) -> RawCoolifyDiscovery {
        discover(base_url, token.expose()).await
    }
}

pub(crate) struct Run<'a> {
    client: reqwest::Client,
    base_url: &'a str,
    token: &'a str,
    deadline: Instant,
}

fn failure(kind: FailureKind, detail: &str) -> ClassFailure {
    ClassFailure {
        kind,
        detail: detail.to_owned(),
    }
}

fn all_failed(version: Option<String>, reason: &ClassFailure) -> RawCoolifyDiscovery {
    RawCoolifyDiscovery {
        version,
        servers: ClassResult::Failed(reason.clone()),
        projects: ClassResult::Failed(reason.clone()),
        applications: ClassResult::Failed(reason.clone()),
        services: ClassResult::Failed(reason.clone()),
        databases: ClassResult::Failed(reason.clone()),
        deployments: ClassResult::Failed(reason.clone()),
    }
}

/// Runs discovery against one instance. `base_url` is the instance root
/// without a trailing slash.
pub async fn discover(base_url: &str, token: &str) -> RawCoolifyDiscovery {
    let Ok(client) = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return all_failed(
            None,
            &failure(FailureKind::Unreachable, "the HTTP client could not start"),
        );
    };
    let run = Run {
        client,
        base_url,
        token,
        deadline: Instant::now() + RUN_BUDGET,
    };
    let version = match run.get(Route::Version).await {
        Ok(Body::Text(text)) if looks_like_version(&text) => {
            text.trim().trim_matches('"').to_owned()
        }
        Ok(_) => {
            return all_failed(
                None,
                &failure(
                    FailureKind::Unreachable,
                    "the answer is not a Coolify API; check the base URL",
                ),
            );
        }
        Err(reason) => return all_failed(None, &reason),
    };
    let servers = run.list(Route::Servers, translate::server).await;
    let projects = run.projects().await;
    let applications = run.list(Route::Applications, translate::application).await;
    let services = run.services().await;
    let databases = run.list(Route::Databases, translate::database).await;
    let deployments = run.deployments(&applications).await;
    RawCoolifyDiscovery {
        version: Some(version),
        servers,
        projects,
        applications,
        services,
        databases,
        deployments,
    }
}

/// A response body: the version route answers plain text, the rest JSON.
enum Body {
    Text(String),
    Json(Value),
}

impl<'a> Run<'a> {
    pub(crate) fn new(client: reqwest::Client, base_url: &'a str, token: &'a str) -> Self {
        Self {
            client,
            base_url,
            token,
            deadline: Instant::now() + RUN_BUDGET,
        }
    }

    /// The raw body of a successful answer, for fixture capture.
    pub(crate) async fn raw(&self, route: Route<'_>) -> Result<String, ClassFailure> {
        self.fetch(route).await
    }

    async fn get(&self, route: Route<'_>) -> Result<Body, ClassFailure> {
        let text = self.fetch(route).await?;
        if matches!(route, Route::Version) {
            return Ok(Body::Text(text));
        }
        serde_json::from_str(&text).map(Body::Json).map_err(|_| {
            failure(
                FailureKind::InvalidResponse,
                "the answer is not the documented JSON",
            )
        })
    }

    async fn fetch(&self, route: Route<'_>) -> Result<String, ClassFailure> {
        let Some(path) = route.path() else {
            return Err(failure(
                FailureKind::InvalidResponse,
                "an identifier from Coolify has an unexpected shape",
            ));
        };
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(failure(
                FailureKind::Timeout,
                "the discovery time budget ran out",
            ));
        }
        let request = self
            .client
            .get(format!("{}{path}", self.base_url))
            .bearer_auth(self.token)
            .header("Accept", "application/json")
            .timeout(remaining.min(REQUEST_TIMEOUT));
        let mut response = request.send().await.map_err(|error| {
            let category = crate::transport_category(&error);
            let kind = if error.is_timeout() {
                FailureKind::Timeout
            } else {
                FailureKind::Unreachable
            };
            failure(kind, category)
        })?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            let host = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(location_host);
            let hint = redirect_hint(self.base_url);
            return Err(failure(
                FailureKind::Unreachable,
                &match host {
                    Some(host) => format!("redirected to {host}; {hint}"),
                    None => format!("redirected; {hint}"),
                },
            ));
        }
        let mut buffer = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    buffer.extend_from_slice(&chunk);
                    if buffer.len() > BODY_LIMIT {
                        return Err(failure(
                            FailureKind::InvalidResponse,
                            "the response is larger than the discovery limit",
                        ));
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let kind = if error.is_timeout() {
                        FailureKind::Timeout
                    } else {
                        FailureKind::Unreachable
                    };
                    return Err(failure(kind, "the response ended early"));
                }
            }
        }
        let text = String::from_utf8_lossy(&buffer).into_owned();
        if !(200..300).contains(&status) {
            return Err(classify_error(status, &text));
        }
        Ok(text)
    }

    async fn json(&self, route: Route<'_>) -> Result<Value, ClassFailure> {
        match self.get(route).await? {
            Body::Json(value) => Ok(value),
            Body::Text(_) => Err(failure(
                FailureKind::InvalidResponse,
                "the answer is not the documented JSON",
            )),
        }
    }

    /// A plain list class: an array of objects translated one by one.
    async fn list<T>(
        &self,
        route: Route<'_>,
        translate: impl Fn(&Value) -> Option<T>,
    ) -> ClassResult<T> {
        let value = match self.json(route).await {
            Ok(value) => value,
            Err(reason) => return ClassResult::Failed(reason),
        };
        let Some(items) = value.as_array() else {
            return ClassResult::Failed(failure(
                FailureKind::InvalidResponse,
                "the list answer is not an array",
            ));
        };
        let mut reasons = Vec::new();
        let mut translated: Vec<T> = items.iter().filter_map(&translate).collect();
        let skipped = items.len() - translated.len();
        if skipped > 0 {
            reasons.push(failure(
                FailureKind::InvalidResponse,
                &format!("{skipped} item(s) without an identity were skipped"),
            ));
        }
        if translated.len() > MAX_ITEMS_PER_CLASS {
            translated.truncate(MAX_ITEMS_PER_CLASS);
            reasons.push(failure(
                FailureKind::InvalidResponse,
                &format!("the list was cut at {MAX_ITEMS_PER_CLASS} items"),
            ));
        }
        finish(translated, reasons)
    }

    async fn projects(&self) -> ClassResult<CoolifyProject> {
        let mut projects = match self.list(Route::Projects, translate::project).await {
            ClassResult::Failed(reason) => return ClassResult::Failed(reason),
            ClassResult::Complete(items) => (items, Vec::new()),
            ClassResult::Partial(items, reasons) => (items, reasons),
        };
        let mut failures: Vec<FailureKind> = Vec::new();
        let mut skipped = 0;
        for (index, project) in projects.0.iter_mut().enumerate() {
            if index >= MAX_PROJECTS {
                skipped += 1;
                continue;
            }
            match self.json(Route::ProjectEnvironments(&project.uuid)).await {
                Ok(Value::Array(items)) => {
                    project.environments =
                        items.iter().filter_map(translate::environment).collect();
                }
                Ok(_) => failures.push(FailureKind::InvalidResponse),
                Err(reason) => failures.push(reason.kind),
            }
        }
        if !failures.is_empty() {
            projects.1.push(failure(
                failures[0],
                &format!(
                    "environments of {} project(s) could not be listed",
                    failures.len()
                ),
            ));
        }
        if skipped > 0 {
            projects.1.push(failure(
                FailureKind::InvalidResponse,
                &format!(
                    "environments of {skipped} project(s) were not requested (limit {MAX_PROJECTS})"
                ),
            ));
        }
        finish(projects.0, projects.1)
    }

    async fn services(&self) -> ClassResult<CoolifyService> {
        let (mut services, mut reasons) = match self.list(Route::Services, translate::service).await
        {
            ClassResult::Failed(reason) => return ClassResult::Failed(reason),
            ClassResult::Complete(items) => (items, Vec::new()),
            ClassResult::Partial(items, reasons) => (items, reasons),
        };
        let mut failed = Vec::new();
        let mut skipped = 0;
        for (index, service) in services.iter_mut().enumerate() {
            if index >= MAX_SERVICE_LOOKUPS {
                skipped += 1;
                continue;
            }
            match self.json(Route::ServiceApplications(&service.uuid)).await {
                Ok(value) => service.fqdns = translate::service_fqdns(&value),
                Err(reason) => failed.push(reason.kind),
            }
        }
        if !failed.is_empty() {
            reasons.push(failure(
                failed[0],
                &format!(
                    "hostnames of {} service(s) could not be listed",
                    failed.len()
                ),
            ));
        }
        if skipped > 0 {
            reasons.push(failure(
                FailureKind::InvalidResponse,
                &format!("hostnames of {skipped} service(s) were not requested (limit {MAX_SERVICE_LOOKUPS})"),
            ));
        }
        finish(services, reasons)
    }

    /// Queued and in-progress deployments, then the latest few per
    /// application, newest first.
    async fn deployments(
        &self,
        applications: &ClassResult<CoolifyApplication>,
    ) -> ClassResult<CoolifyDeployment> {
        let mut reasons = Vec::new();
        let mut all: Vec<CoolifyDeployment> = Vec::new();
        let mut any_ok = false;
        match self
            .list(Route::ActiveDeployments, |v| translate::deployment(v, None))
            .await
        {
            ClassResult::Complete(items) => {
                any_ok = true;
                all.extend(items);
            }
            ClassResult::Partial(items, more) => {
                any_ok = true;
                all.extend(items);
                reasons.extend(more);
            }
            ClassResult::Failed(reason) => reasons.push(reason),
        }
        let apps: &[CoolifyApplication] = match applications {
            ClassResult::Complete(items) | ClassResult::Partial(items, _) => items,
            ClassResult::Failed(_) => {
                reasons.push(failure(
                    FailureKind::InvalidResponse,
                    "applications were unavailable; only active deployments are listed",
                ));
                &[]
            }
        };
        let mut app_failures = Vec::new();
        for app in apps.iter().take(MAX_DEPLOYMENT_APPS) {
            match self.json(Route::ApplicationDeployments(&app.uuid)).await {
                Ok(value) => {
                    any_ok = true;
                    let items = value
                        .get("deployments")
                        .unwrap_or(&value)
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    all.extend(
                        items
                            .iter()
                            .filter_map(|item| translate::deployment(item, Some(&app.uuid))),
                    );
                }
                Err(reason) => app_failures.push(reason.kind),
            }
        }
        if let Some(first) = app_failures.first() {
            reasons.push(failure(
                *first,
                &format!(
                    "deployments of {} application(s) could not be listed",
                    app_failures.len()
                ),
            ));
        }
        if apps.len() > MAX_DEPLOYMENT_APPS {
            reasons.push(failure(
                FailureKind::InvalidResponse,
                &format!(
                    "deployments of {} application(s) were not requested (limit {MAX_DEPLOYMENT_APPS})",
                    apps.len() - MAX_DEPLOYMENT_APPS
                ),
            ));
        }
        if !any_ok {
            return ClassResult::Failed(reasons.into_iter().next().unwrap_or_else(|| {
                failure(FailureKind::InvalidResponse, "no deployment list answered")
            }));
        }
        merge_deployments(&mut all);
        all.truncate(MAX_ITEMS_PER_CLASS);
        finish(all, reasons)
    }
}

/// One entry per deployment uuid (the per-application listing knows the
/// application uuid, the active listing does not), newest first.
fn merge_deployments(all: &mut Vec<CoolifyDeployment>) {
    let mut merged: Vec<CoolifyDeployment> = Vec::new();
    for item in all.drain(..) {
        match merged
            .iter_mut()
            .find(|seen| seen.deployment_uuid == item.deployment_uuid)
        {
            Some(seen) => {
                // The per-application listing is the richer record.
                if seen.application_uuid.is_none() && item.application_uuid.is_some() {
                    *seen = item;
                }
            }
            None => merged.push(item),
        }
    }
    merged.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    *all = merged;
}

fn finish<T>(items: Vec<T>, reasons: Vec<ClassFailure>) -> ClassResult<T> {
    if reasons.is_empty() {
        ClassResult::Complete(items)
    } else {
        ClassResult::Partial(items, reasons)
    }
}

/// Classifies a non-2xx answer without echoing the body.
fn classify_error(status: u16, body: &str) -> ClassFailure {
    match status {
        401 => failure(
            FailureKind::Unauthorized,
            "the token was refused (HTTP 401)",
        ),
        403 if message_of(body)
            .to_ascii_lowercase()
            .contains("missing required permissions") =>
        {
            failure(
                FailureKind::InsufficientPermission,
                "the token lacks the read ability",
            )
        }
        403 => failure(
            FailureKind::Unauthorized,
            &format!("the request was refused (HTTP 403): {}", message_of(body)),
        ),
        404 => failure(
            FailureKind::NotFound,
            "the route does not exist on this Coolify instance",
        ),
        other => failure(
            FailureKind::InvalidResponse,
            &format!("unexpected HTTP status {other}"),
        ),
    }
}
