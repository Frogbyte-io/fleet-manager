//! Read discovery over Coolify's REST API (FM-1030).
//!
//! The client is GET-only and addresses a closed set of [`Route`]s, so no
//! caller can reach `/enable`, `/deploy`, `/start`, `/restart`, an `/envs`
//! route, or any other path: a route is a variant, and the only
//! interpolated parts are Coolify UUIDs checked against a strict character
//! set. It never asks for `read:sensitive` values (Coolify decides that
//! from the token; the [`crate::translate`] allow-list drops them anyway,
//! and a run warns when it sees that the token can read them). Redirects
//! are not followed, because following one could carry the bearer token to
//! another origin.
//!
//! # Bounds
//!
//! [`Limits`]: a timeout per request, a time budget for the run, a byte
//! bound per response, and a request budget. Coolify rate-limits an API
//! user to 200 requests per minute by default, so the budget is 120. The
//! first HTTP 429 stops every later request (the classes report
//! `rate_limited`, with Coolify's `Retry-After` in the detail); the run
//! never sleeps to wait it out. Coolify's list endpoints are not paginated
//! (only the per-application deployment list takes `skip` and `take`), so
//! the bound is the item cap.
//!
//! # Order
//!
//! All top-level lists are fetched first (servers, projects, applications,
//! services, databases, active deployments), then the follow-ups
//! (environments per project, hostnames per service, recent deployments
//! per application). A follow-up route that answers 404 once (for example
//! `/services/{uuid}/applications` before Coolify v4.2.0) is not requested
//! again in the run.
//!
//! Each resource class reports for itself: a class that fails does not stop
//! the others, except that a failed `/version` (unreachable, refused, or
//! not Coolify) fails every class with the same reason without sending the
//! rest of the requests.

use std::collections::HashSet;
use std::sync::Mutex;
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
/// The most requests one run sends (Coolify's default limit is 200 per
/// minute per user).
pub const MAX_REQUESTS: u32 = 120;
/// The most projects whose environments are fetched.
pub const MAX_PROJECTS: usize = 200;
/// The most services whose applications (hostnames) are fetched.
pub const MAX_SERVICE_LOOKUPS: usize = 100;
/// The most applications whose recent deployments are fetched.
pub const MAX_DEPLOYMENT_APPS: usize = 50;
/// How many deployments are taken per application.
pub const DEPLOYMENTS_PER_APP: u32 = 5;
/// The longest `Retry-After` reported, in seconds.
const MAX_RETRY_AFTER: u64 = 3600;
/// The warning recorded when the token can read sensitive values.
pub const SENSITIVE_TOKEN_WARNING: &str = "the answers carried fields a read-only token should not receive (for example deployment logs or database passwords); Fleet drops them at the boundary, but use a read-only token";

/// The bounds of one run; [`Limits::default`] is what production uses.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The timeout of one request.
    pub request_timeout: Duration,
    /// The time budget of the whole run.
    pub run_budget: Duration,
    /// The most bytes read per response.
    pub body_limit: usize,
    /// The most requests sent.
    pub max_requests: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_timeout: REQUEST_TIMEOUT,
            run_budget: RUN_BUDGET,
            body_limit: BODY_LIMIT,
            max_requests: MAX_REQUESTS,
        }
    }
}

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

    /// The route family, shared by every identifier (for the not-found
    /// memory of a run).
    fn kind(&self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Servers => "servers",
            Self::Projects => "projects",
            Self::ProjectEnvironments(_) => "project_environments",
            Self::Applications => "applications",
            Self::Services => "services",
            Self::ServiceApplications(_) => "service_applications",
            Self::Databases => "databases",
            Self::ActiveDeployments => "deployments",
            Self::ApplicationDeployments(_) => "application_deployments",
        }
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

#[derive(Default)]
struct State {
    requests: u32,
    /// Set by the first HTTP 429: the `Retry-After` seconds (0 when absent).
    limited: Option<u64>,
    /// Route families that answered 404 once.
    missing: HashSet<&'static str>,
    /// Whether a response carried sensitive-only fields.
    sensitive: bool,
}

pub(crate) struct Run<'a> {
    client: reqwest::Client,
    base_url: &'a str,
    token: &'a str,
    deadline: Instant,
    limits: Limits,
    state: Mutex<State>,
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
        warnings: Vec::new(),
    }
}

/// Runs discovery against one instance with the default [`Limits`].
/// `base_url` is the instance root without a trailing slash.
pub async fn discover(base_url: &str, token: &str) -> RawCoolifyDiscovery {
    discover_with(base_url, token, Limits::default()).await
}

/// Runs discovery with explicit limits.
pub async fn discover_with(base_url: &str, token: &str, limits: Limits) -> RawCoolifyDiscovery {
    let Ok(client) = reqwest::Client::builder()
        .timeout(limits.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return all_failed(
            None,
            &failure(FailureKind::Unreachable, "the HTTP client could not start"),
        );
    };
    let run = Run::new(client, base_url, token, limits);
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
    // Every top-level list first, then the follow-ups.
    let servers = run.list(Route::Servers, translate::server).await;
    let projects = run.list(Route::Projects, translate::project).await;
    let applications = run.list(Route::Applications, translate::application).await;
    let services = run.list(Route::Services, translate::service).await;
    let databases = run.list(Route::Databases, translate::database).await;
    let active = run
        .list(Route::ActiveDeployments, |v| translate::deployment(v, None))
        .await;
    let projects = run.project_environments(projects).await;
    let services = run.service_hostnames(services).await;
    let deployments = run.deployments(active, &applications).await;
    let warnings = if run.state().sensitive {
        vec![SENSITIVE_TOKEN_WARNING.to_owned()]
    } else {
        Vec::new()
    };
    RawCoolifyDiscovery {
        version: Some(version),
        servers,
        projects,
        applications,
        services,
        databases,
        deployments,
        warnings,
    }
}

/// A response body: the version route answers plain text, the rest JSON.
enum Body {
    Text(String),
    Json(Value),
}

use translate::items_of;

/// The deployments of a per-application answer: the `deployments` member of
/// the `{count, deployments}` wrapper, or the answer itself.
fn deployment_items(value: &Value) -> Option<Vec<&Value>> {
    value
        .get("deployments")
        .map_or_else(|| items_of(value), items_of)
}

impl<'a> Run<'a> {
    pub(crate) fn new(
        client: reqwest::Client,
        base_url: &'a str,
        token: &'a str,
        limits: Limits,
    ) -> Self {
        Self {
            client,
            base_url,
            token,
            deadline: Instant::now() + limits.run_budget,
            limits,
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        {
            let mut state = self.state();
            if let Some(after) = state.limited {
                return Err(rate_limited(after));
            }
            if state.missing.contains(route.kind()) {
                return Err(not_found());
            }
            if state.requests >= self.limits.max_requests {
                return Err(failure(
                    FailureKind::RateLimited,
                    "the run's request budget was reached; the rest is skipped to stay under Coolify's rate limit",
                ));
            }
            state.requests += 1;
        }
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
            .timeout(remaining.min(self.limits.request_timeout));
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
        if status == 429 {
            let after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map_or(0, |seconds| seconds.min(MAX_RETRY_AFTER));
            self.state().limited = Some(after);
            return Err(rate_limited(after));
        }
        let buffer = self.read_body(&mut response).await?;
        let text = String::from_utf8_lossy(&buffer).into_owned();
        if !(200..300).contains(&status) {
            let error = classify_error(status, &text);
            // Only the router's catch-all 404 means the route family does
            // not exist; "Project not found." is about one resource.
            if error.kind == FailureKind::NotFound && is_catch_all_not_found(&text) {
                self.state().missing.insert(route.kind());
            }
            return Err(error);
        }
        Ok(text)
    }

    /// Reads a body up to the limit.
    async fn read_body(&self, response: &mut reqwest::Response) -> Result<Vec<u8>, ClassFailure> {
        let mut buffer = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    buffer.extend_from_slice(&chunk);
                    if buffer.len() > self.limits.body_limit {
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
        Ok(buffer)
    }

    async fn json(&self, route: Route<'_>) -> Result<Value, ClassFailure> {
        match self.get(route).await? {
            Body::Json(value) => {
                self.scan_for_sensitive(route, &value);
                Ok(value)
            }
            Body::Text(_) => Err(failure(
                FailureKind::InvalidResponse,
                "the answer is not the documented JSON",
            )),
        }
    }

    /// Notes whether the answer carries fields Coolify only returns to a
    /// `read:sensitive` token (deployment logs, database passwords and
    /// connection URLs).
    fn scan_for_sensitive(&self, route: Route<'_>, value: &Value) {
        let items = deployment_items(value)
            .or_else(|| items_of(value))
            .unwrap_or_default();
        let sensitive = match route {
            Route::ActiveDeployments | Route::ApplicationDeployments(_) => {
                items.iter().any(|item| item.get("logs").is_some())
            }
            Route::Databases => items.iter().any(|item| {
                item.as_object().is_some_and(|map| {
                    map.keys().any(|key| {
                        key.ends_with("_password")
                            || matches!(
                                key.as_str(),
                                "internal_db_url" | "external_db_url" | "init_scripts"
                            )
                    })
                })
            }),
            _ => false,
        };
        if sensitive {
            self.state().sensitive = true;
        }
    }

    /// A plain list class: the items translated one by one.
    async fn list<T>(
        &self,
        route: Route<'_>,
        translate: impl Fn(&Value) -> Option<T>,
    ) -> ClassResult<T> {
        let value = match self.json(route).await {
            Ok(value) => value,
            Err(reason) => return ClassResult::Failed(reason),
        };
        let Some(items) = items_of(&value) else {
            return ClassResult::Failed(failure(
                FailureKind::InvalidResponse,
                "the list answer is not an array",
            ));
        };
        let mut reasons = Vec::new();
        let mut translated: Vec<T> = items.iter().copied().filter_map(&translate).collect();
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

    async fn project_environments(
        &self,
        base: ClassResult<CoolifyProject>,
    ) -> ClassResult<CoolifyProject> {
        let (mut projects, mut reasons) = match base {
            ClassResult::Failed(reason) => return ClassResult::Failed(reason),
            ClassResult::Complete(items) => (items, Vec::new()),
            ClassResult::Partial(items, reasons) => (items, reasons),
        };
        let mut failed: Vec<FailureKind> = Vec::new();
        let mut skipped = 0;
        for (index, project) in projects.iter_mut().enumerate() {
            if index >= MAX_PROJECTS {
                project.details_stale = true;
                skipped += 1;
                continue;
            }
            match self.json(Route::ProjectEnvironments(&project.uuid)).await {
                Ok(value) => {
                    if let Some(items) = items_of(&value) {
                        project.environments = items
                            .into_iter()
                            .filter_map(translate::environment)
                            .collect();
                    } else {
                        project.details_stale = true;
                        failed.push(FailureKind::InvalidResponse);
                    }
                }
                Err(reason) => {
                    project.details_stale = true;
                    failed.push(reason.kind);
                }
            }
        }
        if let Some(first) = failed.first() {
            reasons.push(failure(
                *first,
                &format!(
                    "environments of {} project(s) could not be listed",
                    failed.len()
                ),
            ));
        }
        if skipped > 0 {
            reasons.push(failure(
                FailureKind::InvalidResponse,
                &format!(
                    "environments of {skipped} project(s) were not requested (limit {MAX_PROJECTS})"
                ),
            ));
        }
        finish(projects, reasons)
    }

    async fn service_hostnames(
        &self,
        base: ClassResult<CoolifyService>,
    ) -> ClassResult<CoolifyService> {
        let (mut services, mut reasons) = match base {
            ClassResult::Failed(reason) => return ClassResult::Failed(reason),
            ClassResult::Complete(items) => (items, Vec::new()),
            ClassResult::Partial(items, reasons) => (items, reasons),
        };
        let mut failed = Vec::new();
        let mut skipped = 0;
        for (index, service) in services.iter_mut().enumerate() {
            if index >= MAX_SERVICE_LOOKUPS {
                service.details_stale = true;
                skipped += 1;
                continue;
            }
            match self.json(Route::ServiceApplications(&service.uuid)).await {
                Ok(value) => {
                    if let Some(fqdns) = translate::service_fqdns(&value) {
                        service.fqdns = fqdns;
                    } else {
                        service.details_stale = true;
                        failed.push(FailureKind::InvalidResponse);
                    }
                }
                Err(reason) => {
                    service.details_stale = true;
                    failed.push(reason.kind);
                }
            }
        }
        if let Some(first) = failed.first() {
            reasons.push(failure(
                *first,
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

    /// Queued and in-progress deployments (already listed), then the latest
    /// few per application, newest first.
    async fn deployments(
        &self,
        active: ClassResult<CoolifyDeployment>,
        applications: &ClassResult<CoolifyApplication>,
    ) -> ClassResult<CoolifyDeployment> {
        let mut reasons = Vec::new();
        let mut all: Vec<CoolifyDeployment> = Vec::new();
        let mut any_ok = false;
        match active {
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
                    if let Some(items) = deployment_items(&value) {
                        any_ok = true;
                        all.extend(
                            items
                                .into_iter()
                                .filter_map(|item| translate::deployment(item, Some(&app.uuid))),
                        );
                    } else {
                        app_failures.push(FailureKind::InvalidResponse);
                    }
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

/// Whether a 404 body is Laravel's route catch-all (`{"message":"Not
/// found."}`), as opposed to a resource-specific message.
fn is_catch_all_not_found(body: &str) -> bool {
    message_of(body)
        .trim()
        .trim_end_matches('.')
        .eq_ignore_ascii_case("not found")
}

fn rate_limited(after: u64) -> ClassFailure {
    failure(
        FailureKind::RateLimited,
        &if after > 0 {
            format!("Coolify rate-limited the run (HTTP 429); retry after {after}s")
        } else {
            "Coolify rate-limited the run (HTTP 429); retry later".to_owned()
        },
    )
}

fn not_found() -> ClassFailure {
    failure(
        FailureKind::NotFound,
        "the route does not exist on this Coolify instance",
    )
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

/// Classifies a non-2xx answer without echoing the body. Any text taken
/// from the answer passes the shared scrubber.
fn classify_error(status: u16, body: &str) -> ClassFailure {
    let message = message_of(body);
    match status {
        401 => failure(
            FailureKind::Unauthorized,
            "the token was refused (HTTP 401)",
        ),
        // Coolify answers an unknown token with 400 "Invalid token.".
        400 if message.to_ascii_lowercase().contains("invalid token") => failure(
            FailureKind::Unauthorized,
            "the token was refused (HTTP 400 invalid token)",
        ),
        403 if message
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
            &format!("the request was refused (HTTP 403): {message}"),
        ),
        404 => not_found(),
        other => failure(
            FailureKind::InvalidResponse,
            &format!("unexpected HTTP status {other}"),
        ),
    }
}
