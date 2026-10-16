//! The Cloudflare API v4 client for zones and DNS records (FM-1042).
//!
//! Primary sources:
//! <https://developers.cloudflare.com/api/resources/zones/methods/list/> and
//! <https://developers.cloudflare.com/api/resources/dns/subresources/records/>
//! (list, create, update with `PUT`, delete). Every answer is the envelope
//! `{ success, errors: [{ code, message }], result, result_info }`.
//!
//! # Behaviour
//!
//! - The token is a bearer header and appears in no returned value.
//! - Redirects are never followed; each response is read up to a bound.
//! - Lists are paginated through `result_info.total_pages` and refused past
//!   [`MAX_PAGES`] rather than silently truncated.
//! - Cloudflare limits an account to 1200 requests per five minutes and
//!   answers `429` with `Retry-After`. A `429` is retried at most
//!   [`MAX_RATE_LIMIT_RETRIES`] times, waiting the advertised time up to
//!   [`MAX_RETRY_WAIT`]; a longer wait, or running out of retries, is
//!   reported as `rate_limited` and the caller decides. A `429` means the
//!   request was not processed, so retrying a write is safe.
//! - Failures are classified (see [`ErrorClass`]) from the HTTP status and,
//!   for `400`, the documented DNS error codes.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

/// How long one request may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// The most response bytes read for one page.
const BODY_BOUND: usize = 4 * 1024 * 1024;
/// The most pages read for one list.
pub const MAX_PAGES: u32 = 50;
/// How many times a `429` is retried.
pub const MAX_RATE_LIMIT_RETRIES: u32 = 2;
/// The longest `Retry-After` the client waits out.
pub const MAX_RETRY_WAIT: Duration = Duration::from_secs(30);
/// The most characters of a Cloudflare error message kept in a detail.
const MESSAGE_BOUND: usize = 200;

/// What a failure means.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorClass {
    /// The token was refused (`401`).
    Auth,
    /// The token is valid but not allowed (`403`).
    Permission,
    /// The zone or record does not exist (`404`).
    NotFound,
    /// A duplicate record, or a CNAME beside other records (`409`, or the
    /// documented `400` codes).
    Conflict,
    /// Rate limited and out of retries (`429`).
    RateLimited,
    /// Cloudflare refused the value (`400` and the rest of `4xx`).
    Invalid,
    /// Unreachable, a TLS failure, a `5xx`, or an answer that is not
    /// Cloudflare's.
    Unavailable,
}

/// A classified failure. The detail is safe to print.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiError {
    /// What kind of failure.
    pub class: ErrorClass,
    /// What happened.
    pub detail: String,
}

impl ApiError {
    fn new(class: ErrorClass, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: detail.into(),
        }
    }
}

/// A zone as Cloudflare reports it.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct Zone {
    /// The zone id.
    pub id: String,
    /// The apex name.
    pub name: String,
    /// `active`, `pending`, `initializing`, `moved`.
    #[serde(default)]
    pub status: String,
}

/// A DNS record as Cloudflare reports it.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct Record {
    /// The record id.
    pub id: String,
    /// The type.
    #[serde(rename = "type")]
    pub record_type: String,
    /// The fully qualified name.
    pub name: String,
    /// The value.
    #[serde(default)]
    pub content: String,
    /// The TTL; `1` is automatic.
    #[serde(default)]
    pub ttl: u32,
    /// Whether traffic is proxied.
    #[serde(default)]
    pub proxied: Option<bool>,
    /// The MX preference.
    #[serde(default)]
    pub priority: Option<u16>,
}

/// The values a create or update sends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordInput {
    /// The type.
    pub record_type: String,
    /// The fully qualified name.
    pub name: String,
    /// The value.
    pub content: String,
    /// The TTL; `1` is automatic.
    pub ttl: u32,
    /// Proxy through Cloudflare (A, AAAA, CNAME only).
    pub proxied: bool,
    /// The MX preference.
    pub priority: Option<u16>,
}

impl RecordInput {
    fn body(&self) -> Value {
        let mut body = json!({
            "type": self.record_type,
            "name": self.name,
            "content": self.content,
            "ttl": self.ttl,
        });
        if matches!(self.record_type.as_str(), "A" | "AAAA" | "CNAME") {
            body["proxied"] = json!(self.proxied);
        }
        if let Some(priority) = self.priority {
            body["priority"] = json!(priority);
        }
        body
    }
}

#[derive(Deserialize)]
struct ApiMessage {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct ResultInfo {
    #[serde(default)]
    total_pages: Option<u32>,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiMessage>,
    #[serde(default)]
    result: Value,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

/// The client for one account's token.
#[derive(Debug)]
pub struct CloudflareClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
    retry_wait_cap: Duration,
}

type Query = Vec<(&'static str, String)>;

impl CloudflareClient {
    /// A client for `base_url` (no trailing slash needed) and `token`.
    ///
    /// # Errors
    ///
    /// Fails when the HTTP client cannot start.
    pub fn new(base_url: &str, token: &str) -> Result<Self, ApiError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| {
                ApiError::new(ErrorClass::Unavailable, "the HTTP client could not start")
            })?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
            retry_wait_cap: MAX_RETRY_WAIT,
        })
    }

    /// Lowers the longest `Retry-After` the client waits out. For tests.
    #[must_use]
    pub fn with_retry_wait_cap(mut self, cap: Duration) -> Self {
        self.retry_wait_cap = cap;
        self
    }

    /// Lists the zones the token can see, optionally only the one named
    /// `name`. Every page is read.
    ///
    /// # Errors
    ///
    /// Fails with a classified error.
    pub async fn list_zones(&self, name: Option<&str>) -> Result<Vec<Zone>, ApiError> {
        let mut query: Query = vec![("per_page", "50".to_owned())];
        if let Some(name) = name {
            query.push(("name", name.to_owned()));
        }
        self.paginate("/zones", query).await
    }

    /// Lists a zone's records, optionally of one name and type. Every page is
    /// read.
    ///
    /// # Errors
    ///
    /// Fails with a classified error.
    pub async fn list_records(
        &self,
        zone_id: &str,
        name: Option<&str>,
        record_type: Option<&str>,
    ) -> Result<Vec<Record>, ApiError> {
        let mut query: Query = vec![("per_page", "100".to_owned())];
        if let Some(name) = name {
            query.push(("name", name.to_owned()));
        }
        if let Some(record_type) = record_type {
            query.push(("type", record_type.to_owned()));
        }
        self.paginate(&format!("/zones/{}/dns_records", segment(zone_id)?), query)
            .await
    }

    /// Creates a record.
    ///
    /// # Errors
    ///
    /// Fails with a classified error.
    pub async fn create_record(
        &self,
        zone_id: &str,
        input: &RecordInput,
    ) -> Result<Record, ApiError> {
        let result = self
            .call(
                reqwest::Method::POST,
                &format!("/zones/{}/dns_records", segment(zone_id)?),
                &[],
                Some(input.body()),
            )
            .await?;
        record_of(result)
    }

    /// Replaces a record (`PUT`).
    ///
    /// # Errors
    ///
    /// Fails with a classified error.
    pub async fn update_record(
        &self,
        zone_id: &str,
        record_id: &str,
        input: &RecordInput,
    ) -> Result<Record, ApiError> {
        let result = self
            .call(
                reqwest::Method::PUT,
                &format!(
                    "/zones/{}/dns_records/{}",
                    segment(zone_id)?,
                    segment(record_id)?
                ),
                &[],
                Some(input.body()),
            )
            .await?;
        record_of(result)
    }

    /// Deletes a record.
    ///
    /// # Errors
    ///
    /// Fails with a classified error.
    pub async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<(), ApiError> {
        self.call(
            reqwest::Method::DELETE,
            &format!(
                "/zones/{}/dns_records/{}",
                segment(zone_id)?,
                segment(record_id)?
            ),
            &[],
            None,
        )
        .await
        .map(|_| ())
    }

    async fn paginate<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        base_query: Query,
    ) -> Result<Vec<T>, ApiError> {
        let mut out = Vec::new();
        let mut page = 1_u32;
        loop {
            let mut query = base_query.clone();
            query.push(("page", page.to_string()));
            let envelope = self
                .call_envelope(reqwest::Method::GET, path, &query, None)
                .await?;
            let Value::Array(items) = envelope.result else {
                return Err(ApiError::new(
                    ErrorClass::Unavailable,
                    "the answer was not a list; check the base URL",
                ));
            };
            let empty = items.is_empty();
            for item in items {
                out.push(serde_json::from_value(item).map_err(|_| {
                    ApiError::new(
                        ErrorClass::Unavailable,
                        "an entry in the list was not in Cloudflare's documented shape",
                    )
                })?);
            }
            let total = envelope
                .result_info
                .and_then(|info| info.total_pages)
                .unwrap_or(1);
            if total > MAX_PAGES {
                return Err(ApiError::new(
                    ErrorClass::Invalid,
                    format!("more than {MAX_PAGES} pages; narrow the query"),
                ));
            }
            if page >= total || empty {
                return Ok(out);
            }
            page += 1;
        }
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&'static str, String)],
        body: Option<Value>,
    ) -> Result<Value, ApiError> {
        self.call_envelope(method, path, query, body)
            .await
            .map(|envelope| envelope.result)
    }

    async fn call_envelope(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&'static str, String)],
        body: Option<Value>,
    ) -> Result<Envelope, ApiError> {
        let mut attempt = 0;
        loop {
            let mut request = self
                .http
                .request(method.clone(), format!("{}{path}", self.base_url))
                .bearer_auth(&self.token)
                .header("Accept", "application/json")
                .query(query);
            if let Some(body) = &body {
                request = request
                    .header("Content-Type", "application/json")
                    .body(body.to_string());
            }
            let mut response = request.send().await.map_err(|error| {
                ApiError::new(ErrorClass::Unavailable, crate::transport_category(&error))
            })?;
            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok());
            let mut bytes = Vec::new();
            while bytes.len() < BODY_BOUND {
                match response.chunk().await {
                    Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
                    _ => break,
                }
            }
            if status == 429 {
                let wait = Duration::from_secs(retry_after.unwrap_or(1));
                if attempt >= MAX_RATE_LIMIT_RETRIES || wait > self.retry_wait_cap {
                    return Err(ApiError::new(
                        ErrorClass::RateLimited,
                        format!(
                            "Cloudflare's rate limit applies (HTTP 429, retry after {} s); try again later",
                            retry_after.unwrap_or(1)
                        ),
                    ));
                }
                attempt += 1;
                tokio::time::sleep(wait).await;
                continue;
            }
            return classify(status, &bytes);
        }
    }
}

/// A path segment must be a plain id: letters, digits, `-` and `_` only, so
/// an id can never add a path segment or a query.
fn segment(id: &str) -> Result<&str, ApiError> {
    if !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(id)
    } else {
        Err(ApiError::new(
            ErrorClass::Invalid,
            "an id is not a Cloudflare id",
        ))
    }
}

fn record_of(result: Value) -> Result<Record, ApiError> {
    serde_json::from_value(result).map_err(|_| {
        ApiError::new(
            ErrorClass::Unavailable,
            "the record was not in Cloudflare's documented shape",
        )
    })
}

/// Cloudflare DNS error codes that mean the record conflicts with one that
/// exists (an identical record, or a name that cannot hold another).
const CONFLICT_CODES: [i64; 4] = [81053, 81054, 81057, 81058];
/// The code for a record that does not exist.
const RECORD_NOT_FOUND_CODE: i64 = 81044;

fn first_error(envelope: Option<&Envelope>) -> (Option<i64>, String) {
    envelope
        .and_then(|envelope| envelope.errors.first())
        .map_or((None, String::new()), |error| {
            let message: String = fleet_core::flatten_control_characters(&error.message)
                .chars()
                .take(MESSAGE_BOUND)
                .collect();
            (error.code, message)
        })
}

fn classify(status: u16, body: &[u8]) -> Result<Envelope, ApiError> {
    let envelope: Option<Envelope> = serde_json::from_slice(body).ok();
    let (code, message) = first_error(envelope.as_ref());
    let described = |lead: &str| {
        let code = code.map_or_else(String::new, |code| format!(" code {code}"));
        fleet_core::scrub_failure_detail(format!("{lead}{code} {message}").trim())
    };
    match status {
        200..=299 => match envelope {
            Some(envelope) if envelope.success => Ok(envelope),
            Some(_) => Err(ApiError::new(
                ErrorClass::Invalid,
                described("Cloudflare reported failure:"),
            )),
            None => Err(ApiError::new(
                ErrorClass::Unavailable,
                "the answer was not Cloudflare's; check the base URL",
            )),
        },
        401 => Err(ApiError::new(
            ErrorClass::Auth,
            described("the token was refused (HTTP 401)"),
        )),
        403 => Err(ApiError::new(
            ErrorClass::Permission,
            described(
                "the token may not do this (HTTP 403); it needs Zone:Read and DNS:Edit on the zone",
            ),
        )),
        404 => Err(ApiError::new(
            ErrorClass::NotFound,
            described("not found (HTTP 404)"),
        )),
        409 => Err(ApiError::new(
            ErrorClass::Conflict,
            described("conflict (HTTP 409)"),
        )),
        400..=499 => {
            let class = match code {
                Some(code) if CONFLICT_CODES.contains(&code) => ErrorClass::Conflict,
                Some(RECORD_NOT_FOUND_CODE) => ErrorClass::NotFound,
                _ => ErrorClass::Invalid,
            };
            Err(ApiError::new(
                class,
                described(&format!("Cloudflare refused the request (HTTP {status})")),
            ))
        }
        500..=599 => Err(ApiError::new(
            ErrorClass::Unavailable,
            described(&format!("Cloudflare failed (HTTP {status})")),
        )),
        other => Err(ApiError::new(
            ErrorClass::Unavailable,
            format!("unexpected HTTP status {other}"),
        )),
    }
}
