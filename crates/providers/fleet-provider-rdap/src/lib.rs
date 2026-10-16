//! The RDAP provider (FM-1020): public registration data for a domain,
//! without any registrar credential.
//!
//! Primary sources:
//!
//! * RFC 9224 (and RFC 7484 before it): the IANA bootstrap registry at
//!   <https://data.iana.org/rdap/dns.json> maps a TLD to the base URLs of
//!   the RDAP servers that answer for it. A TLD with no entry has no RDAP
//!   service; that is a normal answer ([`Lookup::Unavailable`]), not an
//!   error.
//! * RFC 9082: a domain query is `GET <base>/domain/<ldh-name>` with
//!   `Accept: application/rdap+json`.
//! * RFC 9083: the registrar is the entity whose `roles` include
//!   `registrar`, named by the `fn` property of its jCard (RFC 7095); the
//!   expiry is the event whose `eventAction` is `expiration`; `status` is
//!   an array of strings; `nameservers` hold `ldhName`s.
//!
//! Only those fields are read. Everything else a server returns (contact
//! entities, notices, links) is ignored and never stored, so personal data
//! in a response does not reach Fleet.
//!
//! A lookup is for a registrable domain (`example.com`, `example.co.uk`),
//! which is what Registry `domain` entries hold. RDAP servers answer for
//! the registrable name, not for `www.example.com`; the provider sends the
//! name it is given and does not reduce subdomains (that needs the public
//! suffix list, which Fleet does not carry). A subdomain is reported by the
//! registry as not found.
//!
//! When a TLD lists several RDAP servers and the first fails (transport
//! error or HTTP 5xx), the others are tried. Those fallback hosts, and any
//! host a server redirects to, are not covered by the caller's per-server
//! rate limiter, which keys on the first server only.
//!
//! The network sits behind [`RdapTransport`] so tests replay recorded
//! fixtures. The bootstrap file is cached with a TTL and a stale copy is
//! served when a refresh fails.
#![warn(missing_docs)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

/// The IANA DNS bootstrap file.
pub const IANA_BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";
/// How long a fetched bootstrap file is trusted before the next refresh.
pub const BOOTSTRAP_TTL: Duration = Duration::from_hours(24);
/// How long one request may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// The most response bytes read from one answer.
pub const BODY_BOUND: usize = 2 * 1024 * 1024;

/// One HTTP answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// The (bounded) body.
    pub body: Vec<u8>,
}

/// The HTTP port: one GET, no credentials.
#[async_trait::async_trait]
pub trait RdapTransport: std::fmt::Debug + Send + Sync {
    /// Fetches `url`. A transport failure is a short, credential-free
    /// category.
    ///
    /// # Errors
    ///
    /// Fails when the request could not complete.
    async fn get(&self, url: &str) -> Result<HttpResponse, String>;
}

/// The production transport: HTTPS only, bounded body and redirects.
#[derive(Debug)]
pub struct ReqwestRdapTransport {
    client: reqwest::Client,
}

impl ReqwestRdapTransport {
    /// Builds the client.
    ///
    /// # Errors
    ///
    /// Fails when the HTTP client cannot start.
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent("fleet-controller (registry domain observations)")
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 3 {
                    attempt.error("too many redirects")
                } else if attempt.url().scheme() != "https" {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .https_only(true)
            .build()
            .map_err(|_| "the HTTP client could not start".to_owned())?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl RdapTransport for ReqwestRdapTransport {
    async fn get(&self, url: &str) -> Result<HttpResponse, String> {
        let mut response = self
            .client
            .get(url)
            .header("Accept", "application/rdap+json, application/json")
            .send()
            .await
            .map_err(|error| transport_category(&error))?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        while body.len() < BODY_BOUND {
            match response.chunk().await {
                Ok(Some(chunk)) => body.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(error) => return Err(transport_category(&error)),
            }
        }
        body.truncate(BODY_BOUND);
        Ok(HttpResponse { status, body })
    }
}

/// A fixed category for a transport failure; never the URL or the error
/// text, which can carry the request target.
fn transport_category(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "the request timed out"
    } else if error.is_connect() {
        "the server could not be reached"
    } else if error.is_redirect() {
        "the server redirected too many times"
    } else {
        "the request failed"
    }
    .to_owned()
}

/// What can go wrong with a lookup that is not "this TLD has no RDAP".
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RdapError {
    /// The bootstrap file or the server could not be reached or refused.
    Transport(String),
    /// The server answered that the domain is not registered (HTTP 404).
    NotFound,
    /// The server answered with a refusal or a rate limit.
    Refused {
        /// The HTTP status.
        status: u16,
    },
    /// The answer was not RDAP JSON this provider can read.
    Malformed(String),
    /// The name is not one this provider will put in a URL.
    InvalidName(String),
}

impl std::fmt::Display for RdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "the registry reports no such domain"),
            Self::Refused { status } => write!(f, "the RDAP server answered HTTP {status}"),
            Self::Malformed(detail) => write!(f, "unreadable RDAP answer: {detail}"),
            Self::Transport(detail) | Self::InvalidName(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for RdapError {}

/// The parsed IANA bootstrap file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Bootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

#[derive(Deserialize)]
struct BootstrapFile {
    services: Vec<(Vec<String>, Vec<String>)>,
}

impl Bootstrap {
    /// Parses the bootstrap JSON, keeping only HTTPS service URLs.
    ///
    /// # Errors
    ///
    /// Fails when the JSON is not a bootstrap file.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let file: BootstrapFile = serde_json::from_slice(bytes)
            .map_err(|_| "the bootstrap file is not valid RDAP bootstrap JSON".to_owned())?;
        let services = file
            .services
            .into_iter()
            .map(|(tlds, urls)| {
                (
                    tlds.into_iter()
                        .map(|tld| tld.to_ascii_lowercase())
                        .collect(),
                    urls.into_iter()
                        .filter(|url| url.starts_with("https://"))
                        .collect(),
                )
            })
            .collect();
        Ok(Self { services })
    }

    /// The base URL of the preferred server for a TLD, when one exists.
    #[must_use]
    pub fn server_for_tld(&self, tld: &str) -> Option<&str> {
        self.servers_for_tld(tld).first().map(String::as_str)
    }

    /// Every HTTPS server the file lists for a TLD, in its order.
    #[must_use]
    pub fn servers_for_tld(&self, tld: &str) -> &[String] {
        let tld = tld.to_ascii_lowercase();
        self.services
            .iter()
            .find(|(tlds, urls)| !urls.is_empty() && tlds.contains(&tld))
            .map_or(&[][..], |(_, urls)| urls.as_slice())
    }

    /// How many TLDs the file maps.
    #[must_use]
    pub fn tld_count(&self) -> usize {
        self.services.iter().map(|(tlds, _)| tlds.len()).sum()
    }
}

/// The fields Fleet reads from a domain object.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRecord {
    /// The registrar's name, when the answer names one.
    pub registrar: Option<String>,
    /// The expiration event's RFC 3339 timestamp, when the answer has one.
    /// Several ccTLD registries do not publish it.
    pub expires: Option<String>,
    /// The EPP status values.
    pub statuses: Vec<String>,
    /// The delegated nameservers, lowercase without a trailing dot.
    pub nameservers: Vec<String>,
}

/// Parses an RFC 9083 domain object.
///
/// Reading is lenient: a field of an unexpected shape is skipped, not
/// fatal. `status` may be a single string; events without a string action
/// or date, entities without roles, and malformed nameservers are ignored.
///
/// # Errors
///
/// Fails when the body is not a JSON object.
pub fn parse_domain(bytes: &[u8]) -> Result<DomainRecord, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| "the body is not an RDAP domain object".to_owned())?;
    let object = value
        .as_object()
        .ok_or_else(|| "the body is not an RDAP domain object".to_owned())?;
    let items = |name: &str| -> Vec<&serde_json::Value> {
        match object.get(name) {
            Some(serde_json::Value::Array(items)) => items.iter().collect(),
            _ => Vec::new(),
        }
    };
    let expires = items("events").into_iter().find_map(|event| {
        let action = event.get("eventAction")?.as_str()?;
        let date = event.get("eventDate")?.as_str()?.trim();
        (action.eq_ignore_ascii_case("expiration") && !date.is_empty()).then(|| date.to_owned())
    });
    let mut statuses: Vec<String> = match object.get("status") {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|status| status.as_str())
            .map(|status| status.trim().to_owned())
            .collect(),
        Some(serde_json::Value::String(status)) => vec![status.trim().to_owned()],
        _ => Vec::new(),
    };
    statuses.retain(|status| !status.is_empty());
    statuses.sort();
    statuses.dedup();
    let mut nameservers: Vec<String> = items("nameservers")
        .into_iter()
        .filter_map(|ns| ns.get("ldhName")?.as_str())
        .map(|name| name.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    nameservers.sort();
    nameservers.dedup();
    Ok(DomainRecord {
        registrar: registrar_name(&items("entities")),
        expires,
        statuses,
        nameservers,
    })
}

fn registrar_name(entities: &[&serde_json::Value]) -> Option<String> {
    for entity in entities {
        let is_registrar = entity
            .get("roles")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|roles| {
                roles
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|role| role.eq_ignore_ascii_case("registrar"))
            });
        if is_registrar && let Some(name) = entity.get("vcardArray").and_then(vcard_fn) {
            return Some(name);
        }
        if let Some(serde_json::Value::Array(nested)) = entity.get("entities") {
            let nested: Vec<&serde_json::Value> = nested.iter().collect();
            if let Some(name) = registrar_name(&nested) {
                return Some(name);
            }
        }
    }
    None
}

/// The `fn` (formatted name) property of a jCard: `["vcard", [[name,
/// params, type, value], ...]]`.
fn vcard_fn(vcard: &serde_json::Value) -> Option<String> {
    vcard
        .get(1)?
        .as_array()?
        .iter()
        .filter_map(|property| property.as_array())
        .find(|property| property.first().and_then(|n| n.as_str()) == Some("fn"))
        .and_then(|property| property.get(3))
        .and_then(|value| value.as_str())
        .map(|name| name.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|name| !name.is_empty())
}

/// The answer to a lookup that reached a decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Lookup {
    /// A server answered.
    Found {
        /// The server's base URL.
        server: String,
        /// What it said.
        record: DomainRecord,
    },
    /// No RDAP service covers the TLD.
    Unavailable {
        /// The TLD, for the report.
        tld: String,
    },
}

/// The RDAP client: bootstrap resolution with a TTL cache, then one query.
#[derive(Debug)]
pub struct RdapClient {
    transport: Arc<dyn RdapTransport>,
    bootstrap_url: String,
    ttl: Duration,
    cache: Mutex<Cache>,
}

#[derive(Debug, Default)]
struct Cache {
    good: Option<(Instant, Arc<Bootstrap>)>,
    failure: Option<(Instant, RdapError)>,
}

/// How long a failed bootstrap fetch is remembered, so a sweep over many
/// domains does not repeat a doomed request for each of them.
const FAILURE_MEMORY: Duration = Duration::from_secs(30);

impl RdapClient {
    /// A client over the IANA bootstrap file.
    #[must_use]
    pub fn new(transport: Arc<dyn RdapTransport>) -> Self {
        Self {
            transport,
            bootstrap_url: IANA_BOOTSTRAP_URL.to_owned(),
            ttl: BOOTSTRAP_TTL,
            cache: Mutex::new(Cache::default()),
        }
    }

    /// Overrides the bootstrap TTL (tests).
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Seeds the cache from a pinned bootstrap file. The seed is treated
    /// as fresh for one TTL.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not a bootstrap file.
    pub fn with_seed(self, bytes: &[u8]) -> Result<Self, String> {
        let bootstrap = Bootstrap::parse(bytes)?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.good = Some((Instant::now(), Arc::new(bootstrap)));
        }
        Ok(self)
    }

    async fn bootstrap(&self) -> Result<Arc<Bootstrap>, RdapError> {
        let stale = {
            let cache = self
                .cache
                .lock()
                .map_err(|_| RdapError::Transport("the bootstrap cache is poisoned".to_owned()))?;
            match cache.good.as_ref() {
                Some((at, bootstrap)) if at.elapsed() < self.ttl => {
                    return Ok(bootstrap.clone());
                }
                Some((_, bootstrap)) => Some(bootstrap.clone()),
                None => {
                    if let Some((at, error)) = &cache.failure
                        && at.elapsed() < FAILURE_MEMORY
                    {
                        return Err(error.clone());
                    }
                    None
                }
            }
        };
        let fetched = self
            .transport
            .get(&self.bootstrap_url)
            .await
            .map_err(RdapError::Transport)
            .and_then(|response| {
                if response.status == 200 {
                    Bootstrap::parse(&response.body).map_err(RdapError::Malformed)
                } else {
                    Err(RdapError::Refused {
                        status: response.status,
                    })
                }
            });
        match fetched {
            Ok(bootstrap) => {
                let bootstrap = Arc::new(bootstrap);
                if let Ok(mut cache) = self.cache.lock() {
                    cache.good = Some((Instant::now(), bootstrap.clone()));
                    cache.failure = None;
                }
                Ok(bootstrap)
            }
            // A stale copy beats no answer: the file changes rarely.
            Err(_) if stale.is_some() => Ok(stale.unwrap_or_default()),
            Err(error) => {
                if let Ok(mut cache) = self.cache.lock() {
                    cache.failure = Some((Instant::now(), error.clone()));
                }
                Err(error)
            }
        }
    }

    /// The RDAP server base URL for a domain, or `None` when its TLD has
    /// no RDAP service.
    ///
    /// # Errors
    ///
    /// Fails on an invalid name or when the bootstrap file is unavailable.
    pub async fn server_for(&self, domain: &str) -> Result<Option<String>, RdapError> {
        let name = ldh_name(domain)?;
        let tld = name.rsplit('.').next().unwrap_or_default().to_owned();
        let bootstrap = self.bootstrap().await?;
        Ok(bootstrap.server_for_tld(&tld).map(str::to_owned))
    }

    /// Queries `server` for `domain`; when that fails with a transport
    /// error or HTTP 5xx, tries the TLD's other listed servers.
    ///
    /// # Errors
    ///
    /// Fails on an invalid name, a transport failure, a 404, a refusal,
    /// or an unreadable answer (the first server's, when all fail).
    pub async fn query(&self, server: &str, domain: &str) -> Result<DomainRecord, RdapError> {
        let name = ldh_name(domain)?;
        let first = self.query_one(server, &name).await;
        let retryable = matches!(
            &first,
            Err(RdapError::Transport(_) | RdapError::Refused { status: 500..=599 })
        );
        if !retryable {
            return first;
        }
        let tld = name.rsplit('.').next().unwrap_or_default();
        if let Ok(bootstrap) = self.bootstrap().await {
            for other in bootstrap.servers_for_tld(tld) {
                if other.trim_end_matches('/') == server.trim_end_matches('/') {
                    continue;
                }
                match self.query_one(other, &name).await {
                    Ok(record) => return Ok(record),
                    Err(RdapError::NotFound) => return Err(RdapError::NotFound),
                    Err(_) => {}
                }
            }
        }
        first
    }

    async fn query_one(&self, server: &str, name: &str) -> Result<DomainRecord, RdapError> {
        let url = format!("{}/domain/{name}", server.trim_end_matches('/'));
        let response = self
            .transport
            .get(&url)
            .await
            .map_err(RdapError::Transport)?;
        match response.status {
            200 => parse_domain(&response.body).map_err(RdapError::Malformed),
            404 => Err(RdapError::NotFound),
            status => Err(RdapError::Refused { status }),
        }
    }

    /// Resolves the server and queries it.
    ///
    /// # Errors
    ///
    /// As [`RdapClient::server_for`] and [`RdapClient::query`].
    pub async fn lookup(&self, domain: &str) -> Result<Lookup, RdapError> {
        let name = ldh_name(domain)?;
        match self.server_for(&name).await? {
            Some(server) => {
                let record = self.query(&server, &name).await?;
                Ok(Lookup::Found { server, record })
            }
            None => Ok(Lookup::Unavailable {
                tld: name.rsplit('.').next().unwrap_or_default().to_owned(),
            }),
        }
    }
}

/// A lowercase ASCII letters-digits-hyphen name with at least two labels:
/// the only shape this provider puts in a URL path.
///
/// # Errors
///
/// Fails on anything else, including non-ASCII names (give punycode).
pub fn ldh_name(domain: &str) -> Result<String, RdapError> {
    let name = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let invalid = |detail: &str| RdapError::InvalidName(detail.to_owned());
    if name.is_empty() || name.len() > 253 {
        return Err(invalid("the domain name is empty or too long"));
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err(invalid("an RDAP lookup needs a name below a TLD"));
    }
    for label in labels {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(invalid(
                "the domain name must be ASCII letters, digits, and hyphens (use punycode)",
            ));
        }
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_normalized_and_validated() {
        assert_eq!(ldh_name("Example.COM.").unwrap(), "example.com");
        assert!(ldh_name("com").is_err());
        assert!(ldh_name("exa mple.com").is_err());
        assert!(ldh_name("exämple.com").is_err());
        assert!(ldh_name("a/b.com").is_err());
        assert!(ldh_name("-a.com").is_err());
    }

    #[test]
    fn a_registrar_nested_in_another_entity_is_found() {
        let body = br#"{"entities":[{"roles":["reseller"],"entities":[{"roles":["registrar"],
            "vcardArray":["vcard",[["fn",{},"text","  Nested  Registrar "]]]}]}]}"#;
        let record = parse_domain(body).unwrap();
        assert_eq!(record.registrar.as_deref(), Some("Nested Registrar"));
        assert_eq!(record.expires, None);
    }

    #[test]
    fn a_non_domain_body_is_refused() {
        assert!(parse_domain(b"[1,2]").is_err());
        assert!(parse_domain(b"not json").is_err());
    }
}
