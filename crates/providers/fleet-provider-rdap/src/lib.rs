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
                if attempt.previous().len() >= 3 || attempt.url().scheme() != "https" {
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

    /// The base URL of the server for a TLD, when one exists.
    #[must_use]
    pub fn server_for_tld(&self, tld: &str) -> Option<&str> {
        let tld = tld.to_ascii_lowercase();
        self.services
            .iter()
            .find(|(tlds, urls)| !urls.is_empty() && tlds.contains(&tld))
            .and_then(|(_, urls)| urls.first())
            .map(String::as_str)
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

#[derive(Deserialize)]
struct DomainObject {
    #[serde(default)]
    status: Vec<String>,
    #[serde(default)]
    events: Vec<Event>,
    #[serde(default)]
    entities: Vec<Entity>,
    #[serde(default)]
    nameservers: Vec<Nameserver>,
}

#[derive(Deserialize)]
struct Event {
    #[serde(rename = "eventAction", default)]
    action: String,
    #[serde(rename = "eventDate", default)]
    date: String,
}

#[derive(Deserialize)]
struct Entity {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(rename = "vcardArray", default)]
    vcard: serde_json::Value,
    #[serde(default)]
    entities: Vec<Entity>,
}

#[derive(Deserialize)]
struct Nameserver {
    #[serde(rename = "ldhName", default)]
    ldh_name: String,
}

/// Parses an RFC 9083 domain object.
///
/// # Errors
///
/// Fails when the body is not a JSON object shaped like a domain.
pub fn parse_domain(bytes: &[u8]) -> Result<DomainRecord, String> {
    let object: DomainObject = serde_json::from_slice(bytes)
        .map_err(|_| "the body is not an RDAP domain object".to_owned())?;
    let expires = object
        .events
        .iter()
        .find(|event| event.action.eq_ignore_ascii_case("expiration"))
        .map(|event| event.date.trim().to_owned())
        .filter(|date| !date.is_empty());
    let mut statuses: Vec<String> = object
        .status
        .into_iter()
        .map(|status| status.trim().to_owned())
        .filter(|status| !status.is_empty())
        .collect();
    statuses.sort();
    statuses.dedup();
    let mut nameservers: Vec<String> = object
        .nameservers
        .iter()
        .map(|ns| {
            ns.ldh_name
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase()
        })
        .filter(|name| !name.is_empty())
        .collect();
    nameservers.sort();
    nameservers.dedup();
    Ok(DomainRecord {
        registrar: registrar_name(&object.entities),
        expires,
        statuses,
        nameservers,
    })
}

fn registrar_name(entities: &[Entity]) -> Option<String> {
    for entity in entities {
        if entity
            .roles
            .iter()
            .any(|role| role.eq_ignore_ascii_case("registrar"))
            && let Some(name) = vcard_fn(&entity.vcard)
        {
            return Some(name);
        }
        if let Some(name) = registrar_name(&entity.entities) {
            return Some(name);
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
    cache: Mutex<Option<(Instant, Arc<Bootstrap>)>>,
}

impl RdapClient {
    /// A client over the IANA bootstrap file.
    #[must_use]
    pub fn new(transport: Arc<dyn RdapTransport>) -> Self {
        Self {
            transport,
            bootstrap_url: IANA_BOOTSTRAP_URL.to_owned(),
            ttl: BOOTSTRAP_TTL,
            cache: Mutex::new(None),
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
            *cache = Some((Instant::now(), Arc::new(bootstrap)));
        }
        Ok(self)
    }

    async fn bootstrap(&self) -> Result<Arc<Bootstrap>, RdapError> {
        let stale = {
            let cache = self
                .cache
                .lock()
                .map_err(|_| RdapError::Transport("the bootstrap cache is poisoned".to_owned()))?;
            match cache.as_ref() {
                Some((at, bootstrap)) if at.elapsed() < self.ttl => {
                    return Ok(bootstrap.clone());
                }
                Some((_, bootstrap)) => Some(bootstrap.clone()),
                None => None,
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
                    *cache = Some((Instant::now(), bootstrap.clone()));
                }
                Ok(bootstrap)
            }
            // A stale copy beats no answer: the file changes rarely.
            Err(_) if stale.is_some() => Ok(stale.unwrap_or_default()),
            Err(error) => Err(error),
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

    /// Queries `server` for `domain`.
    ///
    /// # Errors
    ///
    /// Fails on an invalid name, a transport failure, a 404, a refusal,
    /// or an unreadable answer.
    pub async fn query(&self, server: &str, domain: &str) -> Result<DomainRecord, RdapError> {
        let name = ldh_name(domain)?;
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
