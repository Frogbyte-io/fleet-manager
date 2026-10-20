//! The WHOIS fallback (FM-529): the registrar and expiry date of a domain
//! whose TLD has no RDAP service (`.io`, `.gg`).
//!
//! Primary sources:
//!
//! * RFC 3912: a WHOIS query is the name and CRLF sent over TCP port 43;
//!   the server answers with free text and closes the connection.
//! * IANA's WHOIS server (`whois.iana.org`) answers a TLD query with that
//!   TLD's registry in a `whois:` line, after the contact blocks (there is
//!   no `refer:` line in these answers). An IANA answer (`% This query
//!   returned N object`) with no such line means the TLD has no public
//!   WHOIS server, which is a normal answer, not an error. Anything that
//!   does not look like an IANA answer is not trusted as "none".
//!
//! There is no standard text format. Two small per-format readers cover
//! what registries answer today: `Key: value` lines (`.io`), and a key line
//! followed by an indented value line (`.gg`). Only the registrar name and
//! the expiry date are read; registrant and contact data are never read
//! or stored. An answer neither reader understands is
//! [`WhoisError::Unreadable`] (reported as `unavailable`, not as a failure).
//!
//! The network sits behind [`WhoisTransport`] so tests replay recorded
//! fixtures. Responses are bounded in bytes and time, and the referral for
//! a TLD is cached.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ldh_name;

/// IANA's WHOIS server, which refers a TLD to its registry.
pub const IANA_WHOIS_SERVER: &str = "whois.iana.org";
/// The WHOIS port.
pub const WHOIS_PORT: u16 = 43;
/// How long a TLD's referral is trusted.
pub const REFERRAL_TTL: Duration = Duration::from_hours(24);
/// How long "this TLD has no WHOIS server" is trusted.
pub const NO_REFERRAL_TTL: Duration = Duration::from_hours(1);
/// How long a failed referral lookup is remembered, so a sweep does not
/// repeat a doomed query for every domain.
pub const REFERRAL_FAILURE_MEMORY: Duration = Duration::from_secs(30);
/// The marker every genuine IANA WHOIS answer carries.
const IANA_MARKER: &str = "% this query returned";
/// How long one whole query (connect, send, read) may take.
pub const WHOIS_TIMEOUT: Duration = Duration::from_secs(15);
/// The most response bytes read from one answer.
pub const WHOIS_BOUND: usize = 64 * 1024;
/// The longest registrar name kept.
const MAX_VALUE: usize = 200;

/// The WHOIS port: one query to one server.
#[async_trait::async_trait]
pub trait WhoisTransport: std::fmt::Debug + Send + Sync {
    /// Sends `query` to `server` and returns the (bounded) answer. A
    /// failure is a short, credential-free category.
    ///
    /// # Errors
    ///
    /// Fails when the query could not complete.
    async fn query(&self, server: &str, query: &str) -> Result<Vec<u8>, String>;
}

/// The production transport: TCP port 43, bounded bytes and time.
#[derive(Debug, Default)]
pub struct TcpWhoisTransport;

#[async_trait::async_trait]
impl WhoisTransport for TcpWhoisTransport {
    async fn query(&self, server: &str, query: &str) -> Result<Vec<u8>, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let exchange = async {
            let mut stream = tokio::net::TcpStream::connect((server, WHOIS_PORT))
                .await
                .map_err(|_| "the WHOIS server could not be reached".to_owned())?;
            stream
                .write_all(format!("{query}\r\n").as_bytes())
                .await
                .map_err(|_| "the WHOIS query could not be sent".to_owned())?;
            let mut body = Vec::new();
            let mut limited = (&mut stream).take(WHOIS_BOUND as u64);
            limited
                .read_to_end(&mut body)
                .await
                .map_err(|_| "the WHOIS answer could not be read".to_owned())?;
            Ok(body)
        };
        tokio::time::timeout(WHOIS_TIMEOUT, exchange)
            .await
            .unwrap_or_else(|_| Err("the WHOIS query timed out".to_owned()))
    }
}

/// What can go wrong with a WHOIS lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WhoisError {
    /// The server could not be reached or the answer could not be read.
    Transport(String),
    /// The server answered that the domain is not registered.
    NotFound,
    /// The answer is in a format no reader understands, or names neither
    /// a registrar nor an expiry date.
    Unreadable,
    /// The server is throttling or refusing queries (a rate-limit or quota
    /// message), so nothing is known about the domain.
    Throttled,
    /// The name is not one this provider will send.
    InvalidName(String),
}

impl std::fmt::Display for WhoisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "the registry reports no such domain"),
            Self::Unreadable => write!(f, "the WHOIS answer is in a format Fleet cannot read"),
            Self::Throttled => write!(
                f,
                "the WHOIS server is rate limiting queries; try again later"
            ),
            Self::Transport(detail) | Self::InvalidName(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for WhoisError {}

/// The fields Fleet reads from a WHOIS answer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WhoisRecord {
    /// The registrar's name, when the answer names one.
    pub registrar: Option<String>,
    /// The expiry as the server wrote it (an RFC 3339 timestamp or a
    /// `YYYY-MM-DD` date), when the answer has one. Some registries
    /// (`.gg`) do not publish it.
    pub expires: Option<String>,
}

/// Expiry keys, lowercase.
const EXPIRY_KEYS: [&str; 4] = [
    "registry expiry date",
    "expiry date",
    "expiration date",
    "paid-till",
];

/// Parses a WHOIS answer for a domain.
///
/// # Errors
///
/// [`WhoisError::NotFound`] when the answer says the domain is not
/// registered; [`WhoisError::Unreadable`] when it names neither a
/// registrar nor an expiry date.
pub fn parse_answer(bytes: &[u8]) -> Result<WhoisRecord, WhoisError> {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().take(2_000).collect();
    let mut record = WhoisRecord::default();
    for (index, line) in lines.iter().enumerate() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        // Indented lines are values of a block format, never keys.
        if key.starts_with(char::is_whitespace) {
            continue;
        }
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if key == "registrar" && record.registrar.is_none() {
            let name = if value.is_empty() {
                // Block format: the name is the next indented line.
                lines
                    .get(index + 1)
                    .filter(|next| next.starts_with(char::is_whitespace))
                    .map_or("", |next| next.trim())
            } else {
                value
            };
            record.registrar = clean_registrar(name);
        } else if record.expires.is_none() && EXPIRY_KEYS.contains(&key.as_str()) {
            record.expires = valid_date(value);
        }
    }
    if record.registrar.is_some() || record.expires.is_some() {
        return Ok(record);
    }
    let has = |markers: &[&str]| {
        lines.iter().any(|line| {
            let line = line.trim().to_ascii_lowercase();
            markers.iter().any(|marker| line.contains(marker))
        })
    };
    // Not found wins: "domain not found, try again" is still not found.
    Err(
        if has(&["not found", "no match", "no entries found", "no data found"]) {
            WhoisError::NotFound
        } else if has(&["rate limit", "too many", "quota", "try again"]) {
            WhoisError::Throttled
        } else {
            WhoisError::Unreadable
        },
    )
}

/// A registrar name without a trailing parenthesized URL (`.gg` appends
/// the registrar's site), collapsed whitespace, bounded.
fn clean_registrar(name: &str) -> Option<String> {
    let mut name = name.trim();
    if name.ends_with(')')
        && let Some(open) = name.rfind('(')
        && name[open..].contains("://")
    {
        name = name[..open].trim_end();
    }
    let name: String = name
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_VALUE)
        .collect();
    (!name.is_empty()).then_some(name)
}

/// The value when it starts with a `YYYY-MM-DD` date.
fn valid_date(value: &str) -> Option<String> {
    let head = value.get(..10)?;
    let shaped = head.bytes().enumerate().all(|(i, b)| match i {
        4 | 7 => b == b'-',
        _ => b.is_ascii_digit(),
    });
    (shaped && value.len() <= 40).then(|| value.to_owned())
}

/// The WHOIS server named by an IANA answer for a TLD: the `whois:` line,
/// when it holds a plain hostname.
#[must_use]
pub fn parse_referral(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    text.lines().take(500).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        let key = key.trim().to_ascii_lowercase();
        let host = value.trim().to_ascii_lowercase();
        (key == "whois" && is_hostname(&host)).then_some(host)
    })
}

/// A plain DNS hostname: at least two labels, letters-digits-hyphens, and
/// a last label that is not all digits (so IP literals are refused). The
/// name still comes from IANA's answer, which is trusted to name a
/// registry; this check only keeps a garbled or hostile answer from making
/// Fleet connect to an address or a non-name.
fn is_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && host
            .rsplit('.')
            .next()
            .is_some_and(|last| !last.bytes().all(|b| b.is_ascii_digit()))
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The WHOIS client: referral through IANA with a TTL cache, then one
/// query.
#[derive(Debug)]
pub struct WhoisClient {
    transport: Arc<dyn WhoisTransport>,
    iana_server: String,
    ttl: Duration,
    referrals: Mutex<HashMap<String, (Instant, Option<String>)>>,
    failures: Mutex<HashMap<String, (Instant, WhoisError)>>,
}

impl WhoisClient {
    /// A client that refers through `whois.iana.org`.
    #[must_use]
    pub fn new(transport: Arc<dyn WhoisTransport>) -> Self {
        Self {
            transport,
            iana_server: IANA_WHOIS_SERVER.to_owned(),
            ttl: REFERRAL_TTL,
            referrals: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// Overrides the referral TTL (tests).
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Whether [`WhoisClient::server_for`] would answer without touching
    /// the network (a cached referral, or a remembered failure). Callers
    /// that rate limit IANA use this to reserve a slot only when needed.
    #[must_use]
    pub fn referral_is_cached(&self, domain: &str) -> bool {
        let Ok(name) = ldh_name(domain) else {
            return true;
        };
        let tld = name.rsplit('.').next().unwrap_or_default();
        self.cached(tld).is_some()
    }

    fn cached(&self, tld: &str) -> Option<Result<Option<String>, WhoisError>> {
        if let Ok(cache) = self.referrals.lock()
            && let Some((at, server)) = cache.get(tld)
        {
            let ttl = if server.is_some() {
                self.ttl
            } else {
                self.ttl.min(NO_REFERRAL_TTL)
            };
            if at.elapsed() < ttl {
                return Some(Ok(server.clone()));
            }
        }
        if let Ok(failures) = self.failures.lock()
            && let Some((at, error)) = failures.get(tld)
            && at.elapsed() < REFERRAL_FAILURE_MEMORY.min(self.ttl)
        {
            return Some(Err(error.clone()));
        }
        None
    }

    /// The registry's WHOIS server for the domain's TLD, or `None` when
    /// IANA says the TLD has none. Referrals are cached (24 hours; "none"
    /// for one hour, and only when the answer is positively an IANA
    /// answer); failures are remembered briefly.
    ///
    /// # Errors
    ///
    /// Fails on an invalid name, when IANA cannot be queried, or when its
    /// answer is not recognizably an IANA answer.
    pub async fn server_for(&self, domain: &str) -> Result<Option<String>, WhoisError> {
        let name = ldh_name(domain).map_err(|error| WhoisError::InvalidName(error.to_string()))?;
        let tld = name.rsplit('.').next().unwrap_or_default().to_owned();
        if let Some(cached) = self.cached(&tld) {
            return cached;
        }
        let outcome = self.fetch_referral(&tld).await;
        match &outcome {
            Ok(server) => {
                if let Ok(mut cache) = self.referrals.lock() {
                    cache.insert(tld, (Instant::now(), server.clone()));
                }
            }
            Err(error) => {
                if let Ok(mut failures) = self.failures.lock() {
                    failures.insert(tld, (Instant::now(), error.clone()));
                }
            }
        }
        outcome
    }

    async fn fetch_referral(&self, tld: &str) -> Result<Option<String>, WhoisError> {
        let answer = self
            .transport
            .query(&self.iana_server, tld)
            .await
            .map_err(WhoisError::Transport)?;
        if let Some(server) = parse_referral(&answer) {
            return Ok(Some(server));
        }
        if String::from_utf8_lossy(&answer)
            .to_ascii_lowercase()
            .contains(IANA_MARKER)
        {
            Ok(None)
        } else {
            // A throttle notice or an error page is not "no WHOIS server".
            Err(WhoisError::Unreadable)
        }
    }

    /// Queries `server` for `domain`.
    ///
    /// # Errors
    ///
    /// Fails on an invalid name, a transport failure, a not-found answer,
    /// or an answer in no known format.
    pub async fn query(&self, server: &str, domain: &str) -> Result<WhoisRecord, WhoisError> {
        let name = ldh_name(domain).map_err(|error| WhoisError::InvalidName(error.to_string()))?;
        if !is_hostname(server) {
            return Err(WhoisError::InvalidName(
                "the WHOIS server is not a plain hostname".to_owned(),
            ));
        }
        let answer = self
            .transport
            .query(server, &name)
            .await
            .map_err(WhoisError::Transport)?;
        parse_answer(&answer)
    }
}
