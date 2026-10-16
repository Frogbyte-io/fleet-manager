//! Recorded-fixture tests: a gTLD (`.com`, Verisign), a ccTLD (`.no`,
//! Norid, which publishes no expiration event), and a TLD with no RDAP
//! service. Fixtures keep only the fields the parser reads and have every
//! contact entity scrubbed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fleet_provider_rdap::{
    Bootstrap, HttpResponse, IANA_BOOTSTRAP_URL, Lookup, RdapClient, RdapError, RdapTransport,
    parse_domain,
};

const BOOTSTRAP: &[u8] = include_bytes!("fixtures/iana-dns-bootstrap.json");
const COM: &[u8] = include_bytes!("fixtures/domain-com.json");
const NO: &[u8] = include_bytes!("fixtures/domain-no.json");

#[derive(Debug, Default)]
struct Replay {
    answers: Mutex<HashMap<String, Result<HttpResponse, String>>>,
    requests: Mutex<Vec<String>>,
}

impl Replay {
    fn answer(&self, url: &str, status: u16, body: &[u8]) {
        self.answers.lock().unwrap().insert(
            url.to_owned(),
            Ok(HttpResponse {
                status,
                body: body.to_vec(),
            }),
        );
    }
    fn fail(&self, url: &str, category: &str) {
        self.answers
            .lock()
            .unwrap()
            .insert(url.to_owned(), Err(category.to_owned()));
    }
    fn count(&self, url: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| *seen == url)
            .count()
    }
}

#[async_trait]
impl RdapTransport for Replay {
    async fn get(&self, url: &str) -> Result<HttpResponse, String> {
        self.requests.lock().unwrap().push(url.to_owned());
        self.answers
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .unwrap_or_else(|| {
                Ok(HttpResponse {
                    status: 404,
                    body: Vec::new(),
                })
            })
    }
}

fn client(replay: &Arc<Replay>) -> RdapClient {
    replay.answer(IANA_BOOTSTRAP_URL, 200, BOOTSTRAP);
    RdapClient::new(replay.clone())
}

#[test]
fn the_pinned_bootstrap_maps_tlds_to_https_servers() {
    let bootstrap = Bootstrap::parse(BOOTSTRAP).unwrap();
    assert_eq!(
        bootstrap.server_for_tld("com"),
        Some("https://rdap.verisign.com/com/v1/")
    );
    assert_eq!(
        bootstrap.server_for_tld("NO"),
        Some("https://rdap.norid.no/")
    );
    // The IANA file lists no RDAP service for .de at the pinned date.
    assert_eq!(bootstrap.server_for_tld("de"), None);
}

#[test]
fn a_non_https_service_url_is_dropped() {
    let bootstrap =
        Bootstrap::parse(br#"{"services":[[["xx"],["http://plain.example/"]]]}"#).unwrap();
    assert_eq!(bootstrap.server_for_tld("xx"), None);
}

#[test]
fn a_gtld_answer_yields_registrar_expiry_status_and_nameservers() {
    let record = parse_domain(COM).unwrap();
    assert_eq!(
        record.registrar.as_deref(),
        Some("RESERVED-Internet Assigned Numbers Authority")
    );
    assert_eq!(record.expires.as_deref(), Some("2027-08-13T04:00:00Z"));
    assert_eq!(
        record.statuses,
        [
            "client delete prohibited",
            "client transfer prohibited",
            "client update prohibited"
        ]
    );
    assert_eq!(
        record.nameservers,
        ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]
    );
}

#[test]
fn a_cctld_answer_without_an_expiration_event_has_no_expiry() {
    let record = parse_domain(NO).unwrap();
    assert_eq!(
        record.registrar.as_deref(),
        Some("SIKT - KUNNSKAPSSEKTORENS TJENESTELEVERANDØR")
    );
    assert_eq!(record.expires, None);
    assert!(record.nameservers.contains(&"y.nic.no".to_owned()));
}

#[test]
fn contact_entities_never_reach_the_record() {
    let text = format!("{:?}", parse_domain(NO).unwrap());
    assert!(!text.contains("REDACTED"));
    assert!(!text.contains("technical"));
}

#[tokio::test]
async fn lookup_resolves_the_server_through_the_bootstrap_and_queries_it() {
    let replay = Arc::new(Replay::default());
    replay.answer(
        "https://rdap.verisign.com/com/v1/domain/example.com",
        200,
        COM,
    );
    let outcome = client(&replay).lookup("Example.com").await.unwrap();
    match outcome {
        Lookup::Found { server, record } => {
            assert_eq!(server, "https://rdap.verisign.com/com/v1/");
            assert_eq!(record.expires.as_deref(), Some("2027-08-13T04:00:00Z"));
        }
        other @ Lookup::Unavailable { .. } => panic!("expected found, got {other:?}"),
    }
}

#[tokio::test]
async fn a_tld_without_rdap_is_unavailable_not_an_error() {
    let replay = Arc::new(Replay::default());
    let outcome = client(&replay).lookup("example.de").await.unwrap();
    assert_eq!(outcome, Lookup::Unavailable { tld: "de".to_owned() });
    // No RDAP request was made, only the bootstrap fetch.
    assert_eq!(replay.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn the_bootstrap_is_cached_within_its_ttl_and_refetched_after() {
    let replay = Arc::new(Replay::default());
    let cached = client(&replay);
    cached.lookup("a.de").await.unwrap();
    cached.lookup("b.de").await.unwrap();
    assert_eq!(replay.count(IANA_BOOTSTRAP_URL), 1);

    let expiring = client(&replay).with_ttl(Duration::ZERO);
    expiring.lookup("a.de").await.unwrap();
    expiring.lookup("b.de").await.unwrap();
    assert_eq!(replay.count(IANA_BOOTSTRAP_URL), 3);
}

#[tokio::test]
async fn a_failed_refresh_serves_the_stale_bootstrap() {
    let replay = Arc::new(Replay::default());
    replay.fail(IANA_BOOTSTRAP_URL, "the server could not be reached");
    let stale = RdapClient::new(replay.clone())
        .with_seed(BOOTSTRAP)
        .unwrap()
        .with_ttl(Duration::ZERO);
    let server = stale.server_for("example.com").await.unwrap();
    assert_eq!(server.as_deref(), Some("https://rdap.verisign.com/com/v1/"));

    let cold = RdapClient::new(replay.clone());
    assert!(matches!(
        cold.server_for("example.com").await,
        Err(RdapError::Transport(_))
    ));
}

#[tokio::test]
async fn http_failures_are_classified() {
    let replay = Arc::new(Replay::default());
    let rdap = client(&replay);
    let server = "https://rdap.verisign.com/com/v1/";
    assert_eq!(
        rdap.query(server, "gone.com").await,
        Err(RdapError::NotFound)
    );
    replay.answer(
        "https://rdap.verisign.com/com/v1/domain/busy.com",
        429,
        b"",
    );
    assert_eq!(
        rdap.query(server, "busy.com").await,
        Err(RdapError::Refused { status: 429 })
    );
    replay.answer(
        "https://rdap.verisign.com/com/v1/domain/odd.com",
        200,
        b"<html>",
    );
    assert!(matches!(
        rdap.query(server, "odd.com").await,
        Err(RdapError::Malformed(_))
    ));
}
