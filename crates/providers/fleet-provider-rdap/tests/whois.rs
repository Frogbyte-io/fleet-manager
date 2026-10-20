//! Recorded-fixture tests for the WHOIS fallback: `.io` (`Key: value`
//! lines, with an expiry), `.gg` (indented block, no expiry), the IANA
//! referral and its cache, a TLD with no WHOIS server, and unreadable and
//! not-found answers. Fixtures keep only the fields the parsers read;
//! registrant data is scrubbed and the domains are examples.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fleet_provider_rdap::whois::{
    WhoisClient, WhoisError, WhoisRecord, WhoisTransport, parse_answer, parse_referral,
};

const IANA_IO: &[u8] = include_bytes!("fixtures/whois-iana-io.txt");
const IANA_GG: &[u8] = include_bytes!("fixtures/whois-iana-gg.txt");
const IANA_NONE: &[u8] = include_bytes!("fixtures/whois-iana-none.txt");
const IO: &[u8] = include_bytes!("fixtures/whois-io.txt");
const GG: &[u8] = include_bytes!("fixtures/whois-gg.txt");
const IO_NOT_FOUND: &[u8] = include_bytes!("fixtures/whois-io-notfound.txt");
const RATE_LIMITED: &[u8] = include_bytes!("fixtures/whois-ratelimited.txt");

type Key = (String, String);

#[derive(Debug, Default)]
struct Replay {
    answers: Mutex<HashMap<Key, Result<Vec<u8>, String>>>,
    requests: Mutex<Vec<Key>>,
}

impl Replay {
    fn answer(&self, server: &str, query: &str, body: &[u8]) {
        self.answers
            .lock()
            .unwrap()
            .insert((server.to_owned(), query.to_owned()), Ok(body.to_vec()));
    }
    fn fail(&self, server: &str, query: &str) {
        self.answers.lock().unwrap().insert(
            (server.to_owned(), query.to_owned()),
            Err("the WHOIS server could not be reached".to_owned()),
        );
    }
    fn count(&self, server: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(seen, _)| seen == server)
            .count()
    }
}

#[async_trait]
impl WhoisTransport for Replay {
    async fn query(&self, server: &str, query: &str) -> Result<Vec<u8>, String> {
        self.requests
            .lock()
            .unwrap()
            .push((server.to_owned(), query.to_owned()));
        self.answers
            .lock()
            .unwrap()
            .get(&(server.to_owned(), query.to_owned()))
            .cloned()
            .unwrap_or_else(|| Err("the WHOIS server could not be reached".to_owned()))
    }
}

#[test]
fn an_io_answer_gives_registrar_and_registry_expiry() {
    let record = parse_answer(IO).unwrap();
    assert_eq!(record.registrar.as_deref(), Some("Example Registrar, Inc."));
    assert_eq!(record.expires.as_deref(), Some("2027-05-01T09:08:07Z"));
}

#[test]
fn a_gg_block_answer_gives_the_registrar_without_an_expiry() {
    let record = parse_answer(GG).unwrap();
    assert_eq!(
        record,
        WhoisRecord {
            registrar: Some("Example Registrar Ltd".to_owned()),
            expires: None,
        }
    );
}

#[test]
fn only_the_registrar_and_expiry_are_read() {
    let record = parse_answer(IO).unwrap();
    let debug = format!("{record:?}");
    assert!(!debug.contains("REDACTED"));
    assert!(!debug.contains("abuse@"));
}

#[test]
fn not_found_and_unreadable_answers_are_distinguished() {
    assert_eq!(parse_answer(IO_NOT_FOUND), Err(WhoisError::NotFound));
    assert_eq!(parse_answer(RATE_LIMITED), Err(WhoisError::Unreadable));
    assert_eq!(parse_answer(b""), Err(WhoisError::Unreadable));
}

#[test]
fn a_malformed_expiry_is_skipped() {
    let record = parse_answer(b"Registrar: A\nRegistry Expiry Date: soon\n").unwrap();
    assert_eq!(record.expires, None);
}

#[test]
fn referrals_name_the_registry_server() {
    assert_eq!(parse_referral(IANA_IO).as_deref(), Some("whois.nic.io"));
    assert_eq!(parse_referral(IANA_GG).as_deref(), Some("whois.gg"));
    assert_eq!(parse_referral(IANA_NONE), None);
    assert_eq!(parse_referral(b"whois: not a host\n"), None);
}

#[tokio::test]
async fn lookup_refers_through_iana_then_queries_the_registry() {
    let replay = Arc::new(Replay::default());
    replay.answer("whois.iana.org", "io", IANA_IO);
    replay.answer("whois.nic.io", "example.io", IO);
    let client = WhoisClient::new(replay.clone());
    let server = client.server_for("Example.IO").await.unwrap().unwrap();
    assert_eq!(server, "whois.nic.io");
    let record = client.query(&server, "example.io").await.unwrap();
    assert_eq!(record.registrar.as_deref(), Some("Example Registrar, Inc."));
}

#[tokio::test]
async fn the_referral_is_cached_per_tld_including_no_server() {
    let replay = Arc::new(Replay::default());
    replay.answer("whois.iana.org", "io", IANA_IO);
    replay.answer("whois.iana.org", "zz", IANA_NONE);
    let client = WhoisClient::new(replay.clone());
    for _ in 0..3 {
        assert!(client.server_for("a.io").await.unwrap().is_some());
        assert_eq!(client.server_for("b.zz").await.unwrap(), None);
    }
    assert_eq!(replay.count("whois.iana.org"), 2);
}

#[tokio::test]
async fn an_expired_referral_is_fetched_again_and_failures_are_not_cached() {
    let replay = Arc::new(Replay::default());
    let client = WhoisClient::new(replay.clone()).with_ttl(Duration::ZERO);
    replay.fail("whois.iana.org", "io");
    assert!(matches!(
        client.server_for("a.io").await,
        Err(WhoisError::Transport(_))
    ));
    replay.answer("whois.iana.org", "io", IANA_IO);
    assert!(client.server_for("a.io").await.unwrap().is_some());
    assert!(client.server_for("a.io").await.unwrap().is_some());
    assert_eq!(replay.count("whois.iana.org"), 3);
}

#[tokio::test]
async fn bad_names_and_servers_are_never_sent() {
    let replay = Arc::new(Replay::default());
    let client = WhoisClient::new(replay.clone());
    assert!(matches!(
        client.server_for("exa mple.io").await,
        Err(WhoisError::InvalidName(_))
    ));
    assert!(matches!(
        client.query("evil host:80", "example.io").await,
        Err(WhoisError::InvalidName(_))
    ));
    assert!(replay.requests.lock().unwrap().is_empty());
}
