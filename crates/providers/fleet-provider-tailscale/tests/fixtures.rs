//! Provider tests over recorded fixtures: the OAuth token flow and its
//! refresh, device listing, the failure taxonomy, and the guarantee that
//! credentials never leak into errors or debug output.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::tailnet::{TailnetCredentials, TailnetSourceError};
use fleet_core::SensitiveString;
use fleet_provider_tailscale::{HttpRequest, HttpResponse, TailscaleClient, Transport};

/// The recorded token response for the `devices:core:read` scope.
const TOKEN_BODY: &str = r#"{"access_token":"tskey-access-recorded-token","scope":"devices:core:read","token_type":"Bearer","expires_in":3600}"#;

/// Devices shaped like the API's real response (camelCase, `nodeId` preferred).
const DEVICES_BODY: &str = r#"{"devices":[
  {"nodeId":"nABC123","id":"1503","name":"build-host.tail-example.ts.net.","hostname":"build-host","os":"linux","addresses":["100.64.0.10","fd7a:115c:a1e0::1"],"tags":["tag:server"],"user":"amelie@example.com","online":true,"connectedToControl":true},
  {"nodeId":"nDEF456","id":"1504","name":"lab-box.tail-example.ts.net.","hostname":"lab-box","os":"linux","addresses":["100.64.0.11"],"user":"amelie@example.com","online":false,"lastSeen":"2026-09-01T05:23:30Z"}
]}"#;

/// A transport that always fails at the transport level.
#[derive(Debug, Default)]
struct BrokenTransport;

#[async_trait]
impl Transport for BrokenTransport {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, String> {
        Err("connection refused".to_owned())
    }
}

fn credentials() -> TailnetCredentials {
    TailnetCredentials {
        client_id: "k1234567890abcdef1234567890abcdef".to_owned(),
        client_secret: SensitiveString::new("tskey-client-secret-never-logged"),
    }
}

fn token_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        body: TOKEN_BODY.as_bytes().to_vec(),
        retry_after_secs: None,
    }
}

fn devices_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        body: DEVICES_BODY.as_bytes().to_vec(),
        retry_after_secs: None,
    }
}

fn response(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        body: body.as_bytes().to_vec(),
        retry_after_secs: None,
    }
}

/// A transport that answers each URL with its own recorded response,
/// recording every request.
#[derive(Debug)]
struct FixedTransport {
    tokens: Mutex<std::collections::VecDeque<HttpResponse>>,
    devices: Mutex<std::collections::VecDeque<HttpResponse>>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl FixedTransport {
    /// The first response is the token; every subsequent one answers a
    /// devices call. The refresh test needs the refresh token response to
    /// land under the token URL, so it uses [`FixedTransport::with_refresh`].
    /// The first response is the token; the rest answer devices calls. For
    /// a refresh test, use [`FixedTransport::alternating`] instead.
    fn with(responses: Vec<HttpResponse>) -> Arc<Self> {
        let mut iter = responses.into_iter();
        let token = iter.next().expect("the token response is first");
        Arc::new(Self {
            tokens: Mutex::new(std::collections::VecDeque::from([token])),
            devices: Mutex::new(std::collections::VecDeque::from(iter.collect::<Vec<_>>())),
            requests: Mutex::new(Vec::new()),
        })
    }

    /// Responses alternate token, devices, token, devices…: the shape of a
    /// refresh test where each listing fetches its own token.
    fn alternating(responses: Vec<HttpResponse>) -> Arc<Self> {
        let mut tokens = std::collections::VecDeque::new();
        let mut devices = std::collections::VecDeque::new();
        for (index, response) in responses.into_iter().enumerate() {
            if index % 2 == 0 {
                tokens.push_back(response);
            } else {
                devices.push_back(response);
            }
        }
        Arc::new(Self {
            tokens: Mutex::new(tokens),
            devices: Mutex::new(devices),
            requests: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl Transport for FixedTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let is_token = request.url.contains("/oauth/token");
        self.requests.lock().unwrap().push(request);
        if is_token {
            return self
                .tokens
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| "no canned token".to_owned());
        }
        self.devices
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| "no canned devices".to_owned())
    }
}

#[tokio::test]
async fn a_listing_fetches_a_token_then_the_devices() {
    let transport = FixedTransport::with(vec![token_response(), devices_response()]);
    let client = TailscaleClient::new(transport.clone());
    let devices = client.list_devices("-", &credentials()).await.unwrap();

    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].node_id, "nABC123");
    assert_eq!(devices[0].id.as_deref(), Some("1503"));
    assert_eq!(devices[0].addresses[0], "100.64.0.10");
    assert_eq!(devices[0].tags, vec!["tag:server".to_owned()]);
    assert_eq!(devices[0].online, Some(true));
    assert_eq!(devices[0].connected_to_control, Some(true));
    assert_eq!(
        devices[1].last_seen.as_deref(),
        Some("2026-09-01T05:23:30Z")
    );

    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0].url.ends_with("/oauth/token"),
        "the token comes first"
    );
    assert!(
        requests[0]
            .form
            .as_ref()
            .expect("the token request is a form")
            .iter()
            .any(|(key, value)| key == "scope" && value == "devices:core:read"),
        "the requested scope is the read-only one"
    );
    assert!(
        requests[1].url.ends_with("/tailnet/-/devices"),
        "the default tailnet selector is used"
    );
    assert!(
        requests[1]
            .authorization
            .starts_with("Bearer tskey-access-recorded-token"),
        "the listing carries the fetched token"
    );
}

#[tokio::test]
async fn a_second_listing_reuses_the_cached_token() {
    let transport = FixedTransport::with(vec![
        token_response(),
        devices_response(),
        devices_response(),
    ]);
    let client = TailscaleClient::new(transport.clone());
    client.list_devices("-", &credentials()).await.unwrap();
    client.list_devices("-", &credentials()).await.unwrap();

    let requests = transport.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.contains("/oauth/token"))
            .count(),
        1,
        "the token is cached across listings"
    );
}

#[tokio::test]
async fn an_expired_cached_token_is_refreshed() {
    // The first token lives for no seconds at all: by the second listing it
    // is past expiry (plus the refresh margin) and must be refetched.
    let short_lived = HttpResponse {
        body: br#"{"access_token":"tskey-access-short-lived","scope":"devices:core:read","token_type":"Bearer","expires_in":0}"#.to_vec(),
        ..token_response()
    };
    let transport = FixedTransport::alternating(vec![
        short_lived,
        devices_response(),
        token_response(),
        devices_response(),
    ]);
    let client = TailscaleClient::new(transport.clone());
    client.list_devices("-", &credentials()).await.unwrap();
    // The second listing runs "an hour later": the cached token is past its
    // expiry (plus the refresh margin), so the client fetches a fresh one.
    // The fake clock is the transport's request count plus the canned
    // expiry: the second token response is consumed, proving the refetch.
    client.list_devices("-", &credentials()).await.unwrap();
    let requests = transport.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.contains("/oauth/token"))
            .count(),
        2,
        "an expired token must be refetched"
    );
}

#[tokio::test]
async fn failures_come_through_the_taxonomy() {
    let credentials = credentials();

    // Auth refusal.
    let client = TailscaleClient::new(FixedTransport::with(vec![
        token_response(),
        response(401, "unauthorized"),
    ]));
    let error = client.list_devices("-", &credentials).await.unwrap_err();
    assert!(
        matches!(error, TailnetSourceError::Auth { .. }),
        "{error:?}"
    );

    // Rate limited, with the source's Retry-After hint.
    let client = TailscaleClient::new(FixedTransport::with(vec![
        token_response(),
        HttpResponse {
            status: 429,
            body: b"slow down".to_vec(),
            retry_after_secs: Some(7),
        },
    ]));
    let error = client.list_devices("-", &credentials).await.unwrap_err();
    match error {
        TailnetSourceError::RateLimited { retry_after_secs } => {
            assert_eq!(retry_after_secs, Some(7));
        }
        other => panic!("expected rate limiting, got {other:?}"),
    }

    // Missing tailnet.
    let client = TailscaleClient::new(FixedTransport::with(vec![
        token_response(),
        response(404, "no such tailnet"),
    ]));
    let error = client.list_devices("-", &credentials).await.unwrap_err();
    assert!(
        matches!(error, TailnetSourceError::NotFound { .. }),
        "{error:?}"
    );

    // Uninterpretable payload.
    let client = TailscaleClient::new(FixedTransport::with(vec![
        token_response(),
        response(200, "<html>not json</html>"),
    ]));
    let error = client.list_devices("-", &credentials).await.unwrap_err();
    assert!(
        matches!(error, TailnetSourceError::InvalidPayload { .. }),
        "{error:?}"
    );

    // A transport-level failure is an honest Http error with status 0.
    let client = TailscaleClient::new(Arc::new(BrokenTransport));
    let error = client.list_devices("-", &credentials).await.unwrap_err();
    match error {
        TailnetSourceError::Http { status, detail } => {
            assert_eq!(status, 0);
            assert!(detail.contains("connection refused"), "{detail}");
        }
        other => panic!("expected an http error, got {other:?}"),
    }
}

#[tokio::test]
async fn credentials_never_appear_in_errors_or_debug() {
    let credentials = credentials();
    let client = TailscaleClient::new(FixedTransport::with(vec![
        token_response(),
        response(401, "unauthorized"),
    ]));
    let error = client.list_devices("-", &credentials).await.unwrap_err();
    let rendered = error.to_string();
    assert!(
        !rendered.contains("tskey-client-secret-never-logged"),
        "the secret must never surface: {rendered}"
    );
    assert!(
        !format!("{error:?}").contains("tskey-client-secret-never-logged"),
        "the secret must never surface in debug"
    );
    assert!(
        !format!("{client:?}").contains("tskey-client-secret-never-logged"),
        "the client's debug must never carry the secret"
    );
}
