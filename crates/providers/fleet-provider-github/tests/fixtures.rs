//! Contract fixtures for the GitHub App flow (FM-403): least
//! permissions, expiring tokens, and redacted refusals.

use fleet_provider_github::{
    BootstrapOutcome, GithubTransport, HttpResponse, request_bootstrap_token,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
struct FakeTransport {
    status: u16,
    body: String,
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

#[async_trait::async_trait]
impl GithubTransport for FakeTransport {
    async fn post_installation_token(
        &self,
        installation_id: &str,
        body: &str,
        _deadline: Duration,
    ) -> Result<HttpResponse, String> {
        self.seen
            .lock()
            .unwrap()
            .push((installation_id.to_owned(), body.to_owned()));
        Ok(HttpResponse {
            status: self.status,
            body: self.body.clone(),
        })
    }
}

#[tokio::test]
async fn the_token_request_carries_least_permissions() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeTransport {
        status: 201,
        body: r#"{"token":"ghs_example","expiresAt":"2026-09-19T00:00:00Z"}"#.to_owned(),
        seen: seen.clone(),
    };
    let outcome = request_bootstrap_token(&transport, "12345", Duration::from_secs(30))
        .await
        .unwrap();
    let BootstrapOutcome::Issued {
        token,
        expires_at,
        permissions,
    } = outcome
    else {
        panic!("the token is issued");
    };
    assert_eq!(token, "ghs_example");
    assert_eq!(expires_at.as_deref(), Some("2026-09-19T00:00:00Z"));
    assert_eq!(permissions, ["contents:read_and_write"]);
    let (installation, body) = &seen.lock().unwrap()[0];
    assert_eq!(installation, "12345");
    assert!(
        body.contains(r#""contents":"write""#),
        "the request carries contents write only: {body}"
    );
    assert!(
        !body.contains("admin"),
        "no admin permissions are requested"
    );
}

#[tokio::test]
async fn a_refusal_is_an_honest_outcome_with_redacted_detail() {
    let transport = FakeTransport {
        status: 404,
        body: r#"{"message":"Not Found: https://user:secret@host.invalid"}"#.to_owned(),
        seen: Arc::new(Mutex::new(Vec::new())),
    };
    let outcome = request_bootstrap_token(&transport, "12345", Duration::from_secs(30))
        .await
        .unwrap();
    let BootstrapOutcome::Refused { detail } = outcome else {
        panic!("the refusal is an outcome");
    };
    assert!(!detail.contains("secret"), "{detail}");
    assert!(detail.contains("***@host.invalid"), "{detail}");
}

#[tokio::test]
async fn a_document_without_a_token_is_refused() {
    let transport = FakeTransport {
        status: 201,
        body: r#"{"expiresAt":"2026-09-19T00:00:00Z"}"#.to_owned(),
        seen: Arc::new(Mutex::new(Vec::new())),
    };
    let outcome = request_bootstrap_token(&transport, "12345", Duration::from_secs(30))
        .await
        .unwrap();
    let BootstrapOutcome::Refused { detail } = outcome else {
        panic!("the refusal is an outcome");
    };
    assert!(detail.contains("no token"), "{detail}");
}

#[tokio::test]
async fn an_oversized_document_is_refused() {
    let transport = FakeTransport {
        status: 201,
        body: "x".repeat(128 * 1024),
        seen: Arc::new(Mutex::new(Vec::new())),
    };
    let outcome = request_bootstrap_token(&transport, "12345", Duration::from_secs(30))
        .await
        .unwrap();
    let BootstrapOutcome::Refused { detail } = outcome else {
        panic!("the refusal is an outcome");
    };
    assert!(detail.contains("exceeds its bound"), "{detail}");
}
