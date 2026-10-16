//! The domain observation endpoints (FM-1020) through the real router and
//! store, with stubbed RDAP and DNS and a stub directory of domain entries:
//! refresh records an observation and an audit intent, reads compare it
//! with the entry, and a caller without `registry.observe` changes nothing.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::operation::Operations;
use fleet_application::project::ProjectUseCaseError;
use fleet_application::registry::enrich::{
    DnsFailure, DnsKind, DnsPort, DomainDirectory, DomainEnricher, DomainEntry, EnrichSettings,
    RdapAnswer, RdapFailure, RdapPort,
};
use fleet_storage_sqlite::{ObservationRepository, Store};
use serde_json::{Value, json};
use tower::ServiceExt as _;

#[derive(Debug)]
struct Directory(Vec<DomainEntry>);

#[async_trait]
impl DomainDirectory for Directory {
    async fn get(
        &self,
        _authorizer: &dyn Authorizer,
        _principal_id: &str,
        key: &str,
    ) -> Result<DomainEntry, ProjectUseCaseError> {
        self.0
            .iter()
            .find(|entry| entry.key == key)
            .cloned()
            .ok_or(ProjectUseCaseError::NotFound {
                what: "registry entry".to_owned(),
            })
    }
    async fn list(
        &self,
        _authorizer: &dyn Authorizer,
        _principal_id: &str,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DomainEntry>, ProjectUseCaseError> {
        Ok(self
            .0
            .iter()
            .filter(|entry| after.is_none_or(|after| entry.key.as_str() > after))
            .take(usize::try_from(limit).unwrap())
            .cloned()
            .collect())
    }
}

#[derive(Debug)]
struct Rdap;

#[async_trait]
impl RdapPort for Rdap {
    async fn server_for(&self, fqdn: &str) -> Result<Option<String>, String> {
        Ok((!fqdn.ends_with(".de")).then(|| "https://rdap.example/".to_owned()))
    }
    async fn lookup(&self, _server: &str, _fqdn: &str) -> Result<RdapAnswer, RdapFailure> {
        Ok(RdapAnswer {
            registrar: Some("Namecheap, Inc.".to_owned()),
            expires: Some("2030-01-01T00:00:00Z".to_owned()),
            statuses: vec![],
            nameservers: vec![],
        })
    }
}

#[derive(Debug)]
struct Dns;

#[async_trait]
impl DnsPort for Dns {
    async fn resolve(&self, _name: &str, kind: DnsKind) -> Result<Vec<String>, DnsFailure> {
        Ok(match kind {
            DnsKind::Ns => vec!["a.ns.cloudflare.com".to_owned()],
            _ => vec![],
        })
    }
}

#[derive(Debug)]
struct Without(Permission);
impl Authorizer for Without {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == self.0 {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

struct Harness {
    state: Arc<ApiState>,
    store: Store,
}

async fn harness(dir: &Path, authorizer: Arc<dyn Authorizer>) -> Harness {
    let store = Store::open(&dir.join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    let enricher = DomainEnricher::new(
        Arc::new(Directory(vec![
            DomainEntry {
                key: "example.com".to_owned(),
                fields: json!({"fqdn": "example.com", "registrar": "Porkbun", "dnsHost": "Cloudflare"}),
            },
            DomainEntry {
                key: "lapsing.com".to_owned(),
                fields: json!({"fqdn": "lapsing.com", "expires": "2000-01-01", "autoRenew": false}),
            },
            DomainEntry {
                key: "example.de".to_owned(),
                fields: json!({"fqdn": "example.de"}),
            },
        ])),
        Arc::new(Rdap),
        Arc::new(Dns),
        Arc::new(ObservationRepository::new(pool.clone())),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
        EnrichSettings {
            rdap_gap: std::time::Duration::ZERO,
            ..EnrichSettings::default()
        },
    );
    let desired =
        fleet_controller::compose_desired_source(&pool).with_domain_enricher(Arc::new(enricher));
    let operations = Arc::new(Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(pool.clone())),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool)),
    ));
    Harness {
        state: Arc::new(ApiState {
            operations,
            desired: Some(Arc::new(desired)),
            authorizer,
            ..ApiState::for_document()
        }),
        store,
    }
}

impl Harness {
    async fn call(&self, method: &str, path: &str) -> (StatusCode, Value) {
        let app = router(self.state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        }));
        let request = Request::builder()
            .method(method)
            .uri(format!("{API_BASE_PATH}{path}"))
            .header(
                CORRELATION_ID_HEADER,
                "01900000-0000-7000-8000-000000000000",
            )
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn observe_audit_events(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE action = 'registry.observe'")
            .fetch_one(self.store.pool())
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn refresh_records_an_observation_that_reads_compare_with_the_entry() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path(), Arc::new(fleet_auth::LanAllowAllAuthorizer)).await;

    // Before the first lookup there is nothing observed.
    let (status, body) = harness
        .call("GET", "/registry/entries/domain/example.com/observations")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["observation"], Value::Null);

    let (status, body) = harness
        .call(
            "POST",
            "/registry/entries/domain/example.com/observations/refresh",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["observation"]["rdap"]["status"], "ok");
    assert_eq!(body["observation"]["rdap"]["expires"], "2030-01-01");
    assert_eq!(
        body["observation"]["dns"]["apex"]["ns"],
        json!(["a.ns.cloudflare.com"])
    );
    let codes: Vec<&str> = body["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, ["registrar_mismatch"]);
    assert_eq!(body["suggestion"][0]["field"], "registrar");
    assert_eq!(body["suggestion"][0]["value"], "Namecheap, Inc.");
    assert_eq!(harness.observe_audit_events().await, 1);

    // The stored observation is served by the read.
    let (_, again) = harness
        .call("GET", "/registry/entries/domain/example.com/observations")
        .await;
    assert_eq!(again["observation"]["rdap"]["registrar"], "Namecheap, Inc.");
}

#[tokio::test]
async fn a_tld_without_rdap_is_unavailable_and_the_attention_list_names_lapsing_domains() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path(), Arc::new(fleet_auth::LanAllowAllAuthorizer)).await;
    let (status, body) = harness
        .call(
            "POST",
            "/registry/entries/domain/example.de/observations/refresh",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["observation"]["rdap"]["status"], "unavailable");

    let (status, page) = harness
        .call("GET", "/registry/observations?attention=true")
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["key"], "lapsing.com");
    assert_eq!(items[0]["warnings"][0]["code"], "auto_renew_off_expiring");
    assert_eq!(items[0]["warnings"][0]["severity"], "err");

    let (_, all) = harness.call("GET", "/registry/observations?limit=2").await;
    assert_eq!(all["items"].as_array().unwrap().len(), 2);
    assert_eq!(all["page"]["nextCursor"], "domain/lapsing.com");
}

#[tokio::test]
async fn only_domain_entries_are_observed() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path(), Arc::new(fleet_auth::LanAllowAllAuthorizer)).await;
    let (status, _) = harness
        .call(
            "POST",
            "/registry/entries/service/aptabase/observations/refresh",
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = harness
        .call("GET", "/registry/entries/domain/nope.com/observations")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_caller_without_registry_observe_changes_nothing_but_may_still_read() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path(), Arc::new(Without(Permission::RegistryObserve))).await;
    let (status, _) = harness
        .call(
            "POST",
            "/registry/entries/domain/example.com/observations/refresh",
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(harness.observe_audit_events().await, 0);
    let (_, body) = harness
        .call("GET", "/registry/entries/domain/example.com/observations")
        .await;
    assert_eq!(body["observation"], Value::Null);
}
