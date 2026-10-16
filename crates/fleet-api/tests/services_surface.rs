//! The running-services surface (FM-1031): paging by cursor, filters, the
//! detail route, and the not-wired answer, over fake input ports.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{ActingPrincipal, Authorizer};
use fleet_application::coolify::{
    ClassObservation, CoolifyApplication, CoolifyObservationPort, CoolifySnapshot,
};
use fleet_application::external_accounts::{
    ExternalAccount, ExternalAccountPort, NewExternalAccount, StoredProbe,
};
use fleet_application::services::{
    InputError, NoContainerObservations, RunningServices, ServiceMachine, ServiceMachines,
};
use fleet_core::{ExternalProviderKind, SystemClock};
use tower::ServiceExt as _;

#[derive(Debug)]
struct Accounts;

#[async_trait]
impl ExternalAccountPort for Accounts {
    async fn create(&self, _: &NewExternalAccount) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn get(&self, _: &str) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn list(&self) -> Result<Vec<ExternalAccount>, String> {
        Ok(vec![ExternalAccount {
            id: "acc1".to_owned(),
            kind: ExternalProviderKind::Coolify,
            label: "prod".to_owned(),
            base_url: "https://coolify.example.test".to_owned(),
            scope_id: None,
            notes: String::new(),
            last_probe: None,
            created_at: 0,
            updated_at: 0,
        }])
    }
    async fn update(
        &self,
        _: &str,
        _: &NewExternalAccount,
        _: bool,
    ) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn record_probe(
        &self,
        _: &str,
        _: Option<&StoredProbe>,
    ) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn delete(&self, _: &str) -> Result<(), String> {
        Err("unsupported".to_owned())
    }
}

fn fresh<T>(now: i64, items: Vec<T>) -> ClassObservation<T> {
    ClassObservation {
        attempted_at: now,
        observed_at: Some(now),
        items,
        ..ClassObservation::default()
    }
}

#[derive(Debug)]
struct Observations;

#[async_trait]
impl CoolifyObservationPort for Observations {
    async fn load(&self, _: &str) -> Result<Option<(CoolifySnapshot, i64)>, String> {
        let now = SystemClock::now_unix_millis();
        let apps = ["a", "b", "c", "d", "e"]
            .into_iter()
            .map(|id| CoolifyApplication {
                uuid: id.to_owned(),
                name: format!("app-{id}"),
                status: "running:healthy".to_owned(),
                fqdns: vec![format!("https://{id}.example.test")],
                ..CoolifyApplication::default()
            })
            .collect();
        Ok(Some((
            CoolifySnapshot {
                servers: fresh(now, Vec::new()),
                projects: fresh(now, Vec::new()),
                applications: fresh(now, apps),
                services: fresh(now, Vec::new()),
                databases: fresh(now, Vec::new()),
                deployments: fresh(now, Vec::new()),
                ..CoolifySnapshot::default()
            },
            now,
        )))
    }
    async fn save(&self, _: &str, _: &CoolifySnapshot, _: i64, _: i64) -> Result<bool, String> {
        Ok(false)
    }
}

#[derive(Debug)]
struct NoMachines;

#[async_trait]
impl ServiceMachines for NoMachines {
    async fn machines(
        &self,
        _: &dyn Authorizer,
        _: &ActingPrincipal,
        _: i64,
    ) -> Result<Vec<ServiceMachine>, InputError> {
        Ok(Vec::new())
    }
}

fn wired() -> Arc<RunningServices> {
    Arc::new(RunningServices::new(
        Arc::new(Accounts),
        Arc::new(Observations),
        Arc::new(NoMachines),
        Arc::new(NoContainerObservations),
        None,
    ))
}

async fn get(
    services: Option<Arc<RunningServices>>,
    path: &str,
) -> (StatusCode, serde_json::Value) {
    let mut app = router(Arc::new(ApiState::for_document())).layer(axum::Extension(
        fleet_api::ActingPrincipal {
            id: "anonymous-lan-admin".to_owned(),
        },
    ));
    if let Some(services) = services {
        app = app.layer(axum::Extension(services));
    }
    let request = Request::builder()
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
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn ids(page: &serde_json::Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn the_list_pages_by_cursor_and_reports_coverage() {
    let (status, first) = get(Some(wired()), "/services?limit=2").await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(ids(&first), ["coolify:acc1:a", "coolify:acc1:b"]);
    assert_eq!(first["page"]["limit"], 2);
    assert_eq!(first["page"]["nextCursor"], "coolify:acc1:b");
    assert_eq!(first["coverage"]["containers"]["state"], "not_configured");
    assert_eq!(first["coverage"]["machines"]["state"], "available");

    let (_, second) = get(Some(wired()), "/services?limit=2&cursor=coolify%3Aacc1%3Ab").await;
    assert_eq!(ids(&second), ["coolify:acc1:c", "coolify:acc1:d"]);
    let (_, last) = get(Some(wired()), "/services?limit=2&cursor=coolify%3Aacc1%3Ad").await;
    assert_eq!(ids(&last), ["coolify:acc1:e"]);
    assert!(last["page"]["nextCursor"].is_null());
}

#[tokio::test]
async fn filters_are_validated_and_applied() {
    let (status, body) = get(Some(wired()), "/services?source=bogus").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, _) = get(Some(wired()), "/services?q=").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, docker) = get(Some(wired()), "/services?source=docker").await;
    assert!(ids(&docker).is_empty());
    let (_, found) = get(Some(wired()), "/services?q=C.EXAMPLE").await;
    assert_eq!(ids(&found), ["coolify:acc1:c"]);
}

#[tokio::test]
async fn the_detail_route_finds_one_or_says_not_found() {
    let (status, one) = get(Some(wired()), "/services/coolify%3Aacc1%3Ac").await;
    assert_eq!(status, StatusCode::OK, "{one}");
    assert_eq!(one["data"]["service"]["name"], "app-c");
    assert_eq!(one["data"]["service"]["serverBasis"], "unknown");
    assert_eq!(one["data"]["coverage"]["coolify"]["state"], "available");
    let (status, _) = get(Some(wired()), "/services/coolify%3Aacc1%3Azzz").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_unwired_surface_answers_503() {
    let (status, body) = get(None, "/services").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}
