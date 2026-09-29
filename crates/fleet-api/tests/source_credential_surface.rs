//! The desired-source credential surface (FM-412): a credential value is
//! write-only, the source names it by reference, and neither the responses
//! nor the audit trail ever carry the value.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::source::{
    ActiveRevision, ActiveSummary, DesiredResourceRecord, DesiredSource, GitCredentialStore,
    SourcePort,
};
use std::sync::{Arc, Mutex};
use tower::ServiceExt as _;

const SECRET: &str = "ghp_API_SURFACE_SECRET_VALUE";

#[derive(Debug)]
struct Permit;
impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// Denies secret writes only.
#[derive(Debug)]
struct NoSecretWrite;
impl Authorizer for NoSecretWrite {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == Permission::SecretWrite {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

#[derive(Debug, Default)]
struct Audit {
    seen: Mutex<Vec<String>>,
}
#[async_trait::async_trait]
impl fleet_application::operation::AuditPort for Audit {
    async fn record_intent(
        &self,
        intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
        self.seen.lock().unwrap().push(format!("{intent:?}"));
        Ok(())
    }
    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: fleet_application::audit::AuditOutcome,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct Port {
    config: Mutex<Option<(String, Option<String>)>>,
}
#[async_trait::async_trait]
impl SourcePort for Port {
    async fn active_revision(&self) -> Result<Option<ActiveRevision>, String> {
        Ok(None)
    }
    async fn prior_revisions(&self) -> Result<Vec<ActiveRevision>, String> {
        Ok(Vec::new())
    }
    async fn record_valid_revision(
        &self,
        _revision: &ActiveRevision,
        _resources: &[DesiredResourceRecord],
    ) -> Result<(), String> {
        Ok(())
    }
    async fn remote(&self) -> Result<Option<String>, String> {
        Ok(self.config.lock().unwrap().as_ref().map(|c| c.0.clone()))
    }
    async fn credential_ref(&self) -> Result<Option<String>, String> {
        Ok(self
            .config
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|c| c.1.clone()))
    }
    async fn set_remote(&self, remote: &str, credential_ref: Option<&str>) -> Result<(), String> {
        *self.config.lock().unwrap() = Some((remote.to_owned(), credential_ref.map(str::to_owned)));
        Ok(())
    }
    async fn snapshot_held(&self, _revision: &ActiveRevision) -> Result<bool, String> {
        Ok(false)
    }
    async fn activate_serialized(
        &self,
        revision: &ActiveRevision,
    ) -> Result<ActiveRevision, String> {
        Ok(revision.clone())
    }
    async fn active_summary(&self) -> Result<Option<ActiveSummary>, String> {
        Ok(None)
    }
    async fn active_resources(
        &self,
        _kind: Option<&str>,
        _after: Option<&str>,
        _limit: i64,
    ) -> Result<Vec<DesiredResourceRecord>, String> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Default)]
struct Credentials {
    stored: Mutex<Vec<(String, String)>>,
}
#[async_trait::async_trait]
impl GitCredentialStore for Credentials {
    async fn create(&self, value: &str) -> Result<String, String> {
        let mut stored = self.stored.lock().unwrap();
        let id = format!("cred-{}", stored.len() + 1);
        stored.push((id.clone(), value.to_owned()));
        Ok(id)
    }
    async fn exists(&self, reference: &str) -> Result<bool, String> {
        Ok(self
            .stored
            .lock()
            .unwrap()
            .iter()
            .any(|(id, _)| id == reference))
    }
    async fn resolve(&self, reference: &str) -> Result<Option<String>, String> {
        Ok(self
            .stored
            .lock()
            .unwrap()
            .iter()
            .find(|(id, _)| id == reference)
            .map(|(_, value)| value.clone()))
    }
}

fn state(authorizer: Arc<dyn Authorizer>, audit: Arc<Audit>) -> Arc<ApiState> {
    Arc::new(ApiState {
        authorizer,
        desired: Some(Arc::new(
            DesiredSource::new(Arc::new(Port::default()), audit)
                .with_credentials(Arc::new(Credentials::default())),
        )),
        ..ApiState::for_document()
    })
}

async fn call(
    state: &Arc<ApiState>,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let router = router(state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }));
    let request = Request::builder()
        .method(method)
        .uri(format!("{API_BASE_PATH}{path}"))
        .header("content-type", "application/json")
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        )
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn a_stored_credential_is_referenced_by_the_source_and_never_echoed() {
    let audit = Arc::new(Audit::default());
    let state = state(Arc::new(Permit), audit.clone());
    let (status, body) = call(
        &state,
        "POST",
        "/desired/source/credential",
        Some(serde_json::json!({ "value": SECRET })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(!body.contains(SECRET));
    let reference =
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["data"]["credentialRef"]
            .as_str()
            .unwrap()
            .to_owned();

    let (status, body) = call(
        &state,
        "PUT",
        "/desired/source",
        Some(serde_json::json!({ "remote": "https://example.test/fleet.git", "credentialRef": reference })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(&state, "GET", "/desired/source", None).await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["data"]["credentialRef"], reference.as_str());
    assert_eq!(value["data"]["remote"], "https://example.test/fleet.git");
    assert!(!body.contains(SECRET));

    // Neither audit intent carries the value; the source-configured one
    // carries the reference id.
    let seen = audit.seen.lock().unwrap().join("\n");
    assert!(!seen.contains(SECRET), "{seen}");
    assert!(seen.contains(&reference), "{seen}");

    // Omitting the reference clears it.
    let (_, _) = call(
        &state,
        "PUT",
        "/desired/source",
        Some(serde_json::json!({ "remote": "https://example.test/fleet.git" })),
    )
    .await;
    let (_, body) = call(&state, "GET", "/desired/source", None).await;
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(value["data"]["credentialRef"].is_null());
}

#[tokio::test]
async fn an_unknown_reference_is_refused() {
    let state = state(Arc::new(Permit), Arc::new(Audit::default()));
    let (status, body) = call(
        &state,
        "PUT",
        "/desired/source",
        Some(
            serde_json::json!({ "remote": "https://example.test/f.git", "credentialRef": "nope" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn storing_a_credential_needs_the_secret_write_permission() {
    let audit = Arc::new(Audit::default());
    let state = state(Arc::new(NoSecretWrite), audit.clone());
    let (status, body) = call(
        &state,
        "POST",
        "/desired/source/credential",
        Some(serde_json::json!({ "value": SECRET })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!body.contains(SECRET));
    assert!(audit.seen.lock().unwrap().is_empty());
}
