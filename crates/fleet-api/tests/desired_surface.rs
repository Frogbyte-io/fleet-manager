//! The desired-state read surface (FM-404): the active revision and its
//! resources are served with the standard envelope, paged and filtered,
//! and a denied caller learns nothing.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, ReasonId};
use fleet_application::source::{
    ActiveRevision, ActiveSummary, DesiredResourceRecord, DesiredSource, SourcePort,
};
use std::sync::Arc;
use tower::ServiceExt as _;

#[derive(Debug)]
struct Permit;
impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[derive(Debug)]
struct Deny;
impl Authorizer for Deny {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

#[derive(Debug)]
struct NoAudit;
#[async_trait::async_trait]
impl fleet_application::operation::AuditPort for NoAudit {
    async fn record_intent(
        &self,
        _intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
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

/// An in-memory source: `active` decides whether anything is served.
#[derive(Debug)]
struct Source {
    active: bool,
    snapshot: bool,
}

fn resource(kind: &str, id: &str) -> DesiredResourceRecord {
    DesiredResourceRecord {
        kind: kind.to_owned(),
        id: id.to_owned(),
        name: format!("{id}-name"),
        spec: serde_json::json!({ "note": id }),
    }
}

#[async_trait::async_trait]
impl SourcePort for Source {
    async fn active_revision(&self) -> Result<Option<ActiveRevision>, String> {
        unimplemented!("the read surface never asks")
    }
    async fn prior_revisions(&self) -> Result<Vec<ActiveRevision>, String> {
        unimplemented!("the read surface never asks")
    }
    async fn record_valid_revision(
        &self,
        _revision: &ActiveRevision,
        _resources: &[DesiredResourceRecord],
    ) -> Result<(), String> {
        unimplemented!("the read surface never writes")
    }
    async fn remote(&self) -> Result<Option<String>, String> {
        unimplemented!("the read surface never asks")
    }
    async fn set_remote(&self, _remote: &str) -> Result<(), String> {
        unimplemented!("the read surface never writes")
    }
    async fn snapshot_held(&self, _revision: &ActiveRevision) -> Result<bool, String> {
        unimplemented!("the read surface never asks")
    }
    async fn activate_serialized(
        &self,
        _revision: &ActiveRevision,
    ) -> Result<ActiveRevision, String> {
        unimplemented!("the read surface never writes")
    }
    async fn active_summary(&self) -> Result<Option<ActiveSummary>, String> {
        Ok(self.active.then(|| ActiveSummary {
            revision: ActiveRevision {
                commit_sha: "abc".to_owned(),
                content_digest: "d1".to_owned(),
            },
            activated_at: 42,
            snapshot_held: self.snapshot,
            kind_counts: [("Machine".to_owned(), 2), ("Profile".to_owned(), 1)]
                .into_iter()
                .collect(),
        }))
    }
    async fn active_resources(
        &self,
        kind: Option<&str>,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DesiredResourceRecord>, String> {
        let mut all = vec![
            resource("Machine", "m-1"),
            resource("Machine", "m-2"),
            resource("Profile", "p-1"),
        ];
        all.retain(|r| {
            kind.is_none_or(|kind| r.kind == kind)
                && after.is_none_or(|after| r.id.as_str() > after)
        });
        all.truncate(usize::try_from(limit).unwrap());
        Ok(all)
    }
}

fn state(authorizer: Arc<dyn Authorizer>, source: Source) -> Arc<ApiState> {
    Arc::new(ApiState {
        authorizer,
        desired: Some(Arc::new(DesiredSource::new(
            Arc::new(source),
            Arc::new(NoAudit),
        ))),
        ..ApiState::for_document()
    })
}

async fn get(state: Arc<ApiState>, path: &str) -> (StatusCode, serde_json::Value) {
    let router = router(state).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }));
    let request = Request::builder()
        .uri(format!("{API_BASE_PATH}{path}"))
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        )
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

#[tokio::test]
async fn the_active_revision_reports_what_its_snapshot_holds() {
    let state = state(
        Arc::new(Permit),
        Source {
            active: true,
            snapshot: true,
        },
    );
    let (status, body) = get(state, "/desired/revision").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let active = &body["data"]["active"];
    assert_eq!(active["commitSha"], "abc");
    assert_eq!(active["contentDigest"], "d1");
    assert_eq!(active["activatedAt"], 42);
    assert_eq!(active["resourcesAvailable"], true);
    assert_eq!(active["resourceCounts"]["Machine"], 2);
}

#[tokio::test]
async fn no_active_revision_is_reported_as_null_not_as_an_error() {
    let state = state(
        Arc::new(Permit),
        Source {
            active: false,
            snapshot: false,
        },
    );
    let (status, body) = get(state, "/desired/revision").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["data"]["active"].is_null());
}

#[tokio::test]
async fn a_revision_without_a_snapshot_says_its_resources_are_unavailable() {
    let state = state(
        Arc::new(Permit),
        Source {
            active: true,
            snapshot: false,
        },
    );
    let (_, body) = get(state, "/desired/revision").await;
    assert_eq!(body["data"]["active"]["resourcesAvailable"], false);
}

#[tokio::test]
async fn resources_are_paged_by_identity_and_filterable_by_kind() {
    let state = state(
        Arc::new(Permit),
        Source {
            active: true,
            snapshot: true,
        },
    );
    let (status, first) = get(state.clone(), "/desired/resources?limit=2").await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    assert_eq!(first["page"]["nextCursor"], "m-2");
    assert_eq!(first["items"][0]["spec"]["note"], "m-1");
    let (_, second) = get(state.clone(), "/desired/resources?limit=2&cursor=m-2").await;
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert!(second["page"]["nextCursor"].is_null());
    let (_, machines) = get(state, "/desired/resources?kind=Machine").await;
    assert_eq!(machines["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn a_denied_caller_learns_nothing() {
    let state = state(
        Arc::new(Deny),
        Source {
            active: true,
            snapshot: true,
        },
    );
    let (status, body) = get(state.clone(), "/desired/revision").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.get("data").is_none());
    let (status, _) = get(state, "/desired/resources").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_unwired_controller_answers_with_the_standard_envelope() {
    let state = Arc::new(ApiState {
        authorizer: Arc::new(Permit),
        ..ApiState::for_document()
    });
    let (status, body) = get(state, "/desired/revision").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "desired_unavailable");
}
