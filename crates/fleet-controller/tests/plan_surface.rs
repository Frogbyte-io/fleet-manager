//! The plan surface (FM-407, ADR 0013) over the real router and stores:
//! plan a machine, apply by plan id, and refuse a stale or forged id.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_application::skills::{SkillsAvailability, SkillsPort as _, SkillsSnapshot};
use fleet_application::source::{ActiveRevision, DesiredResourceRecord, SourcePort as _};
use fleet_core::EndpointKind;
use fleet_storage_sqlite::{MachineRepository, SkillsRepository, SourceRepository, Store};
use tower::ServiceExt as _;

struct Harness {
    _dir: tempfile::TempDir,
    store: Store,
    state: Arc<ApiState>,
    machine_id: String,
    endpoint_id: String,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    let machine = MachineRepository::new(pool.clone())
        .register(&RegisterMachine {
            name: "box".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "ops@box.lan:22".to_owned(),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let audit = || Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone()));
    let state = Arc::new(ApiState {
        operations: Arc::new(Operations::new(
            Arc::new(fleet_storage_sqlite::OperationRepository::new(pool.clone())),
            audit(),
        )),
        machines: Some(Arc::new(fleet_application::machine::Machines::new(
            Arc::new(MachineRepository::new(pool.clone())),
            audit(),
        ))),
        planning: Some(Arc::new(fleet_controller::compose_planning(&pool))),
        authorizer: Arc::new(fleet_auth::LanAllowAllAuthorizer),
        ..ApiState::for_document()
    });
    Harness {
        _dir: dir,
        store,
        state,
        endpoint_id: machine.endpoints[0].id.clone(),
        machine_id: machine.id,
    }
}

impl Harness {
    async fn call(
        &self,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        self.send("POST", path, body, self.state.clone()).await
    }

    async fn get(&self, path: &str) -> (StatusCode, serde_json::Value) {
        self.send("GET", path, None, self.state.clone()).await
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
        state: Arc<ApiState>,
    ) -> (StatusCode, serde_json::Value) {
        let app = router(state).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        }));
        let request = Request::builder()
            .method(method)
            .uri(format!("{API_BASE_PATH}{path}"))
            .header(
                CORRELATION_ID_HEADER,
                "01900000-0000-7000-8000-000000000000",
            )
            .header("content-type", "application/json")
            .body(if method == "GET" {
                Body::empty()
            } else {
                Body::from(body.unwrap_or(serde_json::json!({})).to_string())
            })
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn activate(&self, sha: &str) {
        let source = SourceRepository::new(self.store.pool().clone());
        let revision = ActiveRevision {
            commit_sha: sha.to_owned(),
            content_digest: format!("digest-{sha}"),
        };
        source
            .record_valid_revision(
                &revision,
                &[DesiredResourceRecord {
                    kind: "SkillPreset".to_owned(),
                    id: "p-db".to_owned(),
                    name: "p-db".to_owned(),
                    spec: serde_json::json!({"skillId": "db", "scope": {"type": "all"}, "deployTo": ["codex"], "denyAgents": []}),
                }],
            )
            .await
            .unwrap();
        source.activate_serialized(&revision).await.unwrap();
    }

    async fn observe_fresh_skills(&self) {
        SkillsRepository::new(self.store.pool().clone())
            .record(&SkillsSnapshot {
                machine_id: self.machine_id.clone(),
                availability: SkillsAvailability::Available,
                cli_version: None,
                data: serde_json::json!({"skills": []}),
                update_check: "complete".to_owned(),
                observed_at: fleet_core::SystemClock::now_unix_millis(),
            })
            .await
            .unwrap();
    }

    fn apply_body(&self) -> serde_json::Value {
        serde_json::json!({
            "endpointId": self.endpoint_id,
            "auth": {"type": "agent"},
            "approvals": [{"actionOrder": 1, "kind": "skills.deploy"}],
        })
    }
}

#[tokio::test]
async fn planning_needs_an_active_revision_and_a_known_machine() {
    let harness = harness().await;
    let (status, body) = harness
        .call(&format!("/machines/{}/plans", harness.machine_id), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "no_active_revision");
    harness.activate("aaa").await;
    let (status, _) = harness.call("/machines/no-such-machine/plans", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_plan_is_applied_by_id_with_the_controllers_own_actions() {
    let harness = harness().await;
    harness.activate("aaa").await;
    harness.observe_fresh_skills().await;
    let (status, planned) = harness
        .call(&format!("/machines/{}/plans", harness.machine_id), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{planned}");
    let plan = &planned["data"];
    assert_eq!(plan["revision"]["commitSha"], "aaa");
    assert_eq!(plan["actions"][0]["kind"], "skills.deploy");
    assert_eq!(plan["actions"][0]["requiresApproval"], true);
    assert_eq!(
        plan["actions"][0]["difference"]["identity"],
        "skill:db/codex"
    );
    let plan_id = plan["planId"].as_str().unwrap();

    let (status, accepted) = harness
        .call(
            &format!("/machines/{}/plans/{plan_id}/apply", harness.machine_id),
            Some(harness.apply_body()),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    assert_eq!(accepted["data"]["kind"], "apply.workflow");
    let payload = sqlx::query_scalar::<_, String>(
        "SELECT payload_json FROM operations WHERE kind = 'apply.workflow'",
    )
    .fetch_one(harness.store.pool())
    .await
    .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        payload["planId"], plan_id,
        "approvals bind to the content digest"
    );
    assert_eq!(
        payload["actions"][0]["difference"]["identity"],
        "skill:db/codex"
    );
    assert_eq!(payload["approvals"][0]["planId"], plan_id);
}

#[tokio::test]
async fn a_forged_or_stale_plan_id_is_refused() {
    let harness = harness().await;
    harness.activate("aaa").await;
    harness.observe_fresh_skills().await;
    let (_, planned) = harness
        .call(&format!("/machines/{}/plans", harness.machine_id), None)
        .await;
    let reviewed = planned["data"]["planId"].as_str().unwrap().to_owned();

    let (status, body) = harness
        .call(
            &format!("/machines/{}/plans/forged/apply", harness.machine_id),
            Some(harness.apply_body()),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "stale_plan");

    // A new revision changes the plan: the reviewed id no longer applies.
    harness.activate("bbb").await;
    let (status, body) = harness
        .call(
            &format!("/machines/{}/plans/{reviewed}/apply", harness.machine_id),
            Some(harness.apply_body()),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "stale_plan");
    let created: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM operations WHERE kind = 'apply.workflow'")
            .fetch_one(harness.store.pool())
            .await
            .unwrap();
    assert_eq!(created, 0, "a refused plan starts nothing");
}

#[tokio::test]
async fn an_empty_plan_has_nothing_to_apply() {
    let harness = harness().await;
    // The revision holds no presets and the built-in is not seeded.
    let source = SourceRepository::new(harness.store.pool().clone());
    let revision = ActiveRevision {
        commit_sha: "aaa".to_owned(),
        content_digest: "d".to_owned(),
    };
    source.record_valid_revision(&revision, &[]).await.unwrap();
    source.activate_serialized(&revision).await.unwrap();
    harness.observe_fresh_skills().await;
    let (_, planned) = harness
        .call(&format!("/machines/{}/plans", harness.machine_id), None)
        .await;
    assert!(planned["data"]["actions"].as_array().unwrap().is_empty());
    let plan_id = planned["data"]["planId"].as_str().unwrap();
    let (status, body) = harness
        .call(
            &format!("/machines/{}/plans/{plan_id}/apply", harness.machine_id),
            Some(harness.apply_body()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[derive(Debug)]
struct DenyAll;
impl fleet_application::authz::Authorizer for DenyAll {
    fn decide(
        &self,
        _request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        fleet_application::authz::Decision::deny(
            fleet_application::authz::ReasonId::UnknownPrincipal,
        )
    }
}

fn entry<'a>(page: &'a serde_json::Value, machine_id: &str) -> &'a serde_json::Value {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["machineId"] == machine_id)
        .expect("the machine is listed")
}

#[tokio::test]
async fn drift_says_no_revision_before_anything_is_active() {
    let harness = harness().await;
    let (status, page) = harness.get("/desired/drift").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let mine = entry(&page, &harness.machine_id);
    assert_eq!(mine["status"], "no_revision");
    assert_eq!(mine["counts"]["missing"], 0);
    assert!(mine["revision"].is_null());
}

#[tokio::test]
async fn drift_lists_missing_extra_and_unknown_and_omits_what_is_in_sync() {
    let harness = harness().await;
    harness.activate("aaa").await;

    // Nothing observed yet: the desired skill is unknown, never clean.
    let (_, before) = harness
        .get(&format!("/machines/{}/drift", harness.machine_id))
        .await;
    let unknown = &before["data"];
    assert_eq!(unknown["status"], "computed");
    assert_eq!(unknown["revision"]["commitSha"], "aaa");
    assert_eq!(unknown["counts"]["unknown"], 1);
    assert_eq!(unknown["counts"]["missing"], 0);

    harness.observe_fresh_skills().await;
    let (_, missing) = harness
        .get(&format!("/machines/{}/drift", harness.machine_id))
        .await;
    assert_eq!(missing["data"]["counts"]["missing"], 1);
    assert_eq!(
        missing["data"]["differences"][0]["identity"],
        "skill:db/codex"
    );
    assert_eq!(missing["data"]["differences"][0]["state"], "missing");

    SkillsRepository::new(harness.store.pool().clone())
        .record(&SkillsSnapshot {
            machine_id: harness.machine_id.clone(),
            availability: SkillsAvailability::Available,
            cli_version: None,
            data: serde_json::json!({"skills": [{"id": "db", "deployedTo": ["codex"]}]}),
            update_check: "complete".to_owned(),
            observed_at: fleet_core::SystemClock::now_unix_millis(),
        })
        .await
        .unwrap();
    let (_, clean) = harness
        .get(&format!("/machines/{}/drift", harness.machine_id))
        .await;
    let counts = &clean["data"]["counts"];
    assert!(
        ["missing", "changed", "extra", "unknown", "unsupported"]
            .iter()
            .all(|state| counts[state] == 0),
        "{clean}"
    );
    assert!(clean["data"]["differences"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn fleet_drift_is_paged_and_isolates_each_machine() {
    let harness = harness().await;
    harness.activate("aaa").await;
    MachineRepository::new(harness.store.pool().clone())
        .register(&RegisterMachine {
            name: "second".to_owned(),
            description: String::new(),
            endpoints: vec![],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let (_, first) = harness.get("/desired/drift?limit=1").await;
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    let cursor = first["page"]["nextCursor"]
        .as_str()
        .expect("another machine follows");
    let (_, second) = harness
        .get(&format!("/desired/drift?limit=1&cursor={cursor}"))
        .await;
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert!(second["page"]["nextCursor"].is_null());
}

#[tokio::test]
async fn drift_requires_skills_read_for_each_machine() {
    let harness = harness().await;
    harness.activate("aaa").await;
    let denied = Arc::new(ApiState {
        authorizer: Arc::new(DenyAll),
        ..(*harness.state).clone()
    });
    let (status, page) = harness
        .send("GET", "/desired/drift", None, denied.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        page["items"].as_array().unwrap().is_empty(),
        "unreadable machines are omitted"
    );
    let (status, _) = harness
        .send(
            "GET",
            &format!("/machines/{}/drift", harness.machine_id),
            None,
            denied,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = harness.get("/machines/no-such-machine/drift").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
