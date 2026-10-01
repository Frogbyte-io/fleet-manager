//! The Proxmox task-history use case over fakes (FM-609): the UPID join
//! to Fleet operations, its authorization, the filters, and the
//! explicit-trust gate.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::machine::{
    Machine, MachineFilter, MachinePort, Machines, NewEndpoint, RegisterMachine,
};
use fleet_application::operation::{AuditPort, PortFailure};
use fleet_application::proxmox::tasks::{
    ProxmoxTaskHistoryPort, ProxmoxTaskLinkPort, ProxmoxTaskState, RawTask, RawTaskHistory,
    RawTaskQuery, TASKS_PER_NODE, TaskHistoryQuery,
};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccount, ProxmoxAccountPort, ProxmoxAccounts,
    ProxmoxCredentialStore, ProxmoxDiscoverPort, ProxmoxGuestDiscoverPort, ProxmoxSourceError,
    ProxmoxTrustProbe, ProxmoxUseCaseError, RawDiscovery, RawGuestDiscovery,
};
use fleet_core::{CapabilityFact, SensitiveString};

const NOW: i64 = 1_800_000_000_000;
const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";
const UPID_FLEET: &str = "UPID:pve:001A2B3C:05F5E100:68D83818:qmstart:101:fleet@pve!fleet-ops:";
const UPID_OUTSIDE: &str = "UPID:pve:001A2B00:05F5E000:68D836EC:qmshutdown:101:root@pam:";
const UPID_FAILED: &str = "UPID:pve:001A2900:05F5DE00:68D83624:qmclone:900:root@pam:";

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        id: "operator".to_owned(),
    }
}

/// Allows everything except the listed permissions.
#[derive(Debug, Default)]
struct AllowExcept(Vec<Permission>);

impl Authorizer for AllowExcept {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if self.0.contains(&request.action) {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

fn account(id: &str, fingerprint: Option<&str>) -> ProxmoxAccount {
    ProxmoxAccount {
        id: id.to_owned(),
        name: format!("pve-{id}"),
        host: "192.0.2.10".to_owned(),
        port: 8006,
        token_id: "fleet@pve!fleet-ops".to_owned(),
        fingerprint: fingerprint.map(str::to_owned),
        observed_fingerprint: fingerprint.map(str::to_owned),
        created_at: NOW,
    }
}

#[derive(Debug)]
struct FakeAccounts(Vec<ProxmoxAccount>);

#[async_trait]
impl ProxmoxAccountPort for FakeAccounts {
    async fn create(&self, _account: &NewProxmoxAccount) -> Result<ProxmoxAccount, String> {
        Err("unused".to_owned())
    }
    async fn get(&self, id: &str) -> Result<ProxmoxAccount, String> {
        self.0
            .iter()
            .find(|account| account.id == id)
            .cloned()
            .ok_or_else(|| format!("account {id} not found"))
    }
    async fn list(&self) -> Result<Vec<ProxmoxAccount>, String> {
        Ok(self.0.clone())
    }
    async fn set_fingerprint(
        &self,
        _id: &str,
        _fingerprint: Option<String>,
    ) -> Result<ProxmoxAccount, String> {
        Err("unused".to_owned())
    }
    async fn set_observed_fingerprint(
        &self,
        _id: &str,
        _fingerprint: Option<String>,
    ) -> Result<ProxmoxAccount, String> {
        Err("unused".to_owned())
    }
    async fn delete(&self, _id: &str) -> Result<(), String> {
        Err("unused".to_owned())
    }
}

#[derive(Debug)]
struct FakeCredentials;

#[async_trait]
impl ProxmoxCredentialStore for FakeCredentials {
    async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(Some("the-token-secret".to_owned()))
    }
    async fn store(&self, _account_id: &str, _secret: &str) -> Result<(), CredentialStoreError> {
        Ok(())
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        Ok(())
    }
}

/// The discovery, guest, and trust ports are never reached by the task
/// history.
#[derive(Debug)]
struct Unreached;

#[async_trait]
impl ProxmoxDiscoverPort for Unreached {
    async fn discover(
        &self,
        _account: &ProxmoxAccount,
        _secret: &SensitiveString,
    ) -> Result<RawDiscovery, ProxmoxSourceError> {
        panic!("the task history never discovers");
    }
}

#[async_trait]
impl ProxmoxGuestDiscoverPort for Unreached {
    async fn guest_discover(
        &self,
        _account: &ProxmoxAccount,
        _secret: &SensitiveString,
    ) -> Result<RawGuestDiscovery, ProxmoxSourceError> {
        panic!("the task history never discovers guests");
    }
}

#[async_trait]
impl ProxmoxTrustProbe for Unreached {
    async fn observe(&self, _host: &str, _port: u16) -> Result<String, ProxmoxSourceError> {
        panic!("the task history never probes trust");
    }
}

#[derive(Debug)]
struct NoAudit;

#[async_trait]
impl AuditPort for NoAudit {
    async fn record_intent(&self, _intent: &AuditIntent) -> Result<(), String> {
        panic!("a read writes no audit event");
    }
    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: AuditOutcome,
    ) -> Result<(), String> {
        panic!("a read writes no audit event");
    }
}

/// The machine surface is not part of the task history.
#[derive(Debug)]
struct NoMachines;

fn unused<T>() -> Result<T, PortFailure> {
    Err(PortFailure::Backend {
        detail: "unused in these tests".to_owned(),
    })
}

#[async_trait]
impl MachinePort for NoMachines {
    async fn register(&self, _registration: &RegisterMachine) -> Result<Machine, PortFailure> {
        unused()
    }
    async fn get(&self, _id: &str) -> Result<Machine, PortFailure> {
        unused()
    }
    async fn list(
        &self,
        _filter: &MachineFilter,
        _limit: u32,
    ) -> Result<Vec<Machine>, PortFailure> {
        unused()
    }
    async fn update(
        &self,
        _id: &str,
        _name: &str,
        _description: &str,
    ) -> Result<Machine, PortFailure> {
        unused()
    }
    async fn set_endpoints(
        &self,
        _id: &str,
        _endpoints: &[NewEndpoint],
    ) -> Result<Machine, PortFailure> {
        unused()
    }
    async fn add_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        unused()
    }
    async fn remove_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        unused()
    }
    async fn add_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        unused()
    }
    async fn remove_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        unused()
    }
    async fn record_snapshot(
        &self,
        _id: &str,
        _source: &str,
        _payload_json: &str,
        _collected_at: i64,
    ) -> Result<(), PortFailure> {
        unused()
    }
    async fn record_capabilities(
        &self,
        _id: &str,
        _facts: &[CapabilityFact],
    ) -> Result<(), PortFailure> {
        unused()
    }
    async fn delete(&self, _id: &str) -> Result<(), PortFailure> {
        unused()
    }
    async fn confirm_fingerprint(
        &self,
        _endpoint_id: &str,
        _fingerprint: &str,
        _confirmed_at: i64,
    ) -> Result<(), PortFailure> {
        unused()
    }
    async fn verified_fingerprint(
        &self,
        _endpoint_id: &str,
    ) -> Result<Option<String>, PortFailure> {
        unused()
    }
    async fn latest_inventory_revision(
        &self,
        _machine_id: &str,
    ) -> Result<Option<u64>, PortFailure> {
        unused()
    }
}

fn task(upid: &str, task_type: &str, state: ProxmoxTaskState, exit: Option<&str>) -> RawTask {
    RawTask {
        upid: upid.to_owned(),
        node: "pve".to_owned(),
        task_type: task_type.to_owned(),
        target_id: Some("101".to_owned()),
        user: "fleet@pve".to_owned(),
        token_id: Some("fleet-ops".to_owned()),
        started_at_seconds: 1_759_000_600,
        ended_at_seconds: (state != ProxmoxTaskState::Running).then_some(1_759_000_642),
        state,
        exit_status: exit.map(str::to_owned),
    }
}

/// The task source over a canned history, recording each query.
#[derive(Debug)]
struct FakeTasks {
    history: RawTaskHistory,
    queries: Mutex<Vec<(String, RawTaskQuery)>>,
}

impl FakeTasks {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            history: RawTaskHistory {
                version: "9.2.2".to_owned(),
                tasks: vec![
                    task(UPID_FLEET, "qmstart", ProxmoxTaskState::Running, None),
                    task(UPID_OUTSIDE, "qmshutdown", ProxmoxTaskState::Ok, Some("OK")),
                    task(
                        UPID_FAILED,
                        "qmclone",
                        ProxmoxTaskState::Error,
                        Some("clone failed"),
                    ),
                ],
                warnings: vec!["node pve2 tasks are unavailable: the connection failed".to_owned()],
            },
            queries: Mutex::new(Vec::new()),
        })
    }

    fn queries(&self) -> Vec<(String, RawTaskQuery)> {
        self.queries.lock().unwrap().clone()
    }
}

#[async_trait]
impl ProxmoxTaskHistoryPort for FakeTasks {
    async fn task_history(
        &self,
        account: &ProxmoxAccount,
        secret: &SensitiveString,
        query: &RawTaskQuery,
    ) -> Result<RawTaskHistory, ProxmoxSourceError> {
        assert_eq!(secret.expose(), "the-token-secret");
        self.queries
            .lock()
            .unwrap()
            .push((account.id.clone(), query.clone()));
        Ok(self.history.clone())
    }
}

/// The link store over a map keyed by (account, UPID).
#[derive(Debug, Default)]
struct FakeLinks {
    links: Mutex<HashMap<(String, String), String>>,
    lookups: Mutex<usize>,
}

#[async_trait]
impl ProxmoxTaskLinkPort for FakeLinks {
    async fn record(
        &self,
        account_id: &str,
        upid: &str,
        operation_id: &str,
    ) -> Result<(), PortFailure> {
        self.links
            .lock()
            .unwrap()
            .entry((account_id.to_owned(), upid.to_owned()))
            .or_insert_with(|| operation_id.to_owned());
        Ok(())
    }
    async fn operations_for(
        &self,
        account_id: &str,
        upids: &[String],
    ) -> Result<HashMap<String, String>, PortFailure> {
        *self.lookups.lock().unwrap() += 1;
        let links = self.links.lock().unwrap();
        Ok(upids
            .iter()
            .filter_map(|upid| {
                links
                    .get(&(account_id.to_owned(), upid.clone()))
                    .map(|operation| (upid.clone(), operation.clone()))
            })
            .collect())
    }
}

struct Fixture {
    proxmox: ProxmoxAccounts,
    tasks: Arc<FakeTasks>,
    links: Arc<FakeLinks>,
}

async fn fixture() -> Fixture {
    let tasks = FakeTasks::new();
    let links = Arc::new(FakeLinks::default());
    // The executor recorded the task it started; another account recorded
    // the same UPID string, which must never leak across accounts.
    links
        .record("acc-1", UPID_FLEET, "op-started-by-fleet")
        .await
        .unwrap();
    links
        .record("acc-other", UPID_OUTSIDE, "op-in-another-account")
        .await
        .unwrap();
    let proxmox = ProxmoxAccounts::new(
        Arc::new(FakeAccounts(vec![
            account("acc-1", Some(FP)),
            account("acc-unconfirmed", None),
        ])),
        Arc::new(FakeCredentials),
        Arc::new(Unreached),
        Arc::new(Unreached),
        Arc::new(Unreached),
        Arc::new(Machines::new(Arc::new(NoMachines), Arc::new(NoAudit))),
        Arc::new(NoAudit),
    )
    .with_task_history(tasks.clone(), links.clone());
    Fixture {
        proxmox,
        tasks,
        links,
    }
}

#[tokio::test]
async fn each_task_carries_the_operation_that_started_it() {
    let fixture = fixture().await;

    let snapshot = fixture
        .proxmox
        .task_history(
            &AllowExcept::default(),
            &principal(),
            "acc-1",
            &TaskHistoryQuery::default(),
            NOW,
        )
        .await
        .unwrap();

    assert_eq!(snapshot.account_id, "acc-1");
    assert_eq!(snapshot.pve_version, "9.2.2");
    assert_eq!(snapshot.observed_at, NOW);
    assert_eq!(snapshot.tasks.len(), 3);
    let fleet = &snapshot.tasks[0];
    assert_eq!(fleet.upid, UPID_FLEET);
    assert_eq!(
        fleet.fleet_operation_id.as_deref(),
        Some("op-started-by-fleet")
    );
    assert_eq!(fleet.status, ProxmoxTaskState::Running);
    // PVE seconds become Fleet's epoch millis.
    assert_eq!(fleet.started_at, 1_759_000_600_000);
    assert_eq!(fleet.ended_at, None);
    assert_eq!(fleet.user, "fleet@pve");
    assert_eq!(fleet.token_id.as_deref(), Some("fleet-ops"));
    // A task Fleet did not start carries no link, even though another
    // account recorded the same UPID string.
    assert_eq!(snapshot.tasks[1].fleet_operation_id, None);
    assert_eq!(snapshot.tasks[1].ended_at, Some(1_759_000_642_000));
    assert_eq!(snapshot.tasks[2].fleet_operation_id, None);
    assert_eq!(
        snapshot.tasks[2].exit_status.as_deref(),
        Some("clone failed")
    );
    // The per-node warning passes through untouched.
    assert_eq!(snapshot.warnings.len(), 1);
    assert!(snapshot.warnings[0].contains("node pve2"));
    // One lookup for the whole snapshot, and the bounded provider query.
    assert_eq!(*fixture.links.lookups.lock().unwrap(), 1);
    assert_eq!(
        fixture.tasks.queries(),
        vec![(
            "acc-1".to_owned(),
            RawTaskQuery {
                node: None,
                vmid: None,
                running_only: false,
                limit_per_node: TASKS_PER_NODE,
            }
        )]
    );
    // No secret material anywhere in the serialized snapshot.
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(!json.contains("the-token-secret"), "{json}");
}

#[tokio::test]
async fn without_operation_read_the_link_is_withheld_with_a_warning() {
    let fixture = fixture().await;

    let snapshot = fixture
        .proxmox
        .task_history(
            &AllowExcept(vec![Permission::OperationRead]),
            &principal(),
            "acc-1",
            &TaskHistoryQuery::default(),
            NOW,
        )
        .await
        .unwrap();

    assert_eq!(snapshot.tasks.len(), 3);
    assert!(
        snapshot
            .tasks
            .iter()
            .all(|task| task.fleet_operation_id.is_none())
    );
    assert!(
        snapshot
            .warnings
            .iter()
            .any(|warning| warning.contains("fleetOperationId is withheld"))
    );
    assert_eq!(*fixture.links.lookups.lock().unwrap(), 0);
}

#[tokio::test]
async fn the_filters_reach_the_provider_and_narrow_the_snapshot() {
    let fixture = fixture().await;

    let running = fixture
        .proxmox
        .task_history(
            &AllowExcept::default(),
            &principal(),
            "acc-1",
            &TaskHistoryQuery {
                node: Some("pve".to_owned()),
                vmid: Some(101),
                status: Some("running".to_owned()),
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(running.tasks.len(), 1);
    assert_eq!(running.tasks[0].upid, UPID_FLEET);

    let errors = fixture
        .proxmox
        .task_history(
            &AllowExcept::default(),
            &principal(),
            "acc-1",
            &TaskHistoryQuery {
                status: Some("error".to_owned()),
                ..TaskHistoryQuery::default()
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(errors.tasks.len(), 1);
    assert_eq!(errors.tasks[0].upid, UPID_FAILED);

    let queries = fixture.tasks.queries();
    assert_eq!(
        queries[0].1,
        RawTaskQuery {
            node: Some("pve".to_owned()),
            vmid: Some(101),
            running_only: true,
            limit_per_node: TASKS_PER_NODE,
        }
    );
    assert!(!queries[1].1.running_only);
}

#[tokio::test]
async fn malformed_filters_are_refused_before_any_provider_call() {
    let fixture = fixture().await;
    for query in [
        TaskHistoryQuery {
            status: Some("warning".to_owned()),
            ..TaskHistoryQuery::default()
        },
        TaskHistoryQuery {
            node: Some("../nodes".to_owned()),
            ..TaskHistoryQuery::default()
        },
        TaskHistoryQuery {
            vmid: Some(7),
            ..TaskHistoryQuery::default()
        },
    ] {
        let error = fixture
            .proxmox
            .task_history(&AllowExcept::default(), &principal(), "acc-1", &query, NOW)
            .await
            .unwrap_err();
        assert!(
            matches!(error, ProxmoxUseCaseError::Invalid { .. }),
            "{query:?}: {error}"
        );
    }
    assert!(fixture.tasks.queries().is_empty());
}

#[tokio::test]
async fn denial_and_the_trust_gate_refuse_before_any_provider_call() {
    let fixture = fixture().await;

    let denied = fixture
        .proxmox
        .task_history(
            &AllowExcept(vec![Permission::ProxmoxRead]),
            &principal(),
            "acc-1",
            &TaskHistoryQuery::default(),
            NOW,
        )
        .await
        .unwrap_err();
    assert!(matches!(denied, ProxmoxUseCaseError::Denied(_)), "{denied}");

    let unconfirmed = fixture
        .proxmox
        .task_history(
            &AllowExcept::default(),
            &principal(),
            "acc-unconfirmed",
            &TaskHistoryQuery::default(),
            NOW,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(unconfirmed, ProxmoxUseCaseError::UnconfirmedTrust { .. }),
        "{unconfirmed}"
    );

    let unknown = fixture
        .proxmox
        .task_history(
            &AllowExcept::default(),
            &principal(),
            "acc-missing",
            &TaskHistoryQuery::default(),
            NOW,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(unknown, ProxmoxUseCaseError::NotFound { .. }),
        "{unknown}"
    );

    assert!(fixture.tasks.queries().is_empty());
}
