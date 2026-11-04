//! FM-1124 (#572): the hardware reconciler. Reservations, guest configs, the
//! inventory and the lease or machine behind each reservation are compared;
//! what Fleet itself attached is repaired and everything else is reported.
//!
//! **Simulated.** The shared fake Proxmox (`support/fake_pve.rs`) behind the
//! USB-aware layer (`support/usb_pve.rs`) that speaks the FM-S11 spike's
//! shapes, a real SQLite file, the real reservation store, the real inventory
//! and the real provider calls. Every id, VMID and address is invented; there
//! is no real device serial. Nothing here touches live infrastructure.
//!
//! Not measured: what PVE does with a pending detach once the guest stops,
//! and deleting a pending-only leftover from a running guest (both are read
//! back, never assumed, in the reconciler; the fake models the spike's notes).

#[allow(dead_code)]
#[path = "support/fake_pve.rs"]
mod fake_pve;
#[path = "support/usb_pve.rs"]
mod usb_pve;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use fake_pve::{FINGERPRINT, FakePve, Faults, TEMPLATE_NODE};
use fleet_application::audit::AuditOutcome;
use fleet_application::hardware::HardwareStore;
use fleet_application::hardware_inventory::{DeviceFilter, HardwareInventory};
use fleet_application::hardware_reservation::{
    AuditContext, HardwareReservations, ReserveDecision, ReserveRequest,
};
use fleet_application::lab::{ImagePinValidator, Lab};
use fleet_application::operation::{AuditPort, Operations};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_controller::hardware_reconciler::{
    FRESH_ROW_MS, HardwareReconciler, MAX_GUEST_READS_PER_PASS, PASS_INTERVAL_MS, ReconcileReport,
    SqliteReconcilerRecords,
};
use fleet_controller::hardware_reservation_store::SqliteHardwareReservations;
use fleet_controller::lab_sweeper::LabSweeper;
use fleet_core::{
    DeviceStatus, GuestTarget, HardwareReservationState as State, ReservationOwnerKind,
};
use fleet_provider_proxmox::{ProxmoxClient, PveHttpMethod, PveHttpRequest};
use fleet_storage_sqlite::{
    AuditSink, HardwareRepository, LabRepository, LeaseRepository, OperationRepository,
    ProjectRepository, ProxmoxAccountRepository, Store,
};
use usb_pve::UsbHost;

const PRINCIPAL: &str = fleet_auth::LAN_PRINCIPAL_ID;
const READER_A: &str = "fm-test-reader-a";
const READER_B: &str = "fm-test-reader-b";
/// The exact value Fleet writes for READER_A.
const OURS_A: &str = "mapping=fm-test-reader-a";
const GUEST: u32 = 9101;
const OTHER_GUEST: u32 = 9102;
const SECRET: &str = "fake-token-material";
const MINUTE_MS: i64 = 60_000;

fn now() -> i64 {
    fleet_core::SystemClock::now_unix_millis()
}

/// A pass time late enough that no row counts as freshly changed.
fn later() -> i64 {
    now() + FRESH_ROW_MS * 2
}

#[derive(Debug)]
struct AllowAll;

impl fleet_application::authz::Authorizer for AllowAll {
    fn decide(
        &self,
        _request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        fleet_application::authz::Decision::allow()
    }
}

/// The audit sink, which can be told to refuse the detach intent.
#[derive(Debug)]
struct GateAudit {
    inner: AuditSink,
    refuse_detach_intent: Arc<AtomicBool>,
}

#[async_trait]
impl AuditPort for GateAudit {
    async fn record_intent(
        &self,
        intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
        if self.refuse_detach_intent.load(Ordering::SeqCst)
            && intent
                .metadata
                .entries()
                .any(|(key, value)| key == "event" && value == "hardware_detach_requested")
        {
            return Err("the audit sink is refusing".to_owned());
        }
        self.inner.record_intent(intent).await
    }

    async fn record_outcome(
        &self,
        operation_id: &str,
        outcome: AuditOutcome,
    ) -> Result<(), String> {
        self.inner.record_outcome(operation_id, outcome).await
    }
}

#[derive(Debug)]
struct OneSecret;

#[async_trait]
impl ProxmoxCredentialStore for OneSecret {
    async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(Some(SECRET.to_owned()))
    }
    async fn store(&self, _account_id: &str, _secret: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the reconciler never stores credentials")
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the reconciler never clears credentials")
    }
}

#[derive(Debug)]
struct NoImages;

#[async_trait]
impl ImagePinValidator for NoImages {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(None)
    }
}

/// One SQLite file and one Proxmox host that outlive every controller run.
struct World {
    _dir: tempfile::TempDir,
    database: PathBuf,
    usb: Arc<UsbHost>,
    refuse_detach_intent: Arc<AtomicBool>,
    account_id: String,
}

impl World {
    /// Two readers on the lab node, plus `bulk` more devices.
    async fn new(bulk: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("fleet.db");
        let faults = Arc::new(Faults::default());
        let pve = FakePve::new(faults);
        let usb = UsbHost::new(pve.clone());
        usb.add_mapping(READER_A, &["node=pve-b,id=aaaa:0001,path=1-1"]);
        usb.add_mapping(READER_B, &["node=pve-b,id=bbbb:0002,path=1-2"]);
        for index in 0..bulk {
            usb.add_mapping(
                &format!("fm-test-bulk-{index}"),
                &[&format!("node=pve-b,id=cccc:{index:04x},path=2-{index}")],
            );
        }
        let store = Store::open(&database).await.unwrap();
        let pool = store.pool().clone();
        let accounts = ProxmoxAccountRepository::new(pool.clone());
        let account = accounts
            .create(&NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: fake_pve::API_HOST.to_owned(),
                port: None,
                token_id: "fleet@pve!lab".to_owned(),
            })
            .await
            .unwrap();
        accounts
            .set_fingerprint(&account.id, Some(FINGERPRINT.to_owned()))
            .await
            .unwrap();
        pool.close().await;
        drop(store);
        Self {
            _dir: dir,
            database,
            usb,
            refuse_detach_intent: Arc::new(AtomicBool::new(false)),
            account_id: account.id,
        }
    }

    /// Guests the host knows, each a clone on the lab node.
    async fn guests(&self, vmids: &[u32]) {
        for vmid in vmids {
            self.usb.create_guest(*vmid, "fm-lab-test").await;
        }
    }

    /// A guest runs (so an unplug of its device may only be pending).
    async fn start(&self, vmid: u32) {
        let request = PveHttpRequest {
            host: fake_pve::API_HOST.to_owned(),
            port: 8006,
            path: format!("/api2/json/nodes/{TEMPLATE_NODE}/qemu/{vmid}/status/start"),
            pinned_fingerprint: Some(FINGERPRINT.to_owned()),
            credentials: Arc::new(fleet_provider_proxmox::PveCredentials {
                token_id: "fleet@pve!lab".to_owned(),
                token: fleet_core::SensitiveString::new(SECRET),
            }),
            method: PveHttpMethod::Post,
        };
        self.usb
            .transport()
            .execute_with_body(request, b"{}".to_vec())
            .await
            .expect("the fake starts the guest");
    }
}

/// One controller run over the world.
struct Rig {
    store: Store,
    pool: sqlx::SqlitePool,
    hardware: Arc<dyn HardwareStore>,
    reservations: Arc<HardwareReservations>,
    inventory: Arc<HardwareInventory>,
    reconciler: Arc<HardwareReconciler>,
    sweeper: Arc<LabSweeper>,
    account_id: String,
}

impl Rig {
    async fn start(world: &World) -> Self {
        let store = Store::open(&world.database)
            .await
            .expect("the previous run released the database");
        let pool = store.pool().clone();
        let audit: Arc<dyn AuditPort> = Arc::new(GateAudit {
            inner: AuditSink::new(pool.clone()),
            refuse_detach_intent: world.refuse_detach_intent.clone(),
        });
        let accounts: Arc<dyn ProxmoxAccountPort> =
            Arc::new(ProxmoxAccountRepository::new(pool.clone()));
        let credentials: Arc<dyn ProxmoxCredentialStore> = Arc::new(OneSecret);
        let client = ProxmoxClient::new(world.usb.transport());
        let hardware: Arc<dyn HardwareStore> = Arc::new(HardwareRepository::new(pool.clone()));
        let reservations = Arc::new(HardwareReservations::new(
            Arc::new(SqliteHardwareReservations::new(pool.clone())),
            audit.clone(),
        ));
        let inventory = Arc::new(HardwareInventory::new(
            accounts.clone(),
            credentials.clone(),
            hardware.clone(),
            fleet_controller::hardware_observer::shared(client.clone()),
            audit.clone(),
        ));
        let reconciler = Arc::new(HardwareReconciler::new(
            accounts,
            credentials,
            client,
            hardware.clone(),
            reservations.clone(),
            inventory.clone(),
            audit.clone(),
            Arc::new(SqliteReconcilerRecords::new(pool.clone())),
        ));
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            audit.clone(),
        ));
        let lab = Arc::new(Lab::new(
            labs.clone(),
            labs.clone(),
            leases.clone(),
            Arc::new(NoImages),
            Arc::new(ProjectRepository::new(pool.clone())),
            audit.clone(),
        ));
        let sweeper = Arc::new(
            LabSweeper::new(lab, leases, labs, operations, audit)
                .with_hardware_reconciler(reconciler.clone()),
        );
        Self {
            store,
            pool,
            hardware,
            reservations,
            inventory,
            reconciler,
            sweeper,
            account_id: world.account_id.clone(),
        }
    }

    /// The controller dies: the store and every connection close.
    async fn kill(self) {
        self.pool.close().await;
        drop(self.store);
    }

    /// Records the world's devices, as the operator's refresh does.
    async fn refresh(&self) {
        self.inventory
            .refresh(
                &AllowAll,
                &fleet_application::authz::ActingPrincipal {
                    id: PRINCIPAL.to_owned(),
                },
                None,
                &self.account_id,
            )
            .await
            .expect("the inventory refreshes");
    }

    /// A lease row in `state`, with a provision that allocated a guest or
    /// not.
    async fn lease(&self, state: &str, with_guest: bool) -> String {
        let id = uuid::Uuid::now_v7().to_string();
        let provision = with_guest.then(|| uuid::Uuid::now_v7().to_string());
        if let Some(provision) = &provision {
            sqlx::query(
                "INSERT INTO lab_provisions (id, template_version_id, state, vmid, created_at, updated_at) \
                 VALUES (?1, 'tv', 'provisioned', ?2, ?3, ?3)",
            )
            .bind(provision)
            .bind(i64::from(GUEST))
            .bind(now())
            .execute(&self.pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO lab_leases (id, template_version_id, owner, purpose, state, provision_id, \
             cleanup, created_at, ttl_seconds, cleanup_attempts) \
             VALUES (?1, 'tv', ?2, 'reconcile', ?3, ?4, 'destroy', ?5, 3600, 0)",
        )
        .bind(&id)
        .bind(PRINCIPAL)
        .bind(state)
        .bind(provision)
        .bind(now())
        .execute(&self.pool)
        .await
        .unwrap();
        id
    }

    async fn set_lease(&self, id: &str, state: &str) {
        sqlx::query("UPDATE lab_leases SET state = ?2 WHERE id = ?1")
            .bind(id)
            .bind(state)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    /// Reserves `mapping` for the lease and walks the row to `state` along
    /// the state machine's legal edges, recording the guest and `slot`.
    async fn seed(
        &self,
        lease: &str,
        mapping: &str,
        state: &str,
        vmid: u32,
        slot: Option<u8>,
    ) -> String {
        self.seed_owner(
            ReservationOwnerKind::Lease,
            lease,
            mapping,
            state,
            vmid,
            slot,
        )
        .await
    }

    async fn seed_owner(
        &self,
        owner_kind: ReservationOwnerKind,
        owner: &str,
        mapping: &str,
        state: &str,
        vmid: u32,
        slot: Option<u8>,
    ) -> String {
        let device = self
            .hardware
            .device_by_mapping(&self.account_id, mapping)
            .await
            .unwrap()
            .expect("the device is inventoried");
        let decision = self
            .reservations
            .reserve(
                &AuditContext {
                    actor: PRINCIPAL.to_owned(),
                    operation_id: None,
                },
                &ReserveRequest {
                    device_id: device.id,
                    owner_kind,
                    owner_id: owner.to_owned(),
                },
                now(),
            )
            .await
            .unwrap();
        let ReserveDecision::Reserved { reservation, .. } = decision else {
            panic!("the device is reserved: {decision:?}");
        };
        let target = GuestTarget {
            account_id: self.account_id.clone(),
            node: TEMPLATE_NODE.to_owned(),
            vmid,
            usb_slot: slot,
        };
        let path: &[State] = match state {
            "held" => &[],
            "attaching" => &[State::Attaching],
            "attached" => &[State::Attaching, State::Attached],
            "attach_unknown" => &[State::Attaching, State::AttachUnknown],
            "detaching" => &[State::Attaching, State::Attached, State::Detaching],
            "detach_failed" => &[
                State::Attaching,
                State::Attached,
                State::Detaching,
                State::DetachFailed,
            ],
            other => panic!("no path to {other}"),
        };
        let mut from = State::Held;
        for next in path {
            self.hardware
                .transition_reservation(&reservation.id, from, *next, Some(&target), now())
                .await
                .unwrap();
            from = *next;
        }
        reservation.id
    }

    /// The reservation's state and recorded slot.
    async fn row(&self, id: &str) -> (String, Option<i64>) {
        sqlx::query_as("SELECT state, usb_slot FROM hardware_reservations WHERE id = ?1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// The status a reader sees for the mapping's device.
    async fn status(&self, mapping: &str) -> DeviceStatus {
        self.inventory
            .list(
                &AllowAll,
                &fleet_application::authz::ActingPrincipal {
                    id: PRINCIPAL.to_owned(),
                },
                &DeviceFilter {
                    account_id: Some(self.account_id.clone()),
                },
                500,
                None,
            )
            .await
            .unwrap()
            .into_iter()
            .find(|view| view.device.mapping_id == mapping)
            .expect("the device is inventoried")
            .status
    }

    /// The facts of every audit event of `event`, oldest first.
    async fn audit(&self, event: &str) -> Vec<BTreeMap<String, String>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT metadata_json FROM audit_events WHERE outcome IS NULL AND metadata_json LIKE ?1 \
             ORDER BY rowid",
        )
        .bind(format!("%\"event\":\"{event}\"%"))
        .fetch_all(&self.pool)
        .await
        .unwrap();
        rows.iter()
            .map(|json| serde_json::from_str(json).unwrap())
            .collect()
    }

    /// Every audit event, as text.
    async fn audit_text(&self) -> String {
        let rows: Vec<String> = sqlx::query_scalar("SELECT metadata_json FROM audit_events")
            .fetch_all(&self.pool)
            .await
            .unwrap();
        rows.join("\n")
    }

    async fn pass(&self, at: i64) -> ReconcileReport {
        self.reconciler.startup(at).await
    }
}

fn entries(pairs: &[(u8, &str)]) -> BTreeMap<u8, String> {
    pairs
        .iter()
        .map(|(slot, value)| (*slot, (*value).to_owned()))
        .collect()
}

// ---------------------------------------------------------------------
// The table: reservation state x guest config x lease state, and the
// device's presence and a foreign guest from the inventory.
// ---------------------------------------------------------------------

struct Case {
    name: &'static str,
    /// The lease's state when the reconciler runs.
    lease: &'static str,
    /// Whether the lease's provision allocated a guest.
    guest: bool,
    /// The row's state and recorded slot.
    row: &'static str,
    slot: Option<u8>,
    /// What the recorded guest holds.
    entries: &'static [(u8, &'static str)],
    /// What is true afterwards.
    expect_row: &'static str,
    expect_entries: &'static [(u8, &'static str)],
    expect_writes: &'static [&'static str],
}

const CASES: &[Case] = &[
    // The owner is over: what Fleet attached is repaired.
    Case {
        name: "a hold of a released lease that never attached is released",
        lease: "released",
        guest: true,
        row: "held",
        slot: None,
        entries: &[],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &[],
    },
    Case {
        name: "a hold of a lease that failed without a guest is released",
        lease: "failed",
        guest: false,
        row: "held",
        slot: None,
        entries: &[],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &[],
    },
    Case {
        name: "a crash before the write: attaching, nothing on the guest, released",
        lease: "released",
        guest: true,
        row: "attaching",
        slot: Some(0),
        entries: &[],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &[],
    },
    Case {
        name: "a crash after the write: attaching proves nothing, the entry is left and the row is unknown",
        lease: "released",
        guest: true,
        row: "attaching",
        slot: Some(0),
        entries: &[(0, OURS_A)],
        expect_row: "attach_unknown",
        expect_entries: &[(0, OURS_A)],
        expect_writes: &[],
    },
    Case {
        name: "attached to a released lease: Fleet's own entry is removed and the row released",
        lease: "released",
        guest: true,
        row: "attached",
        slot: Some(0),
        entries: &[(0, OURS_A)],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &["detach usb0"],
    },
    Case {
        name: "attached to a lease whose cleanup gave up: removed and released",
        lease: "cleanup_failed",
        guest: true,
        row: "attached",
        slot: Some(1),
        entries: &[(1, OURS_A)],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &["detach usb1"],
    },
    Case {
        name: "attached but an operator already removed the entry: released with no write",
        lease: "released",
        guest: true,
        row: "attached",
        slot: Some(0),
        entries: &[],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &[],
    },
    Case {
        name: "the entry is in another slot than the recorded one: untouched, row kept",
        lease: "released",
        guest: true,
        row: "attached",
        slot: Some(0),
        entries: &[(1, OURS_A)],
        expect_row: "attached",
        expect_entries: &[(1, OURS_A)],
        expect_writes: &[],
    },
    Case {
        name: "the recorded slot holds the mapping with an operator's options: not Fleet's value, untouched",
        lease: "released",
        guest: true,
        row: "attached",
        slot: Some(0),
        entries: &[(0, "mapping=fm-test-reader-a,usb3=1")],
        expect_row: "detach_failed",
        expect_entries: &[(0, "mapping=fm-test-reader-a,usb3=1")],
        expect_writes: &[],
    },
    Case {
        name: "the recorded slot holds another device's mapping: not this device, untouched",
        lease: "released",
        guest: true,
        row: "attached",
        slot: Some(0),
        entries: &[(0, "mapping=fm-test-reader-b")],
        expect_row: "released",
        expect_entries: &[(0, "mapping=fm-test-reader-b")],
        expect_writes: &[],
    },
    Case {
        name: "an unknown attach with its slot and the entry there: removed and released",
        lease: "released",
        guest: true,
        row: "attach_unknown",
        slot: Some(2),
        entries: &[(2, OURS_A)],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &["detach usb2"],
    },
    Case {
        name: "an unknown attach with no slot and an entry: nothing proves it is Fleet's, untouched",
        lease: "released",
        guest: true,
        row: "attach_unknown",
        slot: None,
        entries: &[(2, OURS_A)],
        expect_row: "attach_unknown",
        expect_entries: &[(2, OURS_A)],
        expect_writes: &[],
    },
    Case {
        name: "an unknown attach with no slot and nothing on the guest: released",
        lease: "released",
        guest: true,
        row: "attach_unknown",
        slot: None,
        entries: &[],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &[],
    },
    Case {
        name: "a detach in flight when the controller died: continued, removed and released",
        lease: "released",
        guest: true,
        row: "detaching",
        slot: Some(0),
        entries: &[(0, OURS_A)],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &["detach usb0"],
    },
    Case {
        name: "a failed detach is retried: removed and released",
        lease: "released",
        guest: true,
        row: "detach_failed",
        slot: Some(0),
        entries: &[(0, OURS_A)],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &["detach usb0"],
    },
    Case {
        name: "a failed detach whose entry is gone: released with no write",
        lease: "cleanup_failed",
        guest: true,
        row: "detach_failed",
        slot: Some(0),
        entries: &[],
        expect_row: "released",
        expect_entries: &[],
        expect_writes: &[],
    },
    // A live owner, or one whose step or cleanup is running, is left alone
    // whatever the guest shows.
    Case {
        name: "a ready lease holds its attached device",
        lease: "ready",
        guest: true,
        row: "attached",
        slot: Some(0),
        entries: &[(0, OURS_A)],
        expect_row: "attached",
        expect_entries: &[(0, OURS_A)],
        expect_writes: &[],
    },
    Case {
        name: "a ready lease's unknown attach is not resolved behind its back",
        lease: "ready",
        guest: true,
        row: "attach_unknown",
        slot: Some(0),
        entries: &[(0, OURS_A)],
        expect_row: "attach_unknown",
        expect_entries: &[(0, OURS_A)],
        expect_writes: &[],
    },
    Case {
        name: "a provision in flight owns its attach step (restart mid-attach, entry written)",
        lease: "provisioning",
        guest: true,
        row: "attaching",
        slot: Some(0),
        entries: &[(0, OURS_A)],
        expect_row: "attaching",
        expect_entries: &[(0, OURS_A)],
        expect_writes: &[],
    },
    Case {
        name: "a provision in flight owns its attach step (restart mid-attach, nothing written)",
        lease: "provisioning",
        guest: true,
        row: "attaching",
        slot: Some(0),
        entries: &[],
        expect_row: "attaching",
        expect_entries: &[],
        expect_writes: &[],
    },
    Case {
        name: "a releasing lease's cleanup owns the detach",
        lease: "releasing",
        guest: true,
        row: "attached",
        slot: Some(0),
        entries: &[(0, OURS_A)],
        expect_row: "attached",
        expect_entries: &[(0, OURS_A)],
        expect_writes: &[],
    },
    Case {
        name: "a failed lease that owns a guest is the cleanup's, not the reconciler's",
        lease: "failed",
        guest: true,
        row: "detach_failed",
        slot: Some(0),
        entries: &[(0, OURS_A)],
        expect_row: "detach_failed",
        expect_entries: &[(0, OURS_A)],
        expect_writes: &[],
    },
    Case {
        name: "a ready lease's hold stays held",
        lease: "ready",
        guest: true,
        row: "held",
        slot: None,
        entries: &[],
        expect_row: "held",
        expect_entries: &[],
        expect_writes: &[],
    },
];

#[tokio::test]
async fn the_reconciliation_table() {
    for case in CASES {
        let world = World::new(0).await;
        world.guests(&[GUEST]).await;
        let rig = Rig::start(&world).await;
        rig.refresh().await;
        let lease = rig.lease("ready", case.guest).await;
        let reservation = rig.seed(&lease, READER_A, case.row, GUEST, case.slot).await;
        for (slot, value) in case.entries {
            world.usb.set_slot(GUEST, *slot, value);
        }
        rig.set_lease(&lease, case.lease).await;

        let report = rig.pass(later()).await;

        let (state, _) = rig.row(&reservation).await;
        assert_eq!(state, case.expect_row, "{}: {report:?}", case.name);
        assert_eq!(
            world.usb.stored(GUEST),
            entries(case.expect_entries),
            "{}",
            case.name
        );
        assert_eq!(world.usb.writes(), case.expect_writes, "{}", case.name);
        assert!(
            report.failures.is_empty(),
            "{}: {:?}",
            case.name,
            report.failures
        );
        rig.kill().await;
    }
}

#[tokio::test]
async fn a_second_pass_changes_nothing() {
    for case in CASES {
        let world = World::new(0).await;
        world.guests(&[GUEST]).await;
        let rig = Rig::start(&world).await;
        rig.refresh().await;
        let lease = rig.lease("ready", case.guest).await;
        let reservation = rig.seed(&lease, READER_A, case.row, GUEST, case.slot).await;
        for (slot, value) in case.entries {
            world.usb.set_slot(GUEST, *slot, value);
        }
        rig.set_lease(&lease, case.lease).await;
        rig.pass(later()).await;
        let first = (
            rig.row(&reservation).await,
            world.usb.stored(GUEST),
            world.usb.writes(),
            rig.audit("hardware_reconciled").await.len(),
        );

        let again = rig.pass(later() + MINUTE_MS).await;
        let second = (
            rig.row(&reservation).await,
            world.usb.stored(GUEST),
            world.usb.writes(),
            rig.audit("hardware_reconciled").await.len(),
        );
        assert_eq!(first, second, "{}: {again:?}", case.name);
        assert_eq!(again.released, 0, "{}", case.name);
        assert_eq!(again.entries_removed, 0, "{}", case.name);
        assert_eq!(again.marked_unproven, 0, "{}", case.name);
        rig.kill().await;
    }
}

#[tokio::test]
async fn an_unplugged_device_does_not_stop_the_repair_and_reads_missing_after() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    rig.set_lease(&lease, "released").await;
    world.usb.set_present(READER_A, false);

    rig.pass(later()).await;

    assert_eq!(rig.row(&reservation).await.0, "released");
    assert!(world.usb.stored(GUEST).is_empty());
    assert_eq!(rig.status(READER_A).await, DeviceStatus::Missing);
}

// ---------------------------------------------------------------------
// Only Fleet's own attachments are repaired; everything else is reported.
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_entry_on_a_foreign_guest_is_never_touched_and_the_device_reads_externally_attached() {
    let world = World::new(0).await;
    world.guests(&[GUEST, OTHER_GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    // Fleet's own attachment of a released lease, and a hand-made entry for
    // the same mapping on another guest (the Decker case).
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    world.usb.set_slot(OTHER_GUEST, 3, OURS_A);
    rig.set_lease(&lease, "released").await;

    let report = rig.pass(later()).await;

    // Fleet's own entry is gone; the operator's is exactly as it was.
    assert_eq!(rig.row(&reservation).await.0, "released");
    assert!(world.usb.stored(GUEST).is_empty());
    assert_eq!(world.usb.stored(OTHER_GUEST), entries(&[(3, OURS_A)]));
    assert_eq!(world.usb.writes(), ["detach usb0"]);
    assert_eq!(rig.status(READER_A).await, DeviceStatus::ExternallyAttached);
    assert_eq!(report.accounts_refreshed, 1);
    // Reported once, with ids only.
    let seen = rig.audit("hardware_externally_attached").await;
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0]["guest_vmid"], OTHER_GUEST.to_string());
    assert_eq!(seen[0]["usb_slot"], "usb3");
    assert_eq!(seen[0]["mapping"], READER_A);

    // Another pass neither writes nor reports it again.
    rig.pass(later() + 20 * MINUTE_MS).await;
    assert_eq!(world.usb.writes(), ["detach usb0"]);
    assert_eq!(rig.audit("hardware_externally_attached").await.len(), 1);
    assert_eq!(world.usb.stored(OTHER_GUEST), entries(&[(3, OURS_A)]));
}

#[tokio::test]
async fn a_device_nobody_holds_with_a_manual_attachment_is_reported_and_left_alone() {
    let world = World::new(0).await;
    world.guests(&[OTHER_GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    world.usb.set_slot(OTHER_GUEST, 0, OURS_A);

    rig.pass(now()).await;

    assert_eq!(rig.status(READER_A).await, DeviceStatus::ExternallyAttached);
    assert_eq!(rig.audit("hardware_externally_attached").await.len(), 1);
    assert!(
        world.usb.writes().is_empty(),
        "Fleet never adopts or removes it"
    );
    assert_eq!(world.usb.stored(OTHER_GUEST), entries(&[(0, OURS_A)]));
    // Nothing was audited as a repair.
    assert!(rig.audit("hardware_reconciled").await.is_empty());
    assert!(rig.audit("hardware_detach_requested").await.is_empty());
}

#[tokio::test]
async fn a_second_guest_that_references_a_held_device_is_a_finding_not_a_repair() {
    let world = World::new(0).await;
    world.guests(&[GUEST, OTHER_GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    world.usb.set_slot(OTHER_GUEST, 1, OURS_A);

    rig.pass(later()).await;

    assert_eq!(rig.row(&reservation).await.0, "attached");
    assert!(world.usb.writes().is_empty());
    let findings = rig.audit("hardware_reconcile_finding").await;
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["finding"], "foreign_reference_to_held_device");
    assert_eq!(findings[0]["guest_vmid"], OTHER_GUEST.to_string());
}

#[tokio::test]
async fn a_guest_the_cluster_does_not_list_is_a_finding_never_a_release() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    rig.set_lease(&lease, "released").await;
    // The guest is deleted by hand: absent is not proof of detach.
    world.usb.remove_guest(GUEST).await;

    let report = rig.pass(later()).await;

    assert_eq!(rig.row(&reservation).await.0, "attached");
    assert!(world.usb.writes().is_empty());
    assert_eq!(report.released, 0);
    assert_eq!(report.findings, 1);
    let findings = rig.audit("hardware_reconcile_finding").await;
    assert_eq!(findings[0]["finding"], "guest_absent");
    assert_eq!(findings[0]["reservation_id"], reservation);
    // The device stays unallocatable until an operator decides.
    assert_eq!(rig.status(READER_A).await, DeviceStatus::Reserved);

    // Looked at again only after a backoff, and reported once.
    let soon = rig.pass(later() + MINUTE_MS).await;
    assert_eq!(soon.skipped, 1);
    assert_eq!(rig.audit("hardware_reconcile_finding").await.len(), 1);
}

#[tokio::test]
async fn an_unreadable_guest_is_not_released_and_is_retried_after_a_backoff() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    rig.set_lease(&lease, "released").await;
    // Both views of the guest fail for the first pass.
    world.usb.fail_next_config(GUEST, 100);

    let first = rig.pass(later()).await;
    assert_eq!(rig.row(&reservation).await.0, "attached");
    assert!(world.usb.writes().is_empty());
    assert_eq!(first.released, 0);
    assert_eq!(
        rig.audit("hardware_reconcile_finding").await[0]["finding"],
        "guest_unreadable"
    );

    // Within the backoff nothing is read for it.
    world.usb.fail_next_config(GUEST, 0);
    let reads = world.usb.count(|line| line.contains("/qemu/9101/config"));
    let early = rig.pass(later() + MINUTE_MS).await;
    assert_eq!(early.skipped, 1);
    assert_eq!(
        world.usb.count(|line| line.contains("/qemu/9101/config")),
        reads,
        "a row that was just looked at is not read again inside its backoff"
    );

    // After it the guest is read, Fleet's own entry removed and the row
    // released.
    let second = rig.pass(later() + 3 * PASS_INTERVAL_MS).await;
    assert_eq!(second.released, 1, "{second:?}");
    assert_eq!(rig.row(&reservation).await.0, "released");
    assert_eq!(world.usb.writes(), ["detach usb0"]);
}

#[tokio::test]
async fn a_detach_pve_keeps_pending_is_not_a_release_until_the_guest_agrees() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    world.start(GUEST).await;
    world.usb.set_hotplug_usb(GUEST, false);
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    rig.set_lease(&lease, "released").await;

    let first = rig.pass(later()).await;

    // The removal is stored and the running guest still holds the device.
    assert_eq!(world.usb.writes(), ["detach usb0"]);
    assert_eq!(world.usb.applied(GUEST), entries(&[(0, OURS_A)]));
    assert_eq!(rig.row(&reservation).await.0, "detaching");
    assert_eq!(first.released, 0);
    assert_eq!(first.entries_removed, 0);
    assert_eq!(
        rig.audit("hardware_reconcile_finding").await[0]["finding"],
        "detach_pending"
    );

    // A restart applies it; the next pass reads it and releases, with no
    // second write.
    world.usb.apply_pending(GUEST);
    let second = rig.pass(later() + 3 * PASS_INTERVAL_MS).await;
    assert_eq!(second.released, 1, "{second:?}");
    assert_eq!(rig.row(&reservation).await.0, "released");
    assert_eq!(world.usb.writes(), ["detach usb0"]);
}

#[tokio::test]
async fn a_refused_detach_keeps_the_row_and_never_releases() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    rig.set_lease(&lease, "released").await;
    world
        .usb
        .inject(usb_pve::UsbStep::Detach, usb_pve::UsbFault::Forbidden, 1);

    let first = rig.pass(later()).await;

    assert_eq!(rig.row(&reservation).await.0, "detach_failed");
    assert_eq!(world.usb.stored(GUEST), entries(&[(0, OURS_A)]));
    assert_eq!(first.released, 0);
    assert_eq!(rig.status(READER_A).await, DeviceStatus::Quarantined);
    assert_eq!(
        rig.audit("hardware_reconcile_finding").await[0]["finding"],
        "detach_failed"
    );

    // The retry, once the privilege is back, removes it and releases.
    let second = rig.pass(later() + 3 * PASS_INTERVAL_MS).await;
    assert_eq!(second.released, 1, "{second:?}");
    assert_eq!(rig.row(&reservation).await.0, "released");
    assert!(world.usb.stored(GUEST).is_empty());
}

#[tokio::test]
async fn a_delete_the_audit_sink_refused_is_not_made() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    rig.set_lease(&lease, "released").await;
    world.refuse_detach_intent.store(true, Ordering::SeqCst);

    let first = rig.pass(later()).await;

    assert!(world.usb.writes().is_empty(), "no intent, no delete");
    assert_eq!(world.usb.stored(GUEST), entries(&[(0, OURS_A)]));
    assert_eq!(rig.row(&reservation).await.0, "detach_failed");
    assert!(
        first
            .failures
            .iter()
            .any(|failure| failure.contains("nothing was deleted")),
        "{first:?}"
    );

    world.refuse_detach_intent.store(false, Ordering::SeqCst);
    let second = rig.pass(later() + 3 * PASS_INTERVAL_MS).await;
    assert_eq!(second.released, 1, "{second:?}");
    assert_eq!(world.usb.writes(), ["detach usb0"]);
}

// ---------------------------------------------------------------------
// Pacing of the periodic pass, and machine owners.
// ---------------------------------------------------------------------

#[tokio::test]
async fn the_periodic_pass_skips_a_row_that_just_changed_and_takes_it_later() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    rig.set_lease(&lease, "released").await;
    let base = now();

    // A saga step may still be running on a row that changed seconds ago.
    let early = rig.reconciler.tick(base).await.expect("due");
    assert_eq!(early.skipped, 1, "{early:?}");
    assert_eq!(rig.row(&reservation).await.0, "attached");
    assert!(world.usb.writes().is_empty());

    let late = rig
        .reconciler
        .tick(base + FRESH_ROW_MS + PASS_INTERVAL_MS)
        .await
        .expect("due");
    assert_eq!(late.released, 1, "{late:?}");
    assert_eq!(rig.row(&reservation).await.0, "released");
}

#[tokio::test]
async fn a_machine_owner_is_live_while_the_machine_exists_and_over_when_it_is_gone() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    sqlx::query("INSERT INTO machines (id, name, created_at, updated_at) VALUES ('machine-1', 'bench', 1, 1)")
        .execute(&rig.pool)
        .await
        .unwrap();
    let reservation = rig
        .seed_owner(
            ReservationOwnerKind::Machine,
            "machine-1",
            READER_A,
            "attached",
            GUEST,
            Some(0),
        )
        .await;
    world.usb.set_slot(GUEST, 0, OURS_A);

    let held = rig.pass(later()).await;
    assert_eq!(held.released, 0);
    assert_eq!(rig.row(&reservation).await.0, "attached");
    assert!(world.usb.writes().is_empty());

    sqlx::query("DELETE FROM machines WHERE id = 'machine-1'")
        .execute(&rig.pool)
        .await
        .unwrap();
    let gone = rig.pass(later() + MINUTE_MS).await;
    assert_eq!(gone.released, 1, "{gone:?}");
    assert_eq!(rig.row(&reservation).await.0, "released");
    assert_eq!(world.usb.writes(), ["detach usb0"]);
}

// ---------------------------------------------------------------------
// Restart mid-attach.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_restart_mid_attach_resumes_with_the_provision_and_a_released_lease_fails_closed() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("provisioning", true).await;
    let reservation = rig
        .seed(&lease, READER_A, "attaching", GUEST, Some(0))
        .await;
    // The write landed and the controller died before it recorded it.
    world.usb.set_slot(GUEST, 0, OURS_A);
    rig.kill().await;

    // The restarted controller's startup pass leaves a provision's own step
    // alone, even though the row changed moments ago.
    let rig = Rig::start(&world).await;
    let startup = rig.pass(now()).await;
    assert_eq!(rig.row(&reservation).await.0, "attaching");
    assert_eq!(startup.released, 0);
    assert!(world.usb.writes().is_empty());

    // The lease is released before the provision resumed: the row proves
    // nothing about the entry, so it is not adopted and not deleted.
    rig.set_lease(&lease, "released").await;
    let after = rig.pass(now()).await;
    assert_eq!(after.marked_unproven, 1, "{after:?}");
    assert_eq!(
        rig.row(&reservation).await,
        ("attach_unknown".to_owned(), None)
    );
    assert_eq!(world.usb.stored(GUEST), entries(&[(0, OURS_A)]));
    assert!(world.usb.writes().is_empty());
    assert_eq!(rig.status(READER_A).await, DeviceStatus::Quarantined);

    // It stays stuck, reported once, until the guest shows nothing.
    rig.pass(later() + 3 * PASS_INTERVAL_MS).await;
    assert_eq!(
        rig.row(&reservation).await.0,
        "attach_unknown",
        "still stuck while the entry is on the guest"
    );
    assert!(world.usb.writes().is_empty());
    let findings = rig.audit("hardware_reconcile_finding").await;
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding["finding"] == "unproven_entry")
            .count(),
        1,
        "{findings:?}"
    );

    // The operator removes it by hand; the next pass releases the row.
    world.usb.clear_slot(GUEST, 0);
    let last = rig.pass(later() + 20 * PASS_INTERVAL_MS).await;
    assert_eq!(last.released, 1, "{last:?}");
    assert_eq!(rig.row(&reservation).await.0, "released");
    assert_eq!(rig.status(READER_A).await, DeviceStatus::Available);
}

#[tokio::test]
async fn a_restart_after_a_repair_changes_nothing_more() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    rig.set_lease(&lease, "released").await;
    rig.pass(later()).await;
    assert_eq!(rig.row(&reservation).await.0, "released");
    rig.kill().await;

    let rig = Rig::start(&world).await;
    let again = rig.pass(now()).await;
    assert_eq!(again.released, 0);
    assert_eq!(again.entries_removed, 0);
    assert_eq!(world.usb.writes(), ["detach usb0"]);
}

// ---------------------------------------------------------------------
// An entry recorded for a released reservation.
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_entry_recorded_for_a_released_reservation_is_removed_when_nobody_holds_the_device() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(1)).await;
    // The row was released by the lease's own flow (slot kept as history),
    // and Fleet's write landed afterwards where it had recorded it.
    rig.set_lease(&lease, "released").await;
    world.usb.set_slot(GUEST, 1, OURS_A);
    sqlx::query(
        "UPDATE hardware_reservations SET state = 'released', released_at = ?2 WHERE id = ?1",
    )
    .bind(&reservation)
    .bind(now() - 10 * MINUTE_MS)
    .execute(&rig.pool)
    .await
    .unwrap();

    let report = rig.pass(now()).await;

    assert_eq!(report.entries_removed, 1, "{report:?}");
    assert!(world.usb.stored(GUEST).is_empty());
    assert_eq!(world.usb.writes(), ["detach usb1"]);
    let reconciled = rig.audit("hardware_reconciled").await;
    assert_eq!(reconciled[0]["outcome"], "leftover_removed");
    let intents = rig.audit("hardware_detach_requested").await;
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0]["leftover"], "true");
}

#[tokio::test]
async fn a_released_row_is_not_examined_when_another_owner_holds_the_device_or_it_was_overridden() {
    let world = World::new(0).await;
    world.guests(&[GUEST, OTHER_GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    // A: released with its slot, but a new live reservation holds the device.
    let old = rig.lease("ready", true).await;
    let first = rig.seed(&old, READER_A, "attached", GUEST, Some(0)).await;
    sqlx::query(
        "UPDATE hardware_reservations SET state = 'released', released_at = ?2 WHERE id = ?1",
    )
    .bind(&first)
    .bind(now() - 10 * MINUTE_MS)
    .execute(&rig.pool)
    .await
    .unwrap();
    let holder = rig.lease("ready", true).await;
    rig.seed(&holder, READER_A, "held", GUEST, None).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    // B: released by an override, which clears the slot: nothing recorded.
    let lease_b = rig.lease("ready", true).await;
    let second = rig
        .seed(&lease_b, READER_B, "attached", OTHER_GUEST, Some(0))
        .await;
    rig.reservations
        .override_release(
            &AuditContext {
                actor: PRINCIPAL.to_owned(),
                operation_id: None,
            },
            &second,
            now() - 10 * MINUTE_MS,
        )
        .await
        .unwrap();
    world
        .usb
        .set_slot(OTHER_GUEST, 0, "mapping=fm-test-reader-b");

    let report = rig.pass(now()).await;

    assert_eq!(report.entries_removed, 0, "{report:?}");
    assert!(world.usb.writes().is_empty());
    assert_eq!(world.usb.stored(GUEST), entries(&[(0, OURS_A)]));
    assert_eq!(
        world.usb.stored(OTHER_GUEST),
        entries(&[(0, "mapping=fm-test-reader-b")])
    );
    assert_eq!(rig.status(READER_B).await, DeviceStatus::ExternallyAttached);
}

// ---------------------------------------------------------------------
// Bounded, paced, audited.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_pass_reads_a_bounded_number_of_guests_and_the_rest_wait() {
    const BULK: usize = MAX_GUEST_READS_PER_PASS + 8;
    let world = World::new(BULK).await;
    let vmids: Vec<u32> = (0..BULK)
        .map(|index| 9200 + u32::try_from(index).unwrap())
        .collect();
    world.guests(&vmids).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    for (index, vmid) in vmids.iter().enumerate() {
        let mapping = format!("fm-test-bulk-{index}");
        rig.seed(&lease, &mapping, "attached", *vmid, Some(0)).await;
        world.usb.set_slot(*vmid, 0, &format!("mapping={mapping}"));
    }
    rig.set_lease(&lease, "released").await;

    let first = rig.pass(later()).await;
    assert_eq!(first.guest_reads, MAX_GUEST_READS_PER_PASS, "{first:?}");
    assert_eq!(first.released, MAX_GUEST_READS_PER_PASS);
    assert_eq!(first.deferred, 8);
    assert_eq!(world.usb.writes().len(), MAX_GUEST_READS_PER_PASS);

    // The rest finish on the next pass; nothing was read twice.
    let second = rig.pass(later() + MINUTE_MS).await;
    assert_eq!(second.released, 8, "{second:?}");
    assert_eq!(second.deferred, 0);
    assert_eq!(world.usb.writes().len(), BULK);
    let third = rig.pass(later() + 2 * MINUTE_MS).await;
    assert_eq!(third.rows_seen, 0);
    assert_eq!(third.guest_reads, 0);
}

#[tokio::test]
async fn the_periodic_pass_is_paced_and_a_failed_pass_backs_off() {
    let world = World::new(0).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let base = now();

    // Due at once, then not before the interval.
    assert!(rig.reconciler.tick(base).await.is_some());
    assert!(
        rig.reconciler
            .tick(base + PASS_INTERVAL_MS - 1)
            .await
            .is_none()
    );
    assert!(rig.reconciler.tick(base + PASS_INTERVAL_MS).await.is_some());

    // A store that cannot be read fails the pass, and the next one waits
    // twice as long.
    sqlx::query("ALTER TABLE hardware_reservations RENAME TO hardware_reservations_away")
        .execute(&rig.pool)
        .await
        .unwrap();
    let at = base + 2 * PASS_INTERVAL_MS;
    let failed = rig.reconciler.tick(at).await.expect("due");
    assert!(failed.pass_failed, "{failed:?}");
    assert!(
        rig.reconciler
            .tick(at + PASS_INTERVAL_MS + 1)
            .await
            .is_none()
    );
    sqlx::query("ALTER TABLE hardware_reservations_away RENAME TO hardware_reservations")
        .execute(&rig.pool)
        .await
        .unwrap();
    let recovered = rig
        .reconciler
        .tick(at + 2 * PASS_INTERVAL_MS + 1)
        .await
        .expect("due after the backoff");
    assert!(!recovered.pass_failed, "{recovered:?}");
    assert!(
        rig.reconciler
            .tick(at + 2 * PASS_INTERVAL_MS + 2)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn the_sweeper_runs_the_reconciler_and_the_audit_carries_no_secret() {
    let world = World::new(0).await;
    world.guests(&[GUEST]).await;
    let rig = Rig::start(&world).await;
    rig.refresh().await;
    let lease = rig.lease("ready", true).await;
    let reservation = rig.seed(&lease, READER_A, "attached", GUEST, Some(0)).await;
    world.usb.set_slot(GUEST, 0, OURS_A);
    rig.set_lease(&lease, "released").await;

    let report = rig.sweeper.tick(later()).await.unwrap();

    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(rig.row(&reservation).await.0, "released");
    assert_eq!(world.usb.writes(), ["detach usb0"]);

    let reconciled = rig.audit("hardware_reconciled").await;
    assert_eq!(reconciled.len(), 1);
    let facts = &reconciled[0];
    assert_eq!(facts["outcome"], "entry_removed_and_released");
    assert_eq!(facts["reservation_id"], reservation);
    assert_eq!(facts["from_state"], "detaching");
    assert_eq!(facts["usb_slot"], "usb0");
    assert_eq!(facts["guest_vmid"], GUEST.to_string());
    assert_eq!(facts["mapping"], READER_A);
    assert_eq!(facts["pass"], "periodic");
    // Ids, states and slots only: no token, no host, no serial.
    let everything = rig.audit_text().await;
    assert!(!everything.contains(SECRET), "{everything}");
    assert!(!everything.contains(fake_pve::API_HOST), "{everything}");
    assert!(
        !everything.to_lowercase().contains("serial"),
        "{everything}"
    );
    // The store's own release event followed the intent.
    assert_eq!(rig.audit("hardware_released").await.len(), 1);
    assert_eq!(rig.audit("hardware_detach_requested").await.len(), 1);
}

#[tokio::test]
async fn an_account_with_no_devices_costs_nothing() {
    let world = World::new(0).await;
    let rig = Rig::start(&world).await;
    // Never refreshed: no devices are inventoried.
    let before = world.usb.log().len();
    let report = rig.pass(now()).await;
    assert_eq!(report.accounts_refreshed, 0);
    assert_eq!(report.rows_seen, 0);
    assert_eq!(
        world.usb.log().len(),
        before,
        "nothing is read from Proxmox"
    );
    assert!(rig.audit("hardware_refresh_started").await.is_empty());
}
