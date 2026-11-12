//! End-to-end `agentless.inventory` operations against a real sshd: the
//! trust gate, the real probe run, capability ingestion, and the snapshot;
//! and the endpoint guest OS rules of ADR 0021 (creation checks, the login
//! shell check, recording under the requester with an audit event).

use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_core::EndpointKind;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{AuditSink, MachineRepository, OperationRepository, Store};
use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

/// One running sshd bound to an ephemeral port with its own host key.
struct TestSshd {
    child: Child,
    port: u16,
    keys_dir: tempfile::TempDir,
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An sshd whose sessions run `force`, a shell script that sees the
/// requested command in `$SSH_ORIGINAL_COMMAND`: it stands in for login
/// shells and wrappers this host does not have.
fn start_sshd_forcing(force: Option<&str>) -> TestSshd {
    let dir = tempfile::tempdir().unwrap();
    let force_line = force.map_or_else(String::new, |script| {
        let path = dir.path().join("force.sh");
        std::fs::write(&path, script).unwrap();
        format!("ForceCommand /bin/sh {}\n", path.display())
    });
    let host_key = dir.path().join("host_ed25519");
    let user_key = dir.path().join("user_ed25519");
    for key in [&host_key, &user_key] {
        let generated = Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-q")
            .arg("-f")
            .arg(key)
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "ssh-keygen failed: {:?}",
            generated.stderr
        );
    }
    let public = std::fs::read_to_string(format!("{}.pub", user_key.display())).unwrap();
    let authz = dir.path().join("authorized_keys");
    std::fs::write(&authz, public).unwrap();

    let port = free_port();
    let sshd_config = dir.path().join("sshd_config");
    let host_key_display = host_key.display().to_string();
    let authz_display = authz.display().to_string();
    let dir_display = dir.path().display().to_string();
    std::fs::write(
        &sshd_config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host_key_display}\n\
             AuthorizedKeysFile {authz_display}\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             StrictModes no\n\
             PidFile {dir_display}/sshd.pid\n\
             {force_line}\
             Subsystem sftp internal-sftp\n"
        ),
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&host_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::create_dir_all("/run/sshd").ok();
    }

    let child = Command::new("/usr/sbin/sshd")
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(&sshd_config)
        .spawn()
        .expect("sshd must start");
    for _ in 0..50 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    TestSshd {
        child,
        port,
        keys_dir: dir,
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "nobody".to_owned())
}

/// What one inventory run is set up with.
#[derive(Default)]
struct Run<'a> {
    /// The payload's `guestOs`, when any.
    payload_guest_os: Option<&'a str>,
    /// An OS recorded on the endpoint before the operation is created.
    recorded: Option<fleet_core::GuestOs>,
    /// A `ForceCommand` script standing in for the login shell.
    force: Option<&'a str>,
    /// Clear the endpoint's OS between creation and the run.
    clear_after_create: bool,
}

/// What one inventory run left behind.
struct Ran {
    /// The finished operation, or the creation refusal.
    operation: Result<fleet_application::operation::Operation, String>,
    /// The machine afterwards.
    machine: fleet_application::machine::Machine,
    /// The audit events' (actor, action, operation id, metadata JSON).
    audit: Vec<(String, String, Option<String>, String)>,
    /// Audit intents left without an outcome.
    open_intents: i64,
}

/// Registers a trusted machine on a real sshd, optionally records an
/// endpoint OS, then creates (through the real creation rules) and runs one
/// `agentless.inventory` operation.
async fn run_inventory(run: Run<'_>) -> Ran {
    run_inventory_as(run, &fleet_auth::LanAllowAllAuthorizer).await
}

async fn run_inventory_as(
    run: Run<'_>,
    authorizer: &dyn fleet_application::authz::Authorizer,
) -> Ran {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    std::mem::forget(store);
    let machines = MachineRepository::new(pool.clone());
    let operations = Operations::new_with_events_and_catalog_rollout_targets(
        std::sync::Arc::new(OperationRepository::new(pool.clone())),
        std::sync::Arc::new(AuditSink::new(pool.clone())),
        std::sync::Arc::new(fleet_application::events::EventHub::new(16)),
        std::sync::Arc::new(MachineRepository::new(pool.clone())),
    );
    let executor = fleet_controller::exec::ScriptExecutor::new(
        std::sync::Arc::new(MachineRepository::new(pool.clone())),
        dir.path().join("ssh"),
        ExecutionLimiter::new(4),
    );
    let sshd = start_sshd_forcing(run.force);
    let machine = machines
        .register(&RegisterMachine {
            name: "os-target".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: format!("{}@127.0.0.1:{}", whoami(), sshd.port),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let endpoint_id = machine.endpoints[0].id.clone();
    let provider = fleet_provider_ssh::SshProvider::new(dir.path().join("ssh")).unwrap();
    let observation = provider
        .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
        .unwrap();
    provider.pin(&observation).unwrap();
    machines
        .confirm_fingerprint(&endpoint_id, &observation.fingerprint, 0)
        .await
        .unwrap();
    if let Some(os) = run.recorded {
        machines.record_endpoint_os(&endpoint_id, os).await.unwrap();
    }
    let mut payload = serde_json::json!({
        "machineId": machine.id,
        "endpointId": endpoint_id,
        "timeoutSeconds": 60,
        // A caller cannot name the requester: creation overwrites it.
        "requestedBy": "someone-else",
        "auth": {"type": "identityFile", "path": format!("{}/user_ed25519", sshd.keys_dir.path().display())}
    });
    if let Some(os) = run.payload_guest_os {
        payload["guestOs"] = serde_json::json!(os);
    }
    let created = operations
        .create(
            authorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "agentless.inventory".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(payload.to_string()),
                review_token: None,
            },
        )
        .await;
    if run.clear_after_create {
        machines.clear_endpoint_os(&endpoint_id).await.unwrap();
    }
    let operation = match created {
        Err(error) => Err(error.to_string()),
        Ok(operation) => {
            operations
                .tick(
                    &executor,
                    "worker-a",
                    fleet_core::SystemClock::now_unix_millis(),
                    60_000,
                )
                .await
                .unwrap();
            Ok(operations
                .get(
                    &fleet_auth::LanAllowAllAuthorizer,
                    "anonymous-lan-admin",
                    &operation.id,
                )
                .await
                .unwrap())
        }
    };
    let machine = machines.get(&machine.id).await.unwrap();
    let audit = sqlx::query_as(
        "SELECT actor, action, operation_id, metadata_json FROM audit_events ORDER BY seq",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let open_intents = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events AS intent WHERE outcome IS NULL \
         AND operation_id IS NOT NULL AND NOT EXISTS \
         (SELECT 1 FROM audit_events AS done WHERE done.intent_seq = intent.seq)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    Ran {
        operation,
        machine,
        audit,
        open_intents,
    }
}

fn error_reason(operation: &fleet_application::operation::Operation) -> String {
    let error: serde_json::Value =
        serde_json::from_str(operation.error_json.as_deref().unwrap_or("{}")).unwrap();
    error["reason"].as_str().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn an_inventory_operation_probes_and_ingests() {
    let ran = run_inventory(Run::default()).await;
    let finished = ran.operation.unwrap();
    assert_eq!(finished.state, "succeeded", "{:?}", finished.error_json);
    let result: serde_json::Value = serde_json::from_str(&finished.result_json.unwrap()).unwrap();
    let fact_count = result["facts"].as_u64().unwrap();
    assert!(
        fact_count >= 10,
        "the real probe produced a full baseline: {result}"
    );
    // ADR 0021: the unknown endpoint ran the login-shell check first, and a
    // POSIX shell is recorded as Linux; the probe is unchanged.
    assert_eq!(result["guestOs"], "linux");
    assert_eq!(
        ran.machine.endpoints[0].guest_os,
        Some(fleet_core::GuestOs::Linux)
    );
    let family = ran
        .machine
        .capabilities
        .iter()
        .find(|fact| fact.namespace == "os" && fact.name == "family")
        .and_then(|fact| fact.value.clone());
    assert_eq!(family.as_deref(), Some("Linux"));
    // The record is audited under the operation's requester (written at
    // creation, not the payload's claim) and names the operation.
    let recorded = ran
        .audit
        .iter()
        .find(|(_, _, _, metadata)| metadata.contains("endpoint_os_recorded"))
        .expect("an audit event for the recorded OS");
    assert_eq!(recorded.0, "anonymous-lan-admin");
    assert_eq!(recorded.1, "machine.update");
    assert_eq!(recorded.2.as_deref(), Some(finished.id.as_str()));
    assert!(recorded.3.contains("linux"), "{}", recorded.3);
    // The record is a resolved event beside the operation's own intent,
    // which the completion resolved: no intent is left open.
    assert_eq!(ran.open_intents, 0);
}

/// `requestedBy` is stamped only where creation authorized `machine.update`
/// (an unknown endpoint). An inventory created against a recorded endpoint
/// names no requester (a caller's value is dropped), so if the record is
/// cleared before it runs, it detects and probes but records nothing.
#[tokio::test]
async fn only_an_authorized_creation_names_a_requester() {
    let ran = run_inventory(Run {
        recorded: Some(fleet_core::GuestOs::Linux),
        clear_after_create: true,
        ..Run::default()
    })
    .await;
    let finished = ran.operation.unwrap();
    assert_eq!(finished.state, "succeeded", "{:?}", finished.error_json);
    assert!(
        !finished
            .payload_json
            .as_deref()
            .unwrap_or_default()
            .contains("requestedBy"),
        "{:?}",
        finished.payload_json
    );
    assert_eq!(ran.machine.endpoints[0].guest_os, None, "nothing recorded");
    assert!(
        !ran.audit
            .iter()
            .any(|(_, _, _, metadata)| metadata.contains("endpoint_os_recorded"))
    );
}

/// An inventory naming an endpoint that does not exist is refused at
/// creation, not queued.
#[tokio::test]
async fn an_inventory_for_a_missing_endpoint_is_refused_at_creation() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    let machines = MachineRepository::new(pool.clone());
    let machine = machines
        .register(&RegisterMachine {
            name: "box".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Fleetd,
                reference: "node-identity".to_owned(),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let operations = Operations::new_with_events_and_catalog_rollout_targets(
        std::sync::Arc::new(OperationRepository::new(pool.clone())),
        std::sync::Arc::new(AuditSink::new(pool.clone())),
        std::sync::Arc::new(fleet_application::events::EventHub::new(16)),
        std::sync::Arc::new(MachineRepository::new(pool.clone())),
    );
    for endpoint_id in ["no-such-endpoint", machine.endpoints[0].id.as_str()] {
        let refused = operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &fleet_application::operation::NewOperation {
                    kind: "agentless.inventory".to_owned(),
                    payload_json: Some(
                        serde_json::json!({
                            "machineId": machine.id,
                            "endpointId": endpoint_id,
                            "timeoutSeconds": 60,
                            "auth": {"type": "agent"},
                        })
                        .to_string(),
                    ),
                    ..Default::default()
                },
            )
            .await;
        assert!(refused.is_err(), "{endpoint_id}: {refused:?}");
    }
}

/// #649: an inventory whose payload the creation rule cannot read — none,
/// not JSON, not an object, or without string `machineId` and `endpointId`
/// — is refused as invalid, never queued past the endpoint checks.
#[tokio::test]
async fn a_malformed_inventory_payload_is_refused_at_creation() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    let operation_repository = std::sync::Arc::new(OperationRepository::new(pool.clone()));
    let operations = Operations::new_with_events_and_catalog_rollout_targets(
        operation_repository.clone(),
        std::sync::Arc::new(AuditSink::new(pool.clone())),
        std::sync::Arc::new(fleet_application::events::EventHub::new(16)),
        std::sync::Arc::new(MachineRepository::new(pool.clone())),
    );
    let payloads = [
        None,
        Some("not json".to_owned()),
        Some("[]".to_owned()),
        Some(serde_json::json!({"machineId": "m"}).to_string()),
        Some(serde_json::json!({"endpointId": "e"}).to_string()),
        Some(serde_json::json!({"machineId": 1, "endpointId": "e"}).to_string()),
    ];
    for payload_json in payloads {
        let refused = operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &fleet_application::operation::NewOperation {
                    kind: "agentless.inventory".to_owned(),
                    payload_json: payload_json.clone(),
                    ..Default::default()
                },
            )
            .await;
        assert!(
            matches!(
                refused,
                Err(fleet_application::operation::OperationUseCaseError::Invalid { .. })
            ),
            "{payload_json:?}: {refused:?}"
        );
    }
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(queued, 0, "nothing was queued");
}

/// Once recorded, the payload's guest OS is a check, refused at creation
/// with `guest_os_mismatch` before anything is queued; a match runs.
#[tokio::test]
async fn a_recorded_endpoint_refuses_a_contradicting_guest_os_at_creation() {
    for (payload, recorded) in [
        ("windows", fleet_core::GuestOs::Linux),
        ("linux", fleet_core::GuestOs::Windows),
    ] {
        let ran = run_inventory(Run {
            payload_guest_os: Some(payload),
            recorded: Some(recorded),
            ..Run::default()
        })
        .await;
        let refused = ran.operation.unwrap_err();
        assert!(refused.contains("guest_os_mismatch"), "{refused}");
        assert!(ran.machine.capabilities.is_empty(), "nothing was probed");
        assert_eq!(ran.machine.endpoints[0].guest_os, Some(recorded));
    }
    let ran = run_inventory(Run {
        payload_guest_os: Some("linux"),
        recorded: Some(fleet_core::GuestOs::Linux),
        ..Run::default()
    })
    .await;
    let finished = ran.operation.unwrap();
    assert_eq!(finished.state, "succeeded", "{:?}", finished.error_json);
}

/// An inventory that may record an unknown endpoint's OS needs
/// `machine.update` on the machine, not just `operation.create`.
#[tokio::test]
async fn an_unknown_endpoint_inventory_needs_machine_update() {
    #[derive(Debug)]
    struct NoMachineUpdate;
    impl fleet_application::authz::Authorizer for NoMachineUpdate {
        fn decide(
            &self,
            request: fleet_application::authz::AccessRequest<'_>,
        ) -> fleet_application::authz::Decision {
            if request.action == fleet_application::authz::Permission::MachineUpdate {
                fleet_application::authz::Decision::deny(
                    fleet_application::authz::ReasonId::PolicyAllow,
                )
            } else {
                fleet_application::authz::Decision::allow()
            }
        }
    }
    let ran = run_inventory_as(Run::default(), &NoMachineUpdate).await;
    assert!(ran.operation.is_err(), "denied without machine.update");
    assert_eq!(ran.machine.endpoints[0].guest_os, None);
    // A recorded endpoint records nothing, so operation.create suffices.
    let ran = run_inventory_as(
        Run {
            recorded: Some(fleet_core::GuestOs::Linux),
            ..Run::default()
        },
        &NoMachineUpdate,
    )
    .await;
    assert_eq!(ran.operation.unwrap().state, "succeeded");
}

/// An unknown endpoint detected as Linux refuses a caller who said
/// `windows`, rather than sending a PowerShell probe to Bash.
#[tokio::test]
async fn an_unknown_endpoint_detected_as_linux_refuses_a_windows_choice() {
    let ran = run_inventory(Run {
        payload_guest_os: Some("windows"),
        ..Run::default()
    })
    .await;
    let finished = ran.operation.unwrap();
    assert_eq!(finished.state, "failed");
    assert_eq!(error_reason(&finished), "guest_os_mismatch");
    assert_eq!(
        ran.machine.endpoints[0].guest_os,
        Some(fleet_core::GuestOs::Linux)
    );
}

/// A Linux login whose shell cannot answer the sniff (a forced command, csh,
/// `set -u`) keeps working: the check is treated as unrecognized, the probe
/// runs with the payload's OS, and nothing is recorded.
#[tokio::test]
async fn a_failed_sniff_on_linux_continues_and_records_nothing() {
    let ran = run_inventory(Run {
        force: Some(
            "case \"$SSH_ORIGINAL_COMMAND\" in\n\
             'echo fleet-shell'*) echo 'Undefined variable.' >&2; exit 1 ;;\n\
             *) exec /bin/sh -c \"$SSH_ORIGINAL_COMMAND\" ;;\n\
             esac\n",
        ),
        ..Run::default()
    })
    .await;
    let finished = ran.operation.unwrap();
    assert_eq!(finished.state, "succeeded", "{:?}", finished.error_json);
    assert_eq!(ran.machine.endpoints[0].guest_os, None);
    assert!(!ran.machine.capabilities.is_empty(), "the probe ran");
}

/// `cmd.exe`, PowerShell 7 on Windows and Git Bash are refused by the
/// inventory too, with the setup step, and nothing is recorded.
#[tokio::test]
async fn an_inventory_refuses_cmd_pwsh_and_git_bash() {
    for force in [
        // cmd.exe answers every command with the expanded sniff.
        "printf 'fleet-shell Windows_NT $PSVersionTable.PSEdition\\r\\n'\n",
        // PowerShell 7 on Windows.
        "printf 'fleet-shell\\r\\n%%OS%%\\r\\nCore\\r\\n7\\r\\nFullLanguage\\r\\nWin32NT\\r\\n'\n",
        // Git Bash: a POSIX answer, then uname names MINGW.
        "case \"$SSH_ORIGINAL_COMMAND\" in\n\
         'uname -s') echo MINGW64_NT-10.0-26100 ;;\n\
         *) exec /bin/sh -c \"$SSH_ORIGINAL_COMMAND\" ;;\n\
         esac\n",
    ] {
        let ran = run_inventory(Run {
            force: Some(force),
            ..Run::default()
        })
        .await;
        let finished = ran.operation.unwrap();
        assert_eq!(finished.state, "failed", "{force}");
        assert_eq!(error_reason(&finished), "unsupported_shell", "{force}");
        let detail: serde_json::Value =
            serde_json::from_str(finished.error_json.as_deref().unwrap()).unwrap();
        assert!(
            detail["detail"].as_str().unwrap().contains("DefaultShell"),
            "{detail}"
        );
        assert_eq!(ran.machine.endpoints[0].guest_os, None);
        assert!(ran.machine.capabilities.is_empty());
    }
}
