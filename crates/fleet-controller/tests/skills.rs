//! End-to-end skills operations against a real sshd (FM-302): the probe
//! against a stub CLI, deploy/undeploy argument flow, the absent-CLI
//! honest answer, checksum-verified install, and redaction.

use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{AuditSink, MachineRepository, OperationRepository, Store};
use sqlx::SqlitePool;
use std::time::Duration;

use std::process::Command;
mod common;
use common::{TestSshd, start_sshd, whoami};
use tokio::sync::Mutex;

/// The stub CLI and its install location are shared machine state; the
/// tests serialize their installation and removal.
static CLI_LOCK: Mutex<()> = Mutex::const_new(());

/// The composed fixture: store, operations, skills executor, and a
/// verified endpoint.
struct Fixture {
    _dir: tempfile::TempDir,
    operations: Operations,
    executor: fleet_controller::skills::SkillsExecutor,
    snapshots: std::sync::Arc<fleet_storage_sqlite::SkillsRepository>,
    machine_id: String,
    endpoint_id: String,
    identity_file: String,
}

async fn compose(sshd: &TestSshd) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool: SqlitePool = store.pool().clone();
    std::mem::forget(store);
    let machines = MachineRepository::new(pool.clone());
    let machine = machines
        .register(&RegisterMachine {
            name: "box".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: fleet_core::EndpointKind::Ssh,
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

    let executor_machines: std::sync::Arc<dyn MachinePort> =
        std::sync::Arc::new(MachineRepository::new(pool.clone()));
    let snapshots = std::sync::Arc::new(fleet_storage_sqlite::SkillsRepository::new(pool.clone()));
    let executor = fleet_controller::skills::SkillsExecutor::new(
        executor_machines,
        dir.path().join("ssh"),
        ExecutionLimiter::new(4),
    )
    .with_snapshot_port(snapshots.clone());
    let operations = Operations::new(
        std::sync::Arc::new(OperationRepository::new(pool.clone())),
        std::sync::Arc::new(AuditSink::new(pool.clone())),
    );
    Fixture {
        _dir: dir,
        operations,
        executor,
        snapshots,
        machine_id: machine.id,
        endpoint_id,
        identity_file: format!("{}/user_ed25519", sshd.keys_dir.path().display()),
    }
}

impl Fixture {
    fn auth_json(&self) -> serde_json::Value {
        serde_json::json!({"type": "identityFile", "path": self.identity_file})
    }

    async fn run_kind(
        &self,
        kind: &str,
        payload: serde_json::Value,
    ) -> (String, Option<String>, Option<String>) {
        let operation = self
            .operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &fleet_application::operation::NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(payload.to_string()),
                    review_token: None,
                },
            )
            .await
            .unwrap();
        self.operations
            .tick(
                &self.executor,
                "worker-a",
                fleet_core::SystemClock::now_unix_millis(),
                60_000,
            )
            .await
            .unwrap();
        let finished = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &operation.id,
            )
            .await
            .unwrap();
        (finished.state, finished.result_json, finished.error_json)
    }
}

/// Installs a stub CLI on the remote PATH: a shell script answering the
/// documented shapes and logging its arguments for assertions.
fn install_stub_cli(home: &str, sha_of_stub: Option<&str>) -> String {
    let bin_dir = format!("{home}/.local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let path = format!("{bin_dir}/skills-manager-cli");
    let stub = r#"#!/usr/bin/env bash
echo "$@" >> /tmp/fleet-stub-cli.log
printf '%q\n' "$@" >> /tmp/fleet-stub-argv.log
[ "$1" = "--json" ] && shift
case "$1" in
  --version) echo '{"version":"1.40.0"}' ;;
  agents) echo '[{"id":"claude_code","name":"Claude Code","skillsDir":"/secret/agent/path"}]' ;;
  presets) echo '[{"id":"default","name":"Default","description":"private","icon":"x","sort_order":0,"skill_count":1,"active":true}]' ;;
  skills)
    shift
    case "$1" in
      list) echo '[{"id":"hello","name":"Hello","description":"private text","path":"/secret/skill/path","enabled":true,"preset_ids":["default"],"deployed_to":["claude_code"],"source_ref":"private"}]' ;;
      check) echo '[{"skill_id":"hello","update_status":"update_available","last_check_error":"/secret/error"}]' ;;
      remove)
        if [ "$2" = conflict ]; then echo '{"ok":false,"code":"TARGET_CONFLICT","message":"blocked","error":{"paths":["/tmp/conflict"],"held_back_removals":["managed"]}}'; exit 2; fi
        echo '{"ok":true}'
        ;;
      deploy)
        skill=$2; shift 2
        agents=""
        for agent in "$@"; do
          [ "$agent" = "--agent" ] && continue
          [ -z "$agent" ] && continue
          agents="$agents\"$agent\","
        done
        agents="${agents%,}"
        echo "{\"skillId\":\"$skill\",\"deployedTo\":[$agents]}"
        ;;
      undeploy) echo "{\"skillId\":\"$2\",\"deployedTo\":[]}" ;;
    esac
    ;;
esac
exit 0
"#;
    std::fs::write(&path, stub).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    if let Some(expected) = sha_of_stub {
        let digest = Command::new("sha256sum").arg(&path).output().unwrap();
        let actual = String::from_utf8_lossy(&digest.stdout)
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(actual, expected, "the stub's digest must match the pin");
    }
    path
}

fn sha256_of(path: &str) -> String {
    let output = Command::new("sha256sum").arg(path).output().unwrap();
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn the_probe_answers_presence_version_and_agents() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home, None);
    std::fs::remove_file("/tmp/fleet-stub-cli.log").ok();

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 30,
    });
    let (state, result, error) = fixture.run_kind("skills.probe", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(result["snapshotRecorded"], true);
    assert_eq!(result["availability"], "available");
    let encoded = serde_json::to_string(&result).unwrap();
    assert!(!encoded.contains("hello"));
    let snapshot =
        fleet_application::skills::SkillsPort::get(fixture.snapshots.as_ref(), &fixture.machine_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(snapshot.cli_version.as_deref(), Some("1.40.0"));
    assert_eq!(
        snapshot.data["skills"][0]["updateStatus"],
        "update_available"
    );
    assert_eq!(snapshot.data["skills"][0]["deployedTo"][0], "claude_code");
    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains("/secret/"));
    assert!(!encoded.contains("private text"));
    assert!(!encoded.contains("private\""));
}

#[tokio::test]
async fn an_absent_cli_answers_honestly() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    // Run the probe through a shell whose PATH lacks the CLI: use a
    // dedicated stub-free PATH by pointing the probe at a root? The probe
    // scans `command -v`; instead remove the stub if present.
    let home = std::env::var("HOME").unwrap();
    let _ = std::fs::remove_file(format!("{home}/.local/bin/skills-manager-cli"));

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 30,
    });
    let (state, result, error) = fixture.run_kind("skills.probe", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(result["snapshotRecorded"], true);
    assert_eq!(result["availability"], "absent");
    let snapshot =
        fleet_application::skills::SkillsPort::get(fixture.snapshots.as_ref(), &fixture.machine_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(snapshot.update_check, "unavailable");
}

#[tokio::test]
async fn deploy_reaches_the_stub_with_an_argument_array() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home, None);
    std::fs::remove_file("/tmp/fleet-stub-cli.log").ok();

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "skillId": "db",
        "agents": ["claude_code", "codex"],
        "timeoutSeconds": 30,
    });
    let (state, result, error) = fixture.run_kind("skills.deploy", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(result["outcome"]["skillId"], "db");
    assert_eq!(
        result["outcome"]["deployedTo"],
        serde_json::json!(["claude_code", "codex"]),
        "each agent arrives as its own --agent pair, not a marker token"
    );

    let log = std::fs::read_to_string("/tmp/fleet-stub-cli.log").unwrap();
    assert!(
        log.contains("skills deploy db --agent claude_code --agent codex"),
        "the arguments arrive as an array: {log}"
    );
    assert!(!log.contains("--dry-run"), "a real deploy is not a dry run");
}

#[tokio::test]
async fn install_and_confirmed_remove_use_the_pinned_cli_argv_contract() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home, None);
    std::fs::remove_file("/tmp/fleet-stub-cli.log").ok();

    let base = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 30,
    });
    let (state, _, error) = fixture.run_kind("skills.install", base.clone()).await;
    assert_eq!(state, "failed", "a reference is required: {error:?}");
    let mut references_only = base.clone();
    references_only["references"] = serde_json::json!(["org/repo/skill"]);
    let (state, _, error) = fixture.run_kind("skills.install", references_only).await;
    assert_eq!(
        state, "failed",
        "install requires one --reference: {error:?}"
    );
    let mut install = base.clone();
    install["reference"] = serde_json::json!("org/repo/skill one");
    install["git"] = serde_json::json!(true);
    install["name"] = serde_json::json!("Friendly Skill");
    install["syncPreset"] = serde_json::json!("default");
    let (state, _, error) = fixture.run_kind("skills.install", install).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let log = std::fs::read_to_string("/tmp/fleet-stub-cli.log").unwrap();
    assert!(
        log.contains(
            "skills install org/repo/skill one --git --name Friendly Skill --sync-preset default"
        ),
        "{log}"
    );
    assert!(
        !log.contains("--yes"),
        "install never receives destructive confirmation: {log}"
    );

    let mut remove = base;
    remove["reference"] = serde_json::json!("skill-id");
    remove["confirm"] = serde_json::json!(true);
    remove["dryRun"] = serde_json::json!(true);
    let (state, _, error) = fixture.run_kind("skills.remove", remove).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let log = std::fs::read_to_string("/tmp/fleet-stub-cli.log").unwrap();
    assert!(
        log.contains("skills remove skill-id --yes --dry-run"),
        "{log}"
    );

    let bulk_remove = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "references": ["skill-a", "skill b"],
        "confirm": true,
        "dryRun": true,
        "timeoutSeconds": 30,
    });
    let (state, _, error) = fixture.run_kind("skills.remove", bulk_remove).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let log = std::fs::read_to_string("/tmp/fleet-stub-cli.log").unwrap();
    assert!(
        log.contains("skills remove skill-a skill b --yes --dry-run"),
        "{log}"
    );
    let argv = std::fs::read_to_string("/tmp/fleet-stub-argv.log").unwrap();
    assert!(
        argv.lines()
            .collect::<Vec<_>>()
            .windows(5)
            .any(|args| { args == ["skills", "remove", "skill-a", "skill\\ b", "--yes"] }),
        "{argv}"
    );

    let adopt = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "path": "/tmp/one",
        "paths": ["/tmp/two"],
        "sourceUrl": "https://example.invalid/org/repo",
        "gitSubpath": "skills/sub",
        "dryRun": true,
        "timeoutSeconds": 30,
    });
    let (state, _, error) = fixture.run_kind("skills.adopt", adopt).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let log = std::fs::read_to_string("/tmp/fleet-stub-cli.log").unwrap();
    assert!(
        log.contains("skills adopt /tmp/one /tmp/two --git-url https://example.invalid/org/repo --git-subpath skills/sub --dry-run"),
        "{log}"
    );

    let conflict = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "reference": "conflict",
        "confirm": true,
        "timeoutSeconds": 30,
    });
    let (state, _, error) = fixture.run_kind("skills.remove", conflict).await;
    assert_eq!(state, "failed");
    let error: serde_json::Value = serde_json::from_str(&error.unwrap()).unwrap();
    assert_eq!(error["reason"], "TARGET_CONFLICT");
    assert_eq!(error["data"]["paths"][0], "/tmp/conflict");
    assert_eq!(error["data"]["held_back_removals"][0], "managed");

    let preset_update = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "reference": "preset",
        "name": "Renamed",
        "description": "Safe text",
        "icon": "book",
        "timeoutSeconds": 30,
    });
    let (state, _, error) = fixture.run_kind("presets.update", preset_update).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let log = std::fs::read_to_string("/tmp/fleet-stub-cli.log").unwrap();
    assert!(
        log.contains("presets update preset --name Renamed --description Safe text --icon book"),
        "{log}"
    );
}

#[tokio::test]
async fn a_dry_run_stays_a_dry_run() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home, None);
    std::fs::remove_file("/tmp/fleet-stub-cli.log").ok();

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "skillId": "db",
        "agents": ["claude_code"],
        "dryRun": true,
        "timeoutSeconds": 30,
    });
    let (state, _result, error) = fixture.run_kind("skills.deploy", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let log = std::fs::read_to_string("/tmp/fleet-stub-cli.log").unwrap();
    assert!(
        log.contains("--dry-run"),
        "the dry run reaches the CLI: {log}"
    );
}

#[tokio::test]
async fn a_leading_dash_id_is_refused_before_any_ssh_work() {
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "skillId": "--flag",
        "agents": ["claude_code"],
        "timeoutSeconds": 10,
    });
    let (state, _result, error) = fixture.run_kind("skills.deploy", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the refusal names its reason");
    assert!(error.contains("dash"), "{error}");
}

#[tokio::test]
async fn the_pinned_install_verifies_the_checksum() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _ = std::fs::remove_file(format!("{home}/.local/bin/skills-manager-cli"));
    // The stub serves as the "release artifact" served over a local file
    // URL; its digest pins the install.
    let staged = format!("/tmp/fleet-sm-release-{}", std::process::id());
    install_stub_cli(&home, None);
    std::fs::copy(format!("{home}/.local/bin/skills-manager-cli"), &staged).unwrap();
    let digest = sha256_of(&staged);
    // The CLI must be absent for the pinned install to run.
    let _ = std::fs::remove_file(format!("{home}/.local/bin/skills-manager-cli"));

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "artifactUrl": format!("file://{staged}"),
        "artifactSha256": digest,
        "timeoutSeconds": 60,
    });
    let (state, result, error) = fixture.run_kind("skills.probe", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(result["snapshotRecorded"], true);
    assert_eq!(result["availability"], "available");
    assert!(
        format!("{home}/.local/bin/skills-manager-cli")
            .lines()
            .count()
            > 0,
        "the binary landed"
    );

    // A mismatched digest refuses loudly.
    let _ = std::fs::remove_file(format!("{home}/.local/bin/skills-manager-cli"));
    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "artifactUrl": format!("file://{staged}"),
        "artifactSha256": "0".repeat(64),
        "timeoutSeconds": 60,
    });
    let (state, result, error) = fixture.run_kind("skills.probe", payload).await;
    assert_eq!(state, "failed");
    assert!(result.is_none());
    assert!(error.unwrap().contains("checksum did not match"));
    let retained =
        fleet_application::skills::SkillsPort::get(fixture.snapshots.as_ref(), &fixture.machine_id)
            .await
            .unwrap()
            .unwrap();
    assert!(matches!(
        retained.availability,
        fleet_application::skills::SkillsAvailability::Available
    ));

    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_file(format!("{home}/.local/bin/skills-manager-cli"));
}

#[tokio::test]
async fn credential_shaped_cli_output_is_redacted() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    // A stub that fails with a credential-bearing message.
    let bin_dir = format!("{home}/.local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let path = format!("{bin_dir}/skills-manager-cli");
    std::fs::write(
        &path,
        "#!/usr/bin/env bash\ncase \"$1\" in\n  --version) echo \"skills-manager-cli 1.40.0\"; exit 0 ;;\nesac\necho '{\"ok\":false,\"code\":\"TARGET_CONFLICT\",\"message\":\"refused https://user:secret@host.invalid/x\"}' >&2\nexit 2\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "skillId": "db",
        "agents": ["claude_code"],
        "timeoutSeconds": 30,
    });
    let (state, _result, error) = fixture.run_kind("skills.deploy", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the failure carries a detail");
    assert!(!error.contains("secret"), "{error}");
    assert!(error.contains("***@host.invalid"), "{error}");
    let _ = std::fs::remove_file(&path);
}
