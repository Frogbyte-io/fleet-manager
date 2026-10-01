//! The real-cluster acceptance suite for the M6 exit gate (FM-611).
//!
//! Each scenario is its own test. It drives the real `fleet-controller`
//! binary (API, worker, and the pinned PVE transport) and the real
//! `fleetctl` against every live target configured through
//! `FLEET_PVE_TARGET_<NAME>_*`. Without `FLEET_PVE_LIVE=1` every scenario
//! prints a skipped result line and passes; with the gate on, a missing
//! variable is a loud failure. `cargo xtask pve-acceptance` runs the suite
//! and turns the result lines into a JSON summary.
//!
//! The variable contract, the cleanup guarantees, and how to run it are in
//! `docs/operations/proxmox-test-cluster.md` (step 7) and the PR for #214.
//! The unit tests at the bottom run without any PVE.

#[macro_use]
mod proxmox_live_support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_core::{CapabilityFact, CapabilityStatus, SensitiveString, Timestamp};
use fleet_provider_proxmox::{
    PveCredentials, PveHttpMethod, PveHttpRequest, PveTransport as _, PveTransportError,
    ReqwestPveTransport, normalize_fingerprint,
};
use proxmox_live_support::{Outcome, Suite, TargetRun, operation_error, operation_result};
use serde_json::{Value, json};

/// Runs one scenario body on every selected target, sequentially, each
/// with its own swept range and fresh controller, then fails the test if
/// any target failed.
macro_rules! scenario {
    ($test:ident, $id:literal, $body:ident) => {
        #[tokio::test]
        async fn $test() {
            let Some(mut suite) = Suite::begin($id) else {
                return;
            };
            for target in suite.targets() {
                let started = Instant::now();
                // An inapplicable target skips before any sweep or
                // controller: the skip never depends on reaching PVE.
                if let Some(reason) = skip_reason($id, &target) {
                    suite.record(&target, &Ok(Outcome::Skipped(reason)), started);
                    continue;
                }
                let result = match TargetRun::start(target.clone(), $id).await {
                    Ok(run) => {
                        let result = $body(&run).await;
                        run.finish(result).await
                    }
                    Err(reason) => Err(reason),
                };
                suite.record(&target, &result, started);
            }
            suite.conclude();
        }
    };
}

scenario!(live_trust, "trust", trust);
scenario!(
    live_privilege_failure,
    "privilege-failure",
    privilege_failure
);
scenario!(live_task_polling, "task-polling", task_polling);
scenario!(live_destructive_gate, "destructive-gate", destructive_gate);
scenario!(live_association, "association", association);
scenario!(
    live_partial_node_failure,
    "partial-node-failure",
    partial_node_failure
);

/// Why a scenario does not apply to a target, when it does not. The
/// partial-node scenario needs a cluster target; the privilege scenario
/// needs the optional read-only token. Neither skip is ever silent: it is a
/// result line the runner records.
fn skip_reason(scenario: &str, target: &proxmox_live_support::config::Target) -> Option<String> {
    match scenario {
        "privilege-failure" if target.ro_token.is_none() => Some(format!(
            "skipped: no read-only token ({} and {} are unset)",
            target.var("RO_TOKEN_ID"),
            target.var("RO_TOKEN_SECRET_FILE")
        )),
        "partial-node-failure" if target.down.is_none() => Some(format!(
            "skipped: no cluster target ({} and {} are unset)",
            target.var("DOWN_NODE"),
            target.var("DOWN_ROLE")
        )),
        _ => None,
    }
}

/// An all-zero pin: never a real certificate.
fn wrong_fingerprint() -> String {
    "00".repeat(32)
}

/// Scenario 1: observe → confirm → discovery, and a wrong pin refused at
/// the TLS handshake before any credential is sent.
async fn trust(run: &TargetRun) -> Result<Outcome, String> {
    let target = &run.target;
    let account = run
        .create_account("acceptance-trust", &target.token)
        .await?;
    let base = format!("/api/v1/proxmox/accounts/{account}");

    // Discovery is locked until trust is confirmed.
    let (status, body) = run.controller.get(&format!("{base}/discovery")).await?;
    check!(
        status == 409 && body["code"] == "proxmox_unconfirmed",
        "discovery before trust answered {status}: {body}"
    );

    // Observe: the probe captures the fingerprint and refuses the
    // handshake, so no credential leaves.
    let (status, body) = run
        .controller
        .post(&format!("{base}/observe"), &json!({}))
        .await?;
    check!(status == 200, "observe answered {status}: {body}");
    let observed = body["data"]["fingerprint"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    check!(
        normalize_fingerprint(&observed) == target.fingerprint,
        "the observed fingerprint is not {}",
        target.var("FINGERPRINT")
    );

    // A fingerprint the probe did not see is refused, and trust stays off.
    let (status, body) = run
        .controller
        .post(
            &format!("{base}/confirm"),
            &json!({ "fingerprint": wrong_fingerprint() }),
        )
        .await?;
    check!(
        status == 400,
        "confirming a wrong fingerprint answered {status}: {body}"
    );
    let (_, body) = run
        .controller
        .get("/api/v1/proxmox/accounts?limit=200")
        .await?;
    let state = body["items"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["id"] == account.as_str()))
        .map(|item| item["fingerprintState"].clone())
        .unwrap_or(Value::Null);
    check!(
        state == "unconfirmed",
        "after a refused confirm the account's trust is {state}"
    );

    // Confirm what was observed, then discover.
    run.trust(&account).await?;
    let (status, body) = run.controller.get(&format!("{base}/discovery")).await?;
    check!(status == 200, "discovery answered {status}: {body}");
    let data = &body["data"];
    check!(
        data["pveVersion"]
            .as_str()
            .is_some_and(|version| !version.is_empty()),
        "discovery reported no PVE version"
    );
    let node = data["nodeCapacities"]
        .as_array()
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|node| node["node"] == target.node.as_str())
        })
        .ok_or_else(|| format!("discovery has no capacity for {}", target.var("NODE")))?;
    check!(
        node["storages"].as_array().is_some_and(|storages| storages
            .iter()
            .any(|s| s["storage"] == target.storage.as_str())),
        "discovery does not report {} on the node",
        target.var("STORAGE")
    );
    check!(
        data["resources"]
            .as_array()
            .is_some_and(|resources| resources
                .iter()
                .any(|r| { r["vmid"] == target.template_vmid && r["kind"] == "qemu-template" })),
        "discovery does not list {} as a qemu template",
        target.var("TEMPLATE_VMID")
    );
    run.log(&format!("discovery ok, PVE {}", data["pveVersion"]));

    // The controller's own path: the host's certificate "changes" (the
    // pinned value is rewritten to a wrong one, which is the only way to
    // simulate a changed certificate without touching the host). The next
    // call is refused at the handshake and names both fingerprints.
    // The store admits one controller, so the controller is stopped around
    // the write and restarted on the same data and address.
    run.controller
        .with_store(async |store| {
            sqlx::query("UPDATE proxmox_accounts SET fingerprint = ?1 WHERE id = ?2")
                .bind(wrong_fingerprint())
                .bind(&account)
                .execute(store.pool())
                .await
                .map(|_| ())
                .map_err(|error| format!("cannot rewrite the pin: {error}"))
        })
        .await?;
    let (status, body) = run.controller.get(&format!("{base}/discovery")).await?;
    check!(
        status == 409 && body["code"] == "proxmox_fingerprint_mismatch",
        "discovery under a wrong pin answered {status} {}",
        body["code"]
    );
    let message = normalize_fingerprint(body["message"].as_str().unwrap_or_default());
    check!(
        message.contains(&target.fingerprint),
        "the mismatch does not report the host's real fingerprint"
    );

    // The transport directly, with a canary credential: even a regression
    // that sent it would leak nothing real. The refusal must be the
    // handshake's fingerprint mismatch, which happens before the HTTP
    // request (and its Authorization header) is written.
    let mut canary = [0_u8; 16];
    getrandom::getrandom(&mut canary).map_err(|error| error.to_string())?;
    let request = PveHttpRequest {
        host: target.host.clone(),
        port: target.port,
        path: "/api2/json/version".to_owned(),
        pinned_fingerprint: Some(wrong_fingerprint()),
        credentials: Arc::new(PveCredentials {
            token_id: "fleet-acceptance@pve!canary".to_owned(),
            token: SensitiveString::new(
                canary
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            ),
        }),
        method: PveHttpMethod::Get,
    };
    match ReqwestPveTransport::new().execute(request).await {
        Err(PveTransportError::FingerprintMismatch { observed, .. }) => check!(
            normalize_fingerprint(&observed) == target.fingerprint,
            "the handshake refusal reports a different certificate"
        ),
        Err(other) => {
            return Err(format!(
                "a wrong pin was refused with {other}, not a fingerprint mismatch"
            ));
        }
        Ok(response) => {
            return Err(format!(
                "a wrong pin was NOT refused: the host answered HTTP {}",
                response.status
            ));
        }
    }
    Ok(Outcome::Pass)
}

/// Scenario 2: the read-only token discovers, a lifecycle operation ends
/// in the honest privilege failure, and the privileges report says
/// `operate: missing`.
async fn privilege_failure(run: &TargetRun) -> Result<Outcome, String> {
    let target = &run.target;
    let Some(ro) = &target.ro_token else {
        return Ok(Outcome::Skipped(
            skip_reason("privilege-failure", target).unwrap_or_default(),
        ));
    };
    let account = run.trusted_account("acceptance-readonly", ro).await?;
    let base = format!("/api/v1/proxmox/accounts/{account}");

    let (status, body) = run.controller.get(&format!("{base}/discovery")).await?;
    check!(
        status == 200,
        "read-only discovery answered {status}: {body}"
    );
    check!(
        body["data"]["resources"]
            .as_array()
            .is_some_and(|r| !r.is_empty()),
        "read-only discovery listed no resources"
    );

    // The privileges report, through the operator's CLI.
    let answer = run
        .controller
        .fleetctl(
            &proxmox_live_support::args(&["proxmox", "privileges", &account]),
            None,
        )
        .await?;
    check!(
        answer.success,
        "fleetctl proxmox privileges failed: {}",
        answer.stderr
    );
    check_readonly_report(&answer.json, "fleetctl proxmox privileges")?;
    // The API answers the same report: the privileges response (not the
    // discovery one) says discover granted, operate missing.
    let (status, privileges) = run.controller.get(&format!("{base}/privileges")).await?;
    check!(
        status == 200,
        "the privileges API answered {status}: {privileges}"
    );
    check_readonly_report(&privileges["data"], "the privileges API")?;

    // A lifecycle start on a VMID the range reserves (nothing is created:
    // the token cannot) ends in the honest privilege failure.
    let vmid = run.guard.allocate().await?;
    let data = run
        .lifecycle(&account, "start", &target.node, vmid, 120)
        .await?;
    check!(
        data["state"] == "failed",
        "a read-only start ended {}",
        data["state"]
    );
    let (_, detail) = operation_error(&data);
    check!(
        detail.contains("lacks the privilege (403)"),
        "the failure is not the privilege refusal: {detail}"
    );
    check!(
        run.pve.resource(vmid).await?.is_none(),
        "a guest {vmid} exists after a refused start"
    );
    Ok(Outcome::Pass)
}

/// The status of `name` in a privileges report's `tiers`, or `absent`.
fn tier_status(report: &Value, name: &str) -> String {
    report["tiers"]
        .as_array()
        .and_then(|tiers| tiers.iter().find(|tier| tier["tier"] == name))
        .and_then(|tier| tier["status"].as_str())
        .unwrap_or("absent")
        .to_owned()
}

/// A read-only token's privileges report: discover granted, operate
/// missing, and a known (not refused) evaluation.
fn check_readonly_report(report: &Value, source: &str) -> Result<(), String> {
    let discover = tier_status(report, "discover");
    check!(
        discover == "granted",
        "{source}: the read-only token's discover tier is {discover}"
    );
    let operate = tier_status(report, "operate");
    check!(
        operate == "missing",
        "{source}: the read-only token's operate tier is {operate}"
    );
    check!(
        report["unknownReason"].is_null(),
        "{source}: the privileges report is unknown: {}",
        report["unknownReason"]
    );
    Ok(())
}

/// Scenario 3: clone through the review gate, start and shutdown with
/// `--wait`, PVE's own task records as the UPID evidence, and a
/// cancellation mid-poll that records the remote task continuing.
async fn task_polling(run: &TargetRun) -> Result<Outcome, String> {
    let target = &run.target;
    let node = target.node.as_str();
    let account = run
        .trusted_account("acceptance-polling", &target.token)
        .await?;
    let vmid = run.clone_scratch(&account, "poll").await?;

    let data = run.lifecycle(&account, "start", node, vmid, 300).await?;
    check!(
        data["state"] == "succeeded",
        "start ended {}: {}",
        data["state"],
        data["errorJson"]
    );
    let result = operation_result(&data);
    check!(
        result["taskState"] == "ok" && result["action"] == "start",
        "start's result is not task OK: {result}"
    );
    check!(
        data["progressMessage"]
            .as_str()
            .is_some_and(|message| message.contains(&format!("qemu/{vmid}"))),
        "start recorded no progress for the guest: {}",
        data["progressMessage"]
    );
    task_evidence(run, vmid, "qmstart").await?;
    check!(
        run.pve.power_state(node, vmid).await? == "running",
        "PVE does not report the guest running after start"
    );

    // Shutdown needs a guest that answers; wait for its agent first.
    wait_for_agent(run, vmid, Duration::from_secs(300)).await?;
    let data = run.lifecycle(&account, "shutdown", node, vmid, 300).await?;
    check!(
        data["state"] == "succeeded",
        "shutdown ended {}: {}",
        data["state"],
        data["errorJson"]
    );
    check!(
        operation_result(&data)["taskState"] == "ok",
        "shutdown's result is not task OK"
    );
    task_evidence(run, vmid, "qmshutdown").await?;
    check!(
        run.pve.power_state(node, vmid).await? == "stopped",
        "PVE does not report the guest stopped after shutdown"
    );

    cancel_mid_poll(run, &account).await?;
    Ok(Outcome::Pass)
}

/// PVE's own record of the task Fleet polled: at least one task of this
/// type for the guest, stopped with `OK`.
async fn task_evidence(run: &TargetRun, vmid: u32, kind: &str) -> Result<(), String> {
    let tasks = run.pve.tasks(&run.target.node, vmid, kind).await?;
    let finished = tasks.iter().find(|task| {
        task["upid"]
            .as_str()
            .is_some_and(|upid| upid.contains(&format!(":{kind}:{vmid}:")))
            && task["status"] == "OK"
    });
    check!(
        finished.is_some(),
        "PVE has no finished {kind} task with status OK for guest {vmid}"
    );
    run.log(&format!("{kind} for {vmid}: PVE's task record is OK"));
    Ok(())
}

/// Polls PVE's agent ping until it answers.
async fn wait_for_agent(run: &TargetRun, vmid: u32, bound: Duration) -> Result<(), String> {
    let started = Instant::now();
    while !run.pve.agent_ping(&run.target.node, vmid).await {
        check!(
            started.elapsed() < bound,
            "the guest agent in {vmid} did not answer within {}s; the template needs qemu-guest-agent",
            bound.as_secs()
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Ok(())
}

/// A full clone (slow enough to poll), cancelled once the worker is
/// polling. The operation must record that the remote task keeps running,
/// and PVE must show that task finishing on its own afterwards.
async fn cancel_mid_poll(run: &TargetRun, account: &str) -> Result<(), String> {
    let target = &run.target;
    let vmid = target.range.check(run.guard.allocate().await?)?;
    let params = json!({
        "newId": vmid,
        "name": format!("fleet-acceptance-cancel-{vmid}"),
        "fullCopy": true,
    });
    let base = format!(
        "/api/v1/proxmox/accounts/{account}/guests/{}",
        target.template_vmid
    );
    let (status, review) = run
        .controller
        .post(
            &format!("{base}/clone/review"),
            &json!({ "node": target.node, "params": params }),
        )
        .await?;
    check!(
        status == 200,
        "the clone review answered {status}: {review}"
    );
    let (status, body) = run
        .controller
        .post(
            &format!("{base}/clone/run"),
            &json!({
                "node": target.node,
                "reviewToken": review["data"]["reviewToken"],
                "params": review["data"]["params"],
                "timeoutSeconds": 600,
            }),
        )
        .await?;
    check!(status == 202, "the clone run answered {status}: {body}");
    let id = body["data"]["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| format!("the clone run answered 202 without an operation id: {body}"))?
        .to_owned();

    // Wait until the worker has started the task (progress recorded and
    // the guest's clone lock visible), then cancel through the CLI.
    let started = Instant::now();
    loop {
        let (_, body) = run
            .controller
            .get(&format!("/api/v1/operations/{id}"))
            .await?;
        let running =
            body["data"]["state"] == "running" && body["data"]["progressTotal"].is_number();
        let locked = run
            .pve
            .resource(vmid)
            .await?
            .is_some_and(|r| r.lock.is_some());
        if running && locked {
            break;
        }
        check!(
            !matches!(body["data"]["state"].as_str(), Some("succeeded" | "failed")),
            "the full clone ended ({}) before it could be cancelled mid-poll; use a template with \
             a larger disk",
            body["data"]["state"]
        );
        check!(
            started.elapsed() < Duration::from_secs(120),
            "the clone never started polling"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let answer = run
        .controller
        .fleetctl(
            &proxmox_live_support::args(&["operations", "cancel", &id]),
            None,
        )
        .await?;
    check!(
        answer.success,
        "fleetctl operations cancel failed: {}",
        answer.stderr
    );

    let data = run.wait_operation(&id, Duration::from_secs(120)).await?;
    check!(
        data["state"] != "succeeded",
        "the full clone finished before the cancellation was observed; use a template with a larger disk"
    );
    let (reason, detail) = operation_error(&data);
    check!(
        reason == "cancelled" && detail.contains("keeps running"),
        "the cancellation is not recorded as the remote task continuing: {reason}: {detail}"
    );
    let upid = detail
        .split_whitespace()
        .find(|word| word.starts_with("UPID:"))
        .ok_or_else(|| format!("the cancellation names no UPID: {detail}"))?
        .to_owned();
    let still_running = run.pve.task_running(&upid).await?;
    run.log(&format!(
        "cancelled mid-poll; the remote clone task is {}",
        if still_running {
            "still running"
        } else {
            "already finished"
        }
    ));
    // The remote task was not stopped by the cancellation: it runs to its
    // own end, and the clone exists.
    let end = run.pve.wait_task(&upid, Duration::from_secs(900)).await?;
    check!(
        end.exitstatus == "OK",
        "the remote clone task did not finish on its own: {}",
        end.exitstatus
    );
    check!(
        run.pve.resource(vmid).await?.is_some(),
        "the remote clone finished but guest {vmid} does not exist"
    );
    // The guest is the sweep's (name prefix); tag it as well.
    run.pve
        .tag(&target.node, vmid, proxmox_live_support::guard::TAG)
        .await?;
    Ok(())
}

/// Scenario 4: snapshot create → idempotent re-run → rollback → delete
/// through the review gate, and a clone into an occupied VMID refused.
async fn destructive_gate(run: &TargetRun) -> Result<Outcome, String> {
    let target = &run.target;
    let node = target.node.as_str();
    let account = run
        .trusted_account("acceptance-destructive", &target.token)
        .await?;
    let vmid = run.clone_scratch(&account, "gate").await?;
    let base = format!("/api/v1/proxmox/accounts/{account}/guests/{vmid}");

    // The gate itself: a run without the review's token is refused.
    let (status, body) = run
        .controller
        .post(
            &format!("{base}/snapshot/run"),
            &json!({
                "node": node,
                "reviewToken": "not-the-review-token",
                "params": { "snapshot": "fleet-acc", "description": "fleet acceptance" },
                "timeoutSeconds": 120,
            }),
        )
        .await?;
    check!(
        status == 400,
        "an unreviewed snapshot run answered {status}: {body}"
    );
    check!(
        run.pve.snapshots(node, vmid).await?.is_empty(),
        "the refused run created a snapshot"
    );

    let snapshot = json!({ "snapshot": "fleet-acc", "description": "fleet acceptance" });
    let data = run
        .reviewed(&account, "snapshot", vmid, snapshot.clone())
        .await?;
    check!(
        data["state"] == "succeeded" && operation_result(&data)["taskState"] == "ok",
        "the snapshot ended {}: {}",
        data["state"],
        data["errorJson"]
    );
    check!(
        run.pve
            .snapshots(node, vmid)
            .await?
            .iter()
            .any(|name| name == "fleet-acc"),
        "PVE does not list the snapshot"
    );

    // Idempotent re-run: the same reviewed request succeeds as a no-op.
    let data = run
        .reviewed(&account, "snapshot", vmid, snapshot.clone())
        .await?;
    check!(
        data["state"] == "succeeded" && operation_result(&data)["noop"].is_string(),
        "the re-run is not an idempotent no-op: {} {}",
        data["state"],
        data["resultJson"]
    );
    check!(
        run.pve.snapshots(node, vmid).await?.len() == 1,
        "the re-run created a second snapshot"
    );

    let data = run
        .reviewed(
            &account,
            "snapshot-revert",
            vmid,
            json!({ "snapshot": "fleet-acc" }),
        )
        .await?;
    check!(
        data["state"] == "succeeded" && operation_result(&data)["taskState"] == "ok",
        "the rollback ended {}: {}",
        data["state"],
        data["errorJson"]
    );
    task_evidence(run, vmid, "qmrollback").await?;

    let data = run
        .reviewed(
            &account,
            "snapshot-delete",
            vmid,
            json!({ "snapshot": "fleet-acc" }),
        )
        .await?;
    check!(
        data["state"] == "succeeded",
        "the snapshot delete ended {}: {}",
        data["state"],
        data["errorJson"]
    );
    check!(
        run.pve.snapshots(node, vmid).await?.is_empty(),
        "PVE still lists the snapshot after delete"
    );

    // A clone whose target VMID is taken is a conflict, never a duplicate
    // or an overwrite.
    let before = run.pve.resource(vmid).await?;
    let data = run
        .reviewed(
            &account,
            "clone",
            target.template_vmid,
            json!({ "newId": target.range.check(vmid)?, "name": format!("fleet-acceptance-occupied-{vmid}") }),
        )
        .await?;
    let (reason, detail) = operation_error(&data);
    check!(
        data["state"] == "failed" && reason == "conflict",
        "a clone into the occupied VMID {vmid} ended {}: {reason}: {detail}",
        data["state"]
    );
    check!(
        run.pve.resource(vmid).await? == before,
        "the refused clone changed guest {vmid}"
    );
    Ok(Outcome::Pass)
}

/// Scenario 5: a running scratch guest's agent reports its MAC, a machine
/// seeded with that MAC becomes a `mac_match` candidate, and confirming
/// the association links the machine to the guest.
async fn association(run: &TargetRun) -> Result<Outcome, String> {
    let target = &run.target;
    let node = target.node.as_str();
    let account = run
        .trusted_account("acceptance-association", &target.token)
        .await?;
    let vmid = run.clone_scratch(&account, "assoc").await?;
    let data = run.lifecycle(&account, "start", node, vmid, 300).await?;
    check!(
        data["state"] == "succeeded",
        "start ended {}: {}",
        data["state"],
        data["errorJson"]
    );
    wait_for_agent(run, vmid, Duration::from_secs(300)).await?;

    // Wait until Fleet's own guest view shows the agent online with the
    // config MAC on one of its interfaces.
    let started = Instant::now();
    let mac = loop {
        if let Some(guest) = find_guest(run, &account, vmid).await? {
            let config_mac = guest["macs"][0].as_str().map(str::to_lowercase);
            let agent_macs: Vec<String> = guest["agent"]["interfaces"]
                .as_array()
                .map(|interfaces| {
                    interfaces
                        .iter()
                        .filter_map(|interface| interface["mac"].as_str())
                        .map(str::to_lowercase)
                        .collect()
                })
                .unwrap_or_default();
            if guest["agent"]["online"] == true
                && let Some(mac) = config_mac.filter(|mac| agent_macs.contains(mac))
            {
                break mac;
            }
        }
        check!(
            started.elapsed() < Duration::from_secs(300),
            "Fleet never saw guest {vmid}'s agent report its config MAC"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    };

    // Seed a machine carrying that MAC (fixture data, written to the
    // controller's store the way the e2e harness seeds machines). Its name
    // and endpoint match nothing, so only MAC evidence can link it.
    // The store admits one controller, so the controller is stopped around
    // the write and restarted on the same data and address.
    let machine = run
        .controller
        .with_store(async |store| {
            let machines = fleet_storage_sqlite::MachineRepository::new(store.pool().clone());
            let machine = machines
                .register(&RegisterMachine {
                    name: format!("acceptance-seeded-{vmid}"),
                    description: "FM-611 association fixture".to_owned(),
                    endpoints: vec![NewEndpoint {
                        kind: fleet_core::EndpointKind::Ssh,
                        reference: "acceptance@192.0.2.10:22".to_owned(),
                    }],
                    tags: Vec::new(),
                    groups: Vec::new(),
                })
                .await
                .map_err(|error| format!("cannot seed the machine: {error:?}"))?;
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|error| error.to_string())?
                    .as_millis(),
            )
            .map_err(|error| error.to_string())?;
            machines
                .record_capabilities(
                    &machine.id,
                    &[CapabilityFact {
                        namespace: "net".to_owned(),
                        name: "mac0".to_owned(),
                        value: Some(mac.clone()),
                        status: CapabilityStatus::Known,
                        observed_at: Timestamp::from_unix_millis(now),
                        source: "fleet-acceptance/1".to_owned(),
                    }],
                )
                .await
                .map_err(|error| format!("cannot seed the MAC: {error:?}"))?;
            Ok(machine)
        })
        .await?;

    let guest = find_guest(run, &account, vmid)
        .await?
        .ok_or_else(|| format!("guest {vmid} disappeared"))?;
    let candidate = guest["candidates"]
        .as_array()
        .and_then(|candidates| {
            candidates
                .iter()
                .find(|c| c["machineId"] == machine.id.as_str())
        })
        .cloned()
        .ok_or_else(|| format!("guest {vmid} has no candidate for the seeded machine"))?;
    check!(
        candidate["kind"] == "mac_match"
            && candidate["evidence"].as_str().map(str::to_lowercase) == Some(mac.clone()),
        "the candidate is not MAC evidence: {}",
        candidate["kind"]
    );

    // Confirm through the operator's CLI.
    let answer = run
        .controller
        .fleetctl(
            &proxmox_live_support::args(&[
                "machines",
                "link-guest",
                &machine.id,
                "--account",
                &account,
                "--kind",
                "qemu",
                "--vmid",
                &vmid.to_string(),
            ]),
            None,
        )
        .await?;
    check!(
        answer.success,
        "fleetctl machines link-guest failed: {}",
        answer.stderr
    );
    let (status, body) = run
        .controller
        .get(&format!("/api/v1/machines/{}", machine.id))
        .await?;
    check!(status == 200, "reading the machine answered {status}");
    check!(
        body["data"]["runsOn"]["vmid"] == vmid
            && body["data"]["runsOn"]["accountId"] == account.as_str(),
        "the machine is not linked to guest {vmid}: {}",
        body["data"]["runsOn"]
    );
    Ok(Outcome::Pass)
}

/// Finds one guest in Fleet's paginated guest view.
async fn find_guest(run: &TargetRun, account: &str, vmid: u32) -> Result<Option<Value>, String> {
    let mut cursor: Option<String> = None;
    for _ in 0..50 {
        let path = match &cursor {
            Some(cursor) => format!(
                "/api/v1/proxmox/accounts/{account}/guests?limit=200&cursor={}",
                proxmox_live_support::pve::encode(cursor)
            ),
            None => format!("/api/v1/proxmox/accounts/{account}/guests?limit=200"),
        };
        let (status, body) = run.controller.get(&path).await?;
        check!(
            status == 200,
            "listing guests answered {status}: {}",
            body["code"]
        );
        if let Some(guest) = body["items"]
            .as_array()
            .and_then(|items| items.iter().find(|guest| guest["vmid"] == vmid))
        {
            return Ok(Some(guest.clone()));
        }
        match body["page"]["nextCursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => return Ok(None),
        }
    }
    Ok(None)
}

/// Takes the cluster target's peer node down with the FM-612 helper and
/// always brings it back, including after a panic.
struct NodeDown {
    role: String,
    redactor: proxmox_live_support::redact::Redactor,
    restored: bool,
}

/// The FM-612 helper script.
fn pve_test_script() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/pve-test/pve-test")
}

/// Runs `deploy/pve-test/pve-test <words>`; the env file comes from
/// `FLEET_PVE_TEST_ENV_FILE` (inherited) or the script's default.
fn pve_test(
    words: &[&str],
    redactor: &proxmox_live_support::redact::Redactor,
) -> Result<(), String> {
    let output = std::process::Command::new("bash")
        .arg(pve_test_script())
        .args(words)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("pve-test could not run: {error}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        proxmox_live_support::log(redactor, &format!("pve-test: {line}"));
    }
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "pve-test {} failed ({})",
            words.join(" "),
            output.status
        ))
    }
}

impl NodeDown {
    fn take(role: &str, redactor: proxmox_live_support::redact::Redactor) -> Result<Self, String> {
        // Constructed first: a failed or partial node-down is still undone.
        let guard = Self {
            role: role.to_owned(),
            redactor,
            restored: false,
        };
        pve_test(&["node-down", role], &guard.redactor)?;
        Ok(guard)
    }

    fn restore(&mut self) -> Result<(), String> {
        let result = pve_test(&["node-up", &self.role], &self.redactor);
        if result.is_ok() {
            self.restored = true;
        }
        result
    }
}

impl Drop for NodeDown {
    fn drop(&mut self) {
        if !self.restored
            && let Err(detail) = self.restore()
        {
            eprintln!(
                "fleet-acceptance: NODE-UP FAILED: {detail}; run `deploy/pve-test/pve-test node-up {}` by hand",
                self.role
            );
        }
    }
}

/// Scenario 6 (cluster targets only): with the peer node down, discovery
/// still reports the healthy node and warns per node, and an operation
/// targeting the down node fails honestly within its deadline.
async fn partial_node_failure(run: &TargetRun) -> Result<Outcome, String> {
    let target = &run.target;
    let Some(down) = &target.down else {
        return Ok(Outcome::Skipped(
            skip_reason("partial-node-failure", target).unwrap_or_default(),
        ));
    };
    let account = run
        .trusted_account("acceptance-partial", &target.token)
        .await?;
    let base = format!("/api/v1/proxmox/accounts/{account}");

    // Precondition: both nodes healthy.
    let (status, body) = run.controller.get(&format!("{base}/discovery")).await?;
    check!(status == 200, "baseline discovery answered {status}");
    check!(
        node_capacity(&body, &down.node).is_some_and(|node| node["cpuCount"].is_number()),
        "the baseline discovery does not report {} healthy; is the cluster up?",
        target.var("DOWN_NODE")
    );
    // Reserve a VMID for the operation aimed at the down node; nothing is
    // created there.
    let vmid = run.guard.allocate().await?;

    let mut node_down = NodeDown::take(&down.role, run.redactor.clone())?;

    // Discovery keeps answering with the healthy node and a per-node
    // warning for the down one (membership changes take a few seconds).
    let started = Instant::now();
    let body = loop {
        let (status, body) = run.controller.get(&format!("{base}/discovery")).await?;
        let warned = status == 200 && warnings_name(&body, &down.node);
        if warned {
            break body;
        }
        check!(
            started.elapsed() < Duration::from_secs(180),
            "discovery never warned about the down node (last answer {status})"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    };
    check!(
        node_capacity(&body, &target.node).is_some_and(|node| node["cpuCount"].is_number()),
        "with the peer down, discovery does not report the healthy node's capacity"
    );

    // An operation on the down node fails honestly within its deadline.
    let deadline = 60;
    let started = Instant::now();
    let data = run
        .lifecycle(&account, "start", &down.node, vmid, deadline)
        .await?;
    let elapsed = started.elapsed();
    let (reason, detail) = operation_error(&data);
    check!(
        data["state"] == "failed" && !detail.is_empty(),
        "an operation on the down node ended {} ({reason}: {detail})",
        data["state"]
    );
    check!(
        elapsed < Duration::from_secs(deadline + 30),
        "the operation on the down node took {}s, past its {deadline}s deadline",
        elapsed.as_secs()
    );
    run.log(&format!(
        "operation on the down node failed in {}s: {reason}: {detail}",
        elapsed.as_secs()
    ));

    // Bring the node back and wait until discovery is clean again, so the
    // fixture is left as found.
    node_down.restore()?;
    let started = Instant::now();
    loop {
        let (status, body) = run.controller.get(&format!("{base}/discovery")).await?;
        if status == 200 && !warnings_name(&body, &down.node) {
            break;
        }
        check!(
            started.elapsed() < Duration::from_secs(300),
            "discovery still warns about the node after node-up"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Ok(Outcome::Pass)
}

fn node_capacity<'a>(body: &'a Value, node: &str) -> Option<&'a Value> {
    body["data"]["nodeCapacities"]
        .as_array()?
        .iter()
        .find(|capacity| capacity["node"] == node)
}

/// Whether discovery's warnings say `node` is unreachable.
fn warnings_name(body: &Value, node: &str) -> bool {
    body["data"]["warnings"].as_array().is_some_and(|warnings| {
        warnings
            .iter()
            .filter_map(Value::as_str)
            .any(|warning| is_node_down_warning(warning, node))
    })
}

/// Whether one discovery warning is the provider's "this node could not be
/// read" warning for exactly `node`.
///
/// The provider emits `node <name> status: <error>` and
/// `node <name> storage: <error>` when the node's own endpoints fail (its
/// `node_capacity`). The node must be the whole second token, so a longer
/// hostname, a VM name, or an unrelated row such as PVE 9's SDN
/// `resource #12: entry network/<node>/zone/localnetwork has an unrecognized
/// type "network"` never counts. The same endpoints also warn about a
/// payload that arrived but was malformed (`cpu usage is missing`, ...);
/// that is not the node being down.
fn is_node_down_warning(warning: &str, node: &str) -> bool {
    let Some(rest) = warning.strip_prefix("node ") else {
        return false;
    };
    let Some((name, detail)) = rest.split_once(' ') else {
        return false;
    };
    if name != node {
        return false;
    }
    let Some(error) = detail
        .strip_prefix("status: ")
        .or_else(|| detail.strip_prefix("storage: "))
    else {
        return false;
    };
    ![
        "cpu usage is missing",
        "memory used or total is missing",
        "the payload is not a list",
    ]
    .iter()
    .any(|payload_problem| error.starts_with(payload_problem))
}

#[cfg(test)]
mod node_down_warning_tests {
    use super::{is_node_down_warning, warnings_name};
    use serde_json::json;

    #[test]
    fn matches_the_endpoint_failure_warnings_for_the_node() {
        assert!(is_node_down_warning(
            "node pvec-b status: the PVE request timed out",
            "pvec-b"
        ));
        assert!(is_node_down_warning(
            "node pvec-b storage: connection refused",
            "pvec-b"
        ));
    }

    #[test]
    fn ignores_the_sdn_row_that_mentions_the_node() {
        assert!(!is_node_down_warning(
            "resource #12: entry network/pvec-b/zone/localnetwork has an unrecognized type \"network\"",
            "pvec-b"
        ));
    }

    #[test]
    fn requires_the_whole_node_name() {
        assert!(!is_node_down_warning(
            "node pvec-b2 status: timed out",
            "pvec-b"
        ));
        assert!(!is_node_down_warning(
            "node pvec-b status: timed out",
            "pvec"
        ));
        assert!(!is_node_down_warning(
            "guest qemu/100: node pvec-b is odd",
            "pvec-b"
        ));
        assert!(!is_node_down_warning(
            "node pvec-b storage #2: bad entry",
            "pvec-b"
        ));
        assert!(!is_node_down_warning("node pvec-b", "pvec-b"));
    }

    #[test]
    fn ignores_payload_problems_of_a_reachable_node() {
        assert!(!is_node_down_warning(
            "node pvec-b status: cpu usage is missing",
            "pvec-b"
        ));
        assert!(!is_node_down_warning(
            "node pvec-b status: memory used or total is missing or invalid",
            "pvec-b"
        ));
        assert!(!is_node_down_warning(
            "node pvec-b storage: the payload is not a list (it is a string)",
            "pvec-b"
        ));
    }

    #[test]
    fn reads_the_discovery_body() {
        let body = json!({"data": {"warnings": [
            "resource #12: entry network/pvec-b/zone/localnetwork has an unrecognized type \"network\"",
        ]}});
        assert!(!warnings_name(&body, "pvec-b"));
        let down = json!({"data": {"warnings": ["node pvec-b status: timed out"]}});
        assert!(warnings_name(&down, "pvec-b"));
        assert!(!warnings_name(&json!({"data": {}}), "pvec-b"));
    }
}

/// The harness itself, without PVE: the real controller binary starts on
/// a throwaway store, `fleetctl` creates an account with the secret on
/// stdin, the secret is never echoed, and the trust gate holds. It runs
/// wherever `fleetctl` is built (every `cargo test --workspace`); without
/// it the test says so instead of passing silently.
#[tokio::test]
async fn harness_drives_the_real_controller_and_fleetctl() {
    if let Err(detail) = proxmox_live_support::controller::locate_fleetctl() {
        println!("fleet-acceptance: harness self-test skipped: {detail}");
        return;
    }
    let mut redactor = proxmox_live_support::redact::Redactor::default();
    redactor.mask("harness-canary-secret", "<secret>");
    let controller = proxmox_live_support::controller::Controller::start(redactor)
        .await
        .expect("the controller binary starts");
    let answer = controller
        .fleetctl(
            &proxmox_live_support::args(&[
                "proxmox",
                "create",
                "--name",
                "harness",
                "--host",
                "192.0.2.1",
                "--token-id",
                "fleet-test@pve!admin",
            ]),
            Some("harness-canary-secret\n".to_owned()),
        )
        .await
        .expect("fleetctl runs");
    assert!(answer.success, "{}", answer.stderr);
    assert!(!answer.json.to_string().contains("harness-canary-secret"));
    let account = answer.json["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no account id: {answer:?}"))
        .to_owned();
    assert_eq!(answer.json["fingerprintState"], "unconfirmed");
    let (status, body) = controller
        .get(&format!("/api/v1/proxmox/accounts/{account}/discovery"))
        .await
        .expect("the controller answers");
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "proxmox_unconfirmed");
    // The store admits one controller: with_store stops it, writes, and
    // restarts it on the same address with the data intact.
    let url = controller.url();
    let touched = controller
        .with_store(async |store| {
            sqlx::query("UPDATE proxmox_accounts SET fingerprint = ?1 WHERE id = ?2")
                .bind("00")
                .bind(&account)
                .execute(store.pool())
                .await
                .map(|done| done.rows_affected())
                .map_err(|error| error.to_string())
        })
        .await
        .expect("the store opens while the controller is stopped");
    assert_eq!(touched, 1);
    assert_eq!(controller.url(), url, "the restart reuses the port");
    let (status, body) = controller
        .get("/api/v1/proxmox/accounts")
        .await
        .expect("the restarted controller answers");
    assert_eq!(status, 200, "{body}");
    assert!(
        body.to_string().contains(&account),
        "the account survived: {body}"
    );

    // The operations surface the suite polls answers through the same binary.
    let (status, _) = controller
        .get("/api/v1/operations")
        .await
        .expect("the controller answers");
    assert_eq!(status, 200);
}

// ---------------------------------------------------------------- unit tests
// These run in every `cargo test` and need no PVE.

mod unit {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::time::Duration;

    use fleet_core::SensitiveString;

    use super::proxmox_live_support::config::{self, Gate, VmidRange};
    use super::proxmox_live_support::guard::{SweepDecision, classify, first_free};
    use super::proxmox_live_support::pve::{VmResource, parse_resources, split_tags};
    use super::proxmox_live_support::redact::{Redactor, mask_ipv4};
    use super::proxmox_live_support::{Outcome, RESULT_MARKER, result_line};

    const FP: &str = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn complete(name: &str) -> Vec<(String, String)> {
        let p = format!("FLEET_PVE_TARGET_{name}_");
        vec![
            (format!("{p}HOST"), "pve.example.test".to_owned()),
            (format!("{p}PORT"), "8006".to_owned()),
            (format!("{p}TOKEN_ID"), "fleet-test@pve!admin".to_owned()),
            (
                format!("{p}TOKEN_SECRET_FILE"),
                "/secrets/admin.token".to_owned(),
            ),
            (format!("{p}FINGERPRINT"), FP.to_owned()),
            (format!("{p}NODE"), "pve".to_owned()),
            (format!("{p}STORAGE"), "local-lvm".to_owned()),
            (format!("{p}TEMPLATE_VMID"), "9000".to_owned()),
            (format!("{p}VMID_RANGE"), "9900-9919".to_owned()),
        ]
    }

    fn with_gate(mut vars: Vec<(String, String)>) -> BTreeMap<String, String> {
        vars.push(("FLEET_PVE_LIVE".to_owned(), "1".to_owned()));
        vars.into_iter().collect()
    }

    fn fake_secret(_: &Path) -> Result<SensitiveString, String> {
        Ok(SensitiveString::new("s3cret-material"))
    }

    #[test]
    fn the_gate_off_skips_without_reading_anything() {
        let gate =
            config::load(&env(&[]), |_| panic!("no secret is read with the gate off")).unwrap();
        assert!(matches!(gate, Gate::Off(reason) if reason.contains("FLEET_PVE_LIVE")));
        // Anything but exactly 1 is off, as in pin_live.rs.
        let gate = config::load(&env(&[("FLEET_PVE_LIVE", "true")]), fake_secret).unwrap();
        assert!(matches!(gate, Gate::Off(_)));
    }

    #[test]
    fn the_gate_on_without_targets_is_a_loud_failure() {
        let error = config::load(&env(&[("FLEET_PVE_LIVE", "1")]), fake_secret).unwrap_err();
        assert!(error.contains("at least one target"), "{error}");
    }

    #[test]
    fn a_complete_target_parses_with_the_runbook_names() {
        let gate = config::load(&with_gate(complete("PVE9")), fake_secret).unwrap();
        let Gate::On(targets) = gate else {
            panic!("the gate is on")
        };
        assert_eq!(targets.len(), 1);
        let target = &targets[0];
        assert_eq!(target.name, "PVE9");
        assert_eq!(target.port, 8006);
        assert_eq!(target.fingerprint, FP.replace(':', ""));
        assert_eq!(
            target.range,
            VmidRange {
                first: 9900,
                last: 9919
            }
        );
        assert!(target.ro_token.is_none());
        assert!(target.down.is_none());
        // The secret never reaches Debug output.
        assert!(!format!("{target:?}").contains("s3cret-material"));
    }

    #[test]
    fn every_missing_variable_is_named() {
        let mut vars = complete("PVE9");
        vars.retain(|(key, _)| !key.ends_with("_NODE") && !key.ends_with("_VMID_RANGE"));
        let error = config::load(&with_gate(vars), fake_secret).unwrap_err();
        assert!(error.contains("FLEET_PVE_TARGET_PVE9_NODE"), "{error}");
        assert!(
            error.contains("FLEET_PVE_TARGET_PVE9_VMID_RANGE"),
            "{error}"
        );
    }

    #[test]
    fn half_configured_optional_pairs_are_refused() {
        let mut vars = complete("CLUSTER");
        vars.push((
            "FLEET_PVE_TARGET_CLUSTER_RO_TOKEN_ID".to_owned(),
            "fleet-test@pve!ro".to_owned(),
        ));
        vars.push((
            "FLEET_PVE_TARGET_CLUSTER_DOWN_NODE".to_owned(),
            "node-b".to_owned(),
        ));
        let error = config::load(&with_gate(vars), fake_secret).unwrap_err();
        assert!(
            error.contains("RO_TOKEN_SECRET_FILE are set together"),
            "{error}"
        );
        assert!(error.contains("DOWN_ROLE are set together"), "{error}");
    }

    #[test]
    fn a_cluster_target_carries_its_down_node_and_read_only_token() {
        let mut vars = complete("CLUSTER");
        for (key, value) in [
            ("RO_TOKEN_ID", "fleet-test@pve!ro"),
            ("RO_TOKEN_SECRET_FILE", "/secrets/ro.token"),
            ("DOWN_NODE", "node-b"),
            ("DOWN_ROLE", "node-b"),
        ] {
            vars.push((format!("FLEET_PVE_TARGET_CLUSTER_{key}"), value.to_owned()));
        }
        let Gate::On(targets) = config::load(&with_gate(vars), fake_secret).unwrap() else {
            panic!("the gate is on")
        };
        let down = targets[0].down.clone().unwrap();
        assert_eq!(
            (down.node.as_str(), down.role.as_str()),
            ("node-b", "node-b")
        );
        assert_eq!(
            targets[0].ro_token.as_ref().unwrap().id,
            "fleet-test@pve!ro"
        );
    }

    #[test]
    fn malformed_values_are_refused() {
        let mut vars = complete("PVE9");
        for (key, value) in [
            ("HOST", "https://pve.example.test:8006"),
            ("FINGERPRINT", "not-a-digest"),
            ("TEMPLATE_VMID", "9905"),
            ("TOKEN_ID", "root"),
        ] {
            vars.retain(|(existing, _)| {
                !existing.ends_with(&format!("_{key}")) || existing.contains("RO_")
            });
            vars.push((format!("FLEET_PVE_TARGET_PVE9_{key}"), value.to_owned()));
        }
        let error = config::load(&with_gate(vars), fake_secret).unwrap_err();
        assert!(error.contains("bare host"), "{error}");
        assert!(error.contains("SHA-256"), "{error}");
        assert!(error.contains("must stay outside"), "{error}");
        assert!(error.contains("API token id"), "{error}");
    }

    fn with_value(name: &str, key: &str, value: &str) -> BTreeMap<String, String> {
        let mut vars = complete(name);
        vars.retain(|(existing, _)| !existing.ends_with(&format!("_{key}")));
        vars.push((format!("FLEET_PVE_TARGET_{name}_{key}"), value.to_owned()));
        with_gate(vars)
    }

    #[test]
    fn a_host_with_an_embedded_port_is_refused_but_ipv6_is_not() {
        for host in [
            "pve.example.test:8006",
            "192.0.2.10:8006",
            "[2001:db8::1]:8006",
        ] {
            let error = config::load(&with_value("PVE9", "HOST", host), fake_secret).unwrap_err();
            assert!(error.contains("host:port"), "{host}: {error}");
        }
        for host in ["2001:db8::1", "[2001:db8::1]", "192.0.2.10"] {
            assert!(
                config::load(&with_value("PVE9", "HOST", host), fake_secret).is_ok(),
                "{host} is a bare address"
            );
        }
    }

    #[test]
    fn the_template_vmid_must_lie_within_pves_bounds() {
        for vmid in ["0", "99", "1000000000"] {
            let error =
                config::load(&with_value("PVE9", "TEMPLATE_VMID", vmid), fake_secret).unwrap_err();
            assert!(
                error.contains("within PVE's VMIDs 100-999999999"),
                "{vmid}: {error}"
            );
        }
        assert!(config::load(&with_value("PVE9", "TEMPLATE_VMID", "100"), fake_secret).is_ok());
    }

    #[test]
    fn a_target_name_outside_the_identifier_alphabet_is_refused() {
        for name in ["PVE 9", "PVE-9", "PVE\t9"] {
            let error = config::load(&with_gate(complete(name)), fake_secret).unwrap_err();
            assert!(error.contains("may hold only A-Z"), "{name:?}: {error}");
        }
        assert!(config::valid_target_name("PVE_9_lab"));
        assert!(!config::valid_target_name(""));
    }

    #[test]
    fn the_target_filter_selects_one_and_refuses_an_unknown_name() {
        let mut vars = complete("PVE9");
        vars.extend(complete("PVE8"));
        let mut map = with_gate(vars);
        map.insert("FLEET_PVE_ACCEPTANCE_TARGET".to_owned(), "PVE8".to_owned());
        let Gate::On(targets) = config::load(&map, fake_secret).unwrap() else {
            panic!("the gate is on")
        };
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "PVE8");
        map.insert("FLEET_PVE_ACCEPTANCE_TARGET".to_owned(), "NOPE".to_owned());
        let error = config::load(&map, fake_secret).unwrap_err();
        assert!(error.contains("names no configured target"), "{error}");
    }

    #[test]
    fn a_secret_read_failure_never_carries_the_content() {
        let error = config::load(&with_gate(complete("PVE9")), |_| {
            Err("cannot read /secrets/admin.token: denied".to_owned())
        })
        .unwrap_err();
        assert!(error.contains("TOKEN_ID: cannot read"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_must_be_private_and_non_empty() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "  the-secret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = config::read_secret_file(&path).unwrap_err();
        assert!(error.contains("chmod 600"), "{error}");
        assert!(!error.contains("the-secret"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            config::read_secret_file(&path).unwrap().expose(),
            "the-secret"
        );
        std::fs::write(&path, "\n").unwrap();
        assert!(
            config::read_secret_file(&path)
                .unwrap_err()
                .contains("empty")
        );
        assert!(config::read_secret_file(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn the_range_parses_and_guards() {
        let range = VmidRange::parse("9900-9909").unwrap();
        assert!(range.contains(9900) && range.contains(9909));
        assert!(!range.contains(9899) && !range.contains(9910));
        assert_eq!(range.check(9905), Ok(9905));
        let refused = range.check(100).unwrap_err();
        assert!(
            refused.contains("outside the suite's VMID_RANGE 9900-9909"),
            "{refused}"
        );
        for bad in [
            "9909-9900",
            "99-120",
            "9900",
            "a-b",
            "9900-9902",
            "100-1000000000",
        ] {
            assert!(VmidRange::parse(bad).is_err(), "{bad} must be refused");
        }
    }

    fn resource(vmid: u32, name: Option<&str>, tags: &str, template: bool) -> VmResource {
        VmResource {
            vmid,
            node: "pve".to_owned(),
            kind: "qemu".to_owned(),
            name: name.map(str::to_owned),
            tags: split_tags(tags),
            template,
            lock: None,
            status: Some("stopped".to_owned()),
        }
    }

    #[test]
    fn the_sweep_destroys_only_the_suites_own_guests_inside_the_range() {
        let range = VmidRange::parse("9900-9909").unwrap();
        // Outside the range: never touched, whatever it is called.
        assert_eq!(
            classify(
                &resource(100, Some("fleet-acceptance-x"), "fleet-acceptance", false),
                range
            ),
            SweepDecision::Outside
        );
        // Inside and tagged, or inside and named: destroyed.
        assert_eq!(
            classify(
                &resource(9900, Some("vm"), "a;fleet-acceptance", false),
                range
            ),
            SweepDecision::Destroy
        );
        assert_eq!(
            classify(
                &resource(9901, Some("fleet-acceptance-poll-9901"), "", false),
                range
            ),
            SweepDecision::Destroy
        );
        // Inside but foreign, or a template: left alone and reported.
        assert!(matches!(
            classify(&resource(9902, Some("prod-db"), "prod", false), range),
            SweepDecision::Foreign(_)
        ));
        assert!(matches!(
            classify(
                &resource(9903, Some("fleet-acceptance-t"), "fleet-acceptance", true),
                range
            ),
            SweepDecision::Foreign(_)
        ));
    }

    #[test]
    fn allocation_stays_inside_the_range_and_skips_taken_vmids() {
        let range = VmidRange::parse("9900-9905").unwrap();
        let taken: BTreeSet<u32> = [9900, 9901, 9903].into_iter().collect();
        assert_eq!(first_free(range, &taken), Some(9902));
        let full: BTreeSet<u32> = (9900..=9905).collect();
        assert_eq!(first_free(range, &full), None);
    }

    #[test]
    fn cluster_resources_parse_with_tags_and_locks() {
        let entry = serde_json::json!({
            "vmid": 9901, "node": "pve", "type": "qemu", "name": "fleet-acceptance-poll-9901",
            "tags": "fleet-acceptance;other", "template": 0, "lock": "clone", "status": "stopped"
        });
        let parsed = VmResource::parse(&entry).unwrap();
        assert_eq!(parsed.tags, vec!["fleet-acceptance", "other"]);
        assert_eq!(parsed.lock.as_deref(), Some("clone"));
        assert!(!parsed.template);
        assert!(VmResource::parse(&serde_json::json!({"id": "node/pve"})).is_none());
    }

    #[test]
    fn the_inventory_refuses_a_non_array_or_a_partial_answer() {
        assert_eq!(parse_resources(&serde_json::json!([])).unwrap(), vec![]);
        let one = serde_json::json!([{"vmid": 9901, "node": "pve"}]);
        assert_eq!(parse_resources(&one).unwrap().len(), 1);
        for data in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!("[]"),
        ] {
            let error = parse_resources(&data).unwrap_err();
            assert!(error.contains("not an array"), "{data}: {error}");
        }
        let partial = serde_json::json!([{"vmid": 9901, "node": "pve"}, {"vmid": "9902"}]);
        let error = parse_resources(&partial).unwrap_err();
        assert!(error.contains("row 1"), "{error}");
    }

    #[test]
    fn the_result_line_is_one_parseable_line() {
        let line = result_line(
            "trust",
            Some("PVE9"),
            &Ok(Outcome::Pass),
            Duration::from_millis(1234),
        );
        assert_eq!(
            line,
            format!(
                "{RESULT_MARKER} scenario=trust target=PVE9 status=pass duration_ms=1234 reason="
            )
        );
        let line = result_line(
            "partial-node-failure",
            Some("PVE8"),
            &Ok(Outcome::Skipped("skipped: no cluster target".to_owned())),
            Duration::ZERO,
        );
        assert!(
            line.ends_with("status=skipped duration_ms=0 reason=skipped: no cluster target"),
            "{line}"
        );
        let line = result_line("trust", None, &Err("two\nlines".to_owned()), Duration::ZERO);
        assert!(
            line.contains("target=- status=fail") && line.ends_with("reason=two lines"),
            "{line}"
        );
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn the_redactor_masks_secrets_hosts_fingerprints_nodes_and_addresses() {
        let mut redactor = Redactor::default();
        redactor.mask("s3cret-material", "<secret>");
        redactor.mask("pve.example.test", "<PVE9-host>");
        redactor.mask(&FP.replace(':', ""), "<PVE9-fingerprint>");
        redactor.mask_word("pve", "<PVE9-node>");
        let text = format!(
            "token s3cret-material on pve.example.test node pve (pveVersion 9) fp {FP} lease 192.168.68.240/24 v1.2.3"
        );
        let out = redactor.redact(&text);
        assert!(!out.contains("s3cret"), "{out}");
        assert!(!out.contains("example.test"), "{out}");
        assert!(!out.contains("AB:CD:EF"), "{out}");
        assert!(out.contains("node <PVE9-node> (pveVersion 9)"), "{out}");
        assert!(out.contains("lease <redacted-ipv4>/24"), "{out}");
        assert!(out.contains("v1.2.3"), "{out}");
        assert_eq!(
            mask_ipv4("999.1.1.1 and 10.0.0.1"),
            "999.1.1.1 and <redacted-ipv4>"
        );
    }
}
