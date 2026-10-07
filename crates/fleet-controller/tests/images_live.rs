//! The real-host image build suite (FM-704, #255).
//!
//! Each scenario is its own test. It drives the real `fleet-controller`
//! binary (API, worker, and the operator-installed Packer CLI) and the real
//! `fleetctl` against every live target configured through
//! `FLEET_PVE_TARGET_<NAME>_*`, the same contract as the FM-611 suite
//! (`proxmox_live.rs`). Without `FLEET_PVE_LIVE=1` every scenario prints a
//! skipped result line and passes. `cargo xtask image-acceptance` runs the
//! suite and turns the result lines into a JSON summary.
//!
//! Builds are `proxmox-clone` linked clones of the target's guest-agent
//! template (`TEMPLATE_VMID`) into the scratch range, so they finish in
//! minutes. Every template a build creates is named
//! `fleet-acceptance-image-*` and tagged `fleet-acceptance`; the suite
//! destroys those (and only those) at the start and end of each scenario.
//! The shared scratch guard never destroys a template, so this suite owns
//! that narrower cleanup itself.
//!
//! Credentials reach Packer's Proxmox plugin through the controller's
//! process environment (`PROXMOX_USERNAME`/`PROXMOX_TOKEN`), and the recipe
//! sets `insecure_skip_tls_verify`. Both are the only paths the product
//! supports today; #272 replaces them, and this suite follows.
//!
//! The unit tests at the bottom run without any PVE or Packer.

#[macro_use]
mod proxmox_live_support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_core::SensitiveString;
use fleet_provider_packer::{PackerClient, ProcessTransport};
use proxmox_live_support::config::Target;
use proxmox_live_support::guard::{NAME_PREFIX, TAG};
use proxmox_live_support::{Outcome, Suite, TargetRun, args, operation_error, operation_result};
use serde_json::{Value, json};

/// The marker that starts every result line. Kept in step with
/// `xtask/src/image_acceptance.rs`.
const RESULT_MARKER: &str = "FLEET_IMAGE_ACCEPTANCE_RESULT";

/// The scenario identifiers, in report order. Kept in step with
/// `xtask/src/image_acceptance.rs`.
const SCENARIOS: [&str; 7] = [
    "version-gate",
    "validate-failure",
    "build",
    "build-record",
    "promotion",
    "rebuild-keeps-promotion",
    "cancel-cleanup",
];

/// The name prefix of every template a build creates.
const IMAGE_PREFIX: &str = "fleet-acceptance-image-";

/// How long one build may take, end to end.
const BUILD_BOUND: Duration = Duration::from_secs(1800);

/// Runs one scenario body on every selected target, sequentially, each
/// with its own swept range and fresh controller, then fails the test if
/// any target failed.
macro_rules! scenario {
    ($test:ident, $id:literal, $body:ident) => {
        #[tokio::test]
        async fn $test() {
            let Some(mut suite) = Suite::begin_marked(RESULT_MARKER, $id) else {
                return;
            };
            for target in suite.targets() {
                let started = Instant::now();
                if let Some(reason) = skip_reason($id, packer_gate().await) {
                    suite.record(&target, &Ok(Outcome::Skipped(reason)), started);
                    continue;
                }
                let result = match start($id, target.clone()).await {
                    Ok(run) => {
                        // The shared start sweep never destroys templates,
                        // so this suite clears its own leftovers (from an
                        // interrupted earlier run) before the body too.
                        let result = match destroy_image_templates(&run).await {
                            Ok(()) => $body(&run).await,
                            Err(cleanup) => Err(format!(
                                "the start-of-scenario template cleanup failed: {cleanup}"
                            )),
                        };
                        let swept = destroy_image_templates(&run).await;
                        let result = match (result, swept) {
                            (Ok(outcome), Ok(())) => Ok(outcome),
                            (Ok(_), Err(cleanup)) => Err(format!(
                                "the scenario passed but template cleanup failed: {cleanup}"
                            )),
                            (Err(reason), Ok(())) => Err(reason),
                            (Err(reason), Err(cleanup)) => {
                                Err(format!("{reason}; template cleanup also failed: {cleanup}"))
                            }
                        };
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

scenario!(live_version_gate, "version-gate", version_gate);
scenario!(live_validate_failure, "validate-failure", validate_failure);
scenario!(live_build, "build", build);
scenario!(live_build_record, "build-record", build_record);
scenario!(live_promotion, "promotion", promotion);
scenario!(
    live_rebuild_keeps_promotion,
    "rebuild-keeps-promotion",
    rebuild_keeps_promotion
);
scenario!(live_cancel_cleanup, "cancel-cleanup", cancel_cleanup);

/// Whether the machine running the suite has a Packer the product accepts,
/// asked through the product's own version gate.
async fn packer_gate() -> Result<(), String> {
    let work = std::env::temp_dir();
    PackerClient::new(Arc::new(ProcessTransport::new()))
        .version(work)
        .await
        .map(|_| ())
        .map_err(|gate| gate.to_string())
}

/// Why a scenario does not apply, when it does not. The version gate's
/// absent leg needs no Packer; everything else builds and needs one inside
/// the FM-S09 pins.
fn skip_reason(scenario: &str, packer: Result<(), String>) -> Option<String> {
    match (scenario, packer) {
        ("version-gate", _) | (_, Ok(())) => None,
        (_, Err(gate)) => Some(format!(
            "skipped: no usable packer on this machine: {gate} (with the proxmox plugin \
             >= 1.2.4 < 2, FM-S09)"
        )),
    }
}

/// Starts one scenario's run with one trusted Proxmox account for the
/// target, so every build resolves its account from the recipe's
/// `proxmox_url` (FM-702) without `--account`. The version gate's
/// controller sees no Packer at all; every other controller gets the
/// plugin's credentials.
async fn start(scenario: &str, target: Arc<Target>) -> Result<TargetRun, String> {
    let run = start_controller(scenario, target).await?;
    run.trusted_account("acceptance-images", &run.target.token)
        .await?;
    Ok(run)
}

async fn start_controller(scenario: &str, target: Arc<Target>) -> Result<TargetRun, String> {
    let env = if scenario == "version-gate" {
        let empty = empty_path_dir();
        std::fs::create_dir_all(&empty).map_err(|error| error.to_string())?;
        vec![(
            "PATH".to_owned(),
            SensitiveString::new(empty.display().to_string()),
        )]
    } else {
        plugin_env(&target)
    };
    TargetRun::start_with_env(target, scenario, env).await
}

/// The Proxmox plugin's credentials, from the target's token (#272).
fn plugin_env(target: &Target) -> Vec<(String, SensitiveString)> {
    vec![
        (
            "PROXMOX_USERNAME".to_owned(),
            SensitiveString::new(target.token.id.clone()),
        ),
        (
            "PROXMOX_TOKEN".to_owned(),
            SensitiveString::new(target.token.secret.expose()),
        ),
    ]
}

/// The recipe content: a legacy-JSON `proxmox-clone` template, because the
/// executor names the recipe file `*.json`. `communicator: none` keeps the
/// build to clone → boot → template, with no provisioner.
fn recipe(target: &Target, vmid: u32, label: &str) -> Value {
    clone_recipe(
        &format!("https://{}:{}/api2/json", target.host, target.port),
        &target.node,
        target.template_vmid,
        vmid,
        label,
    )
}

/// [`recipe`] over plain values. Credentials are never part of it.
fn clone_recipe(url: &str, node: &str, template_vmid: u32, vmid: u32, label: &str) -> Value {
    json!({
        "builders": [{
            "type": "proxmox-clone",
            "proxmox_url": url,
            "insecure_skip_tls_verify": true,
            "node": node,
            "clone_vm_id": template_vmid,
            "full_clone": false,
            "vm_id": vmid,
            "vm_name": format!("{IMAGE_PREFIX}{label}-{vmid}"),
            "template_name": format!("{IMAGE_PREFIX}{label}-{vmid}"),
            "template_description": "Fleet image acceptance (FM-704); safe to delete",
            "tags": TAG,
            // The plugin's default controller is `lsi`; a cloud-image
            // template with a virtio-scsi root disk then hangs in its
            // initramfs and never honours the shutdown before conversion.
            "scsi_controller": "virtio-scsi-pci",
            "memory": 1024,
            "cores": 1,
            "network_adapters": [{ "model": "virtio", "bridge": "vmbr0" }],
            "communicator": "none",
            "qemu_agent": true,
            "task_timeout": "10m"
        }]
    })
}

/// A recipe Fleet accepts as a frozen build target but `packer validate`
/// refuses: an otherwise valid clone with a key the plugin does not have.
fn invalid_recipe(target: &Target, vmid: u32) -> Value {
    let mut content = recipe(target, vmid, "invalid");
    content["builders"][0]["fleet_acceptance_unknown_key"] = json!(true);
    content
}

/// Creates a recipe from `content` and publishes it; answers the version id.
async fn publish(run: &TargetRun, label: &str, content: &Value) -> Result<String, String> {
    let created = run
        .controller
        .fleetctl(
            &args(&[
                "images",
                "create",
                "--name",
                &format!("{IMAGE_PREFIX}{label}"),
                "--description",
                "Fleet image acceptance (FM-704)",
                "--node",
                &run.target.node,
                "--storage-pool",
                &run.target.storage,
                "--source",
                "clone",
            ]),
            Some(content.to_string()),
        )
        .await?;
    check!(created.success, "images create failed: {}", created.stderr);
    let recipe = created.json["id"].as_str().unwrap_or_default().to_owned();
    check!(
        !recipe.is_empty(),
        "images create answered no id: {}",
        created.json
    );
    let published = run
        .controller
        .fleetctl(&args(&["images", "publish", &recipe]), None)
        .await?;
    check!(
        published.success,
        "images publish failed: {}",
        published.stderr
    );
    let version = published.json["id"].as_str().unwrap_or_default().to_owned();
    check!(
        !version.is_empty(),
        "images publish answered no version id: {}",
        published.json
    );
    Ok(version)
}

/// Builds one version with `--wait`; answers the terminal operation.
async fn build_wait(run: &TargetRun, version: &str) -> Result<Value, String> {
    let timeout = BUILD_BOUND.as_secs().to_string();
    run.fleetctl_operation(
        &["images", "build", version, "--wait", "--timeout", &timeout],
        None,
    )
    .await
}

/// Builds one version that must succeed; answers the artifact VMID the
/// executor recorded.
async fn build_ok(run: &TargetRun, version: &str, vmid: u32) -> Result<u32, String> {
    let data = build_wait(run, version).await?;
    check!(
        data["state"] == "succeeded",
        "the build ended {}: {:?}",
        data["state"],
        operation_error(&data)
    );
    let artifact = operation_result(&data)["artifactId"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    // FM-702 records the template as `<node>:<vmid>`.
    let expected = format!("{}:{vmid}", run.target.node);
    check!(
        artifact == expected,
        "the recorded artifact is {artifact:?}, not the built template {expected}"
    );
    // `/cluster/resources` can lag the conversion by a few seconds.
    let converted = Instant::now();
    let mut template = run.pve.resource(vmid).await?;
    while !template.as_ref().is_some_and(|guest| guest.template)
        && converted.elapsed() < Duration::from_secs(60)
    {
        tokio::time::sleep(Duration::from_secs(2)).await;
        template = run.pve.resource(vmid).await?;
    }
    check!(
        template.as_ref().is_some_and(|guest| guest.template),
        "VMID {vmid} is not a template on the host after a successful build: {template:?}"
    );
    run.log(&format!("built template {vmid}"));
    Ok(vmid)
}

/// The version's current DTO.
async fn version_dto(run: &TargetRun, version: &str) -> Result<Value, String> {
    let answer = run
        .controller
        .fleetctl(&args(&["images", "version", version]), None)
        .await?;
    check!(answer.success, "images version failed: {}", answer.stderr);
    Ok(answer.json)
}

/// Destroys this suite's image templates in the range: a template, named
/// `fleet-acceptance-image-*`, and tagged `fleet-acceptance`. Anything else
/// is left to the shared guard (which never destroys templates).
async fn destroy_image_templates(run: &TargetRun) -> Result<(), String> {
    let mut problems = Vec::new();
    for resource in run.pve.resources().await? {
        if is_own_image_template(&resource, run) {
            if let Err(detail) = run.pve.destroy(&resource).await {
                problems.push(format!("VMID {}: {detail}", resource.vmid));
            } else {
                run.log(&format!("destroyed image template {}", resource.vmid));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

fn is_own_image_template(
    resource: &proxmox_live_support::pve::VmResource,
    run: &TargetRun,
) -> bool {
    own_image_template(
        resource.vmid,
        resource.template,
        resource.name.as_deref(),
        &resource.tags,
        |vmid| run.target.range.contains(vmid),
    )
}

/// The narrow template rule, separated for the unit tests.
fn own_image_template(
    vmid: u32,
    template: bool,
    name: Option<&str>,
    tags: &[String],
    in_range: impl Fn(u32) -> bool,
) -> bool {
    in_range(vmid)
        && template
        && name.is_some_and(|name| name.starts_with(IMAGE_PREFIX))
        && tags.iter().any(|tag| tag == TAG)
}

/// Scenario 1: a controller without Packer refuses the build at the
/// version gate, honestly, before anything reaches the host.
async fn version_gate(run: &TargetRun) -> Result<Outcome, String> {
    let vmid = run.guard.allocate().await?;
    let version = publish(run, "gate", &recipe(&run.target, vmid, "gate")).await?;
    let data = build_wait(run, &version).await?;
    let (reason, detail) = operation_error(&data);
    check!(
        data["state"] == "failed" && reason == "version_gate",
        "a build without packer ended {} ({reason}: {detail}), not failed/version_gate",
        data["state"]
    );
    check!(
        run.pve.resource(vmid).await?.is_none(),
        "VMID {vmid} exists after a build refused at the version gate"
    );
    Ok(Outcome::Pass)
}

/// Scenario 2: `packer validate` refuses a recipe Fleet accepted, the
/// build fails with the `validate_failed` reason, and nothing is created on
/// the host. FM-702 keeps provider output out of the record by design, so
/// the reason code is the whole public diagnostic.
async fn validate_failure(run: &TargetRun) -> Result<Outcome, String> {
    let before: Vec<u32> = run.pve.resources().await?.iter().map(|r| r.vmid).collect();
    let vmid = run.guard.allocate().await?;
    let version = publish(run, "invalid", &invalid_recipe(&run.target, vmid)).await?;
    let data = build_wait(run, &version).await?;
    let (reason, detail) = operation_error(&data);
    check!(
        data["state"] == "failed" && reason == "validate_failed",
        "an invalid recipe ended {} ({reason}: {detail}), not failed/validate_failed",
        data["state"]
    );
    let after: Vec<u32> = run.pve.resources().await?.iter().map(|r| r.vmid).collect();
    let created: Vec<&u32> = after.iter().filter(|vmid| !before.contains(vmid)).collect();
    check!(
        created.is_empty(),
        "a refused recipe created guests {created:?}"
    );
    Ok(Outcome::Pass)
}

/// Scenario 3: a valid recipe builds into a template in the range, and the
/// operation records it as the artifact.
async fn build(run: &TargetRun) -> Result<Outcome, String> {
    let vmid = run.guard.allocate().await?;
    let version = publish(run, "build", &recipe(&run.target, vmid, "build")).await?;
    build_ok(run, &version, vmid).await?;
    Ok(Outcome::Pass)
}

/// Scenario 4: the immutable build record (FM-702) holds the version's
/// digest, the Packer and plugin versions actually installed, the resolved
/// account and frozen target, and the built template, and carries no
/// credential.
async fn build_record(run: &TargetRun) -> Result<Outcome, String> {
    let vmid = run.guard.allocate().await?;
    let version = publish(run, "record", &recipe(&run.target, vmid, "record")).await?;
    build_ok(run, &version, vmid).await?;
    let builds = run
        .controller
        .fleetctl(&args(&["images", "builds", "--version", &version]), None)
        .await?;
    check!(builds.success, "images builds failed: {}", builds.stderr);
    let items = builds.json["items"].as_array().cloned().unwrap_or_default();
    check!(
        items.len() == 1,
        "expected one build record, got {}",
        builds.json
    );
    let id = items[0]["id"].as_str().unwrap_or_default().to_owned();
    let shown = run
        .controller
        .fleetctl(&args(&["images", "build-show", &id]), None)
        .await?;
    check!(shown.success, "images build-show failed: {}", shown.stderr);
    let record = shown.json.clone();
    let dto = version_dto(run, &version).await?;
    let (status, accounts) = run.controller.get("/api/v1/proxmox/accounts").await?;
    check!(status == 200, "listing accounts answered {status}");
    let account = accounts["items"][0]["id"].clone();
    let (packer, plugin) = installed_versions()?;
    let expected = [
        ("outcome", json!("succeeded")),
        ("versionId", json!(version)),
        ("contentDigest", dto["contentDigest"].clone()),
        ("packerVersion", json!(packer)),
        ("proxmoxPluginVersion", json!(plugin)),
        ("accountId", account),
        ("node", json!(run.target.node)),
        ("storagePool", json!(run.target.storage)),
    ];
    for (field, want) in expected {
        check!(
            record[field] == want,
            "build record {field} is {}, expected {want}",
            record[field]
        );
    }
    check!(
        record["template"]["vmid"] == vmid
            && record["template"]["node"] == run.target.node.as_str(),
        "the record's template is {}, not {}:{vmid}",
        record["template"],
        run.target.node
    );
    check!(
        record["endedAt"].as_i64() >= record["startedAt"].as_i64(),
        "the record ends before it starts: {record}"
    );
    let text = record.to_string();
    check!(
        !text.contains(run.target.token.secret.expose()) && !text.contains(&run.target.token.id),
        "the build record carries the token"
    );
    Ok(Outcome::Pass)
}

/// The installed Packer and Proxmox plugin versions, as the record should
/// hold them, read from the documented CLI surfaces.
fn installed_versions() -> Result<(String, String), String> {
    let run = |args: &[&str]| {
        std::process::Command::new("packer")
            .args(args)
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .map_err(|error| format!("packer {args:?}: {error}"))
    };
    let version = run(&["-machine-readable", "version"])?
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split(',').collect();
            (fields.get(2) == Some(&"version")).then(|| fields.get(3).map(|v| (*v).to_owned()))
        })
        .flatten()
        .ok_or("packer reported no version")?;
    let plugin = run(&["plugins", "installed"])?
        .lines()
        .find_map(|line| {
            let name = line.trim().rsplit('/').next()?;
            Some(
                name.strip_prefix("packer-plugin-proxmox_v")?
                    .split('_')
                    .next()?
                    .to_owned(),
            )
        })
        .ok_or("no proxmox plugin is installed")?;
    Ok((version, plugin))
}

/// Scenario 5: a successfully built version can be promoted, and the
/// promotion is visible on the version.
async fn promotion(run: &TargetRun) -> Result<Outcome, String> {
    let vmid = run.guard.allocate().await?;
    let version = publish(run, "promote", &recipe(&run.target, vmid, "promote")).await?;
    build_ok(run, &version, vmid).await?;
    let answer = run
        .controller
        .fleetctl(&args(&["images", "promote", &version]), None)
        .await?;
    check!(answer.success, "images promote failed: {}", answer.stderr);
    let dto = version_dto(run, &version).await?;
    check!(
        dto["promotedAt"].is_number(),
        "the promoted version shows no promotedAt: {dto}"
    );
    Ok(Outcome::Pass)
}

/// Scenario 6: building the promoted version again neither demotes it nor
/// silently changes the template it stands for.
async fn rebuild_keeps_promotion(run: &TargetRun) -> Result<Outcome, String> {
    let first = run.guard.allocate().await?;
    let version = publish(run, "rebuild", &recipe(&run.target, first, "rebuild")).await?;
    build_ok(run, &version, first).await?;
    let answer = run
        .controller
        .fleetctl(&args(&["images", "promote", &version]), None)
        .await?;
    check!(answer.success, "images promote failed: {}", answer.stderr);
    let promoted = version_dto(run, &version).await?["promotedAt"].clone();

    // The same version again. The recipe pins `vm_id`, so Packer must
    // refuse it (the VMID is taken): the rebuild fails and the newest
    // successful build, which Lab clones from, is still the first. A recipe
    // without `vm_id` would succeed into a new VMID and silently move
    // Lab's clone source (#281); the suite cannot build outside its range,
    // so #281 covers that case with unit tests.
    let data = build_wait(run, &version).await?;
    let (reason, _) = operation_error(&data);
    check!(
        data["state"] == "failed" && reason == "build_failed",
        "rebuilding into a taken VMID ended {} ({reason}), not failed/build_failed",
        data["state"]
    );
    let dto = version_dto(run, &version).await?;
    check!(
        dto["promotedAt"] == promoted,
        "the rebuild changed the promotion: {promoted} → {}",
        dto["promotedAt"]
    );
    let builds = run
        .controller
        .fleetctl(&args(&["images", "builds", "--version", &version]), None)
        .await?;
    check!(builds.success, "images builds failed: {}", builds.stderr);
    let succeeded: Vec<Value> = builds.json["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|build| build["outcome"] == "succeeded")
        .collect();
    check!(
        succeeded.len() == 1 && succeeded[0]["template"]["vmid"] == first,
        "the version's successful builds changed: {}",
        builds.json
    );
    let template = run.pve.resource(first).await?;
    check!(
        template.as_ref().is_some_and(|guest| guest.template),
        "the promoted template {first} is gone after the rebuild"
    );
    Ok(Outcome::Pass)
}

/// Scenario 7: cancelling a running build stops Packer gracefully and the
/// plugin removes its in-progress VM, so nothing is left on the host.
async fn cancel_cleanup(run: &TargetRun) -> Result<Outcome, String> {
    let vmid = run.guard.allocate().await?;
    let version = publish(run, "cancel", &recipe(&run.target, vmid, "cancel")).await?;
    let started = run
        .fleetctl_operation(&["images", "build", &version], None)
        .await?;
    let operation = started["id"].as_str().unwrap_or_default().to_owned();
    check!(!operation.is_empty(), "the build answered no operation id");

    // Wait until the plugin's clone exists, so the cancel lands mid-build.
    let appeared = Instant::now();
    while run.pve.resource(vmid).await?.is_none() {
        check!(
            appeared.elapsed() < Duration::from_secs(300),
            "the build never created VMID {vmid}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let answer = run
        .controller
        .fleetctl(&args(&["operations", "cancel", &operation]), None)
        .await?;
    check!(
        answer.success,
        "operations cancel failed: {}",
        answer.stderr
    );
    let data = run
        .wait_operation(&operation, Duration::from_secs(600))
        .await?;
    check!(
        data["state"] == "cancelled",
        "a cancelled build ended {} ({:?}); see #271",
        data["state"],
        operation_error(&data)
    );
    // The plugin's own cleanup runs after the interrupt; give it time.
    let cleaned = Instant::now();
    while run.pve.resource(vmid).await?.is_some() {
        check!(
            cleaned.elapsed() < Duration::from_secs(300),
            "VMID {vmid} is still on the host 5 minutes after the cancel; see #271"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Ok(Outcome::Pass)
}

/// The empty directory the version-gate controller gets as its `PATH`.
fn empty_path_dir() -> PathBuf {
    std::env::temp_dir().join("fleet-image-acceptance-empty-path")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scenarios_match_the_runner() {
        assert_eq!(SCENARIOS.len(), 7);
        assert!(SCENARIOS.iter().all(|id| !id.contains(' ')));
        assert_ne!(RESULT_MARKER, proxmox_live_support::RESULT_MARKER);
    }

    #[test]
    fn only_the_version_gate_runs_without_packer() {
        let absent = || Err("the packer CLI is not installed".to_owned());
        assert_eq!(skip_reason("version-gate", absent()), None);
        for scenario in SCENARIOS.iter().filter(|id| **id != "version-gate") {
            let reason = skip_reason(scenario, absent()).unwrap();
            assert!(reason.starts_with("skipped: no usable packer"), "{reason}");
        }
        assert_eq!(skip_reason("build", Ok(())), None);
    }

    #[test]
    fn the_template_rule_is_narrow() {
        let tagged = vec![TAG.to_owned()];
        let range = |vmid: u32| (900..=949).contains(&vmid);
        let name = format!("{IMAGE_PREFIX}build-901");
        assert!(own_image_template(901, true, Some(&name), &tagged, range));
        // Outside the range, not a template, a foreign name, or untagged:
        // never touched.
        assert!(!own_image_template(7000, true, Some(&name), &tagged, range));
        assert!(!own_image_template(901, false, Some(&name), &tagged, range));
        let other = format!("{NAME_PREFIX}clone-901");
        assert!(!own_image_template(901, true, Some(&other), &tagged, range));
        assert!(!own_image_template(901, true, Some(&name), &[], range));
        assert!(!own_image_template(901, true, None, &tagged, range));
    }

    #[test]
    fn the_recipe_is_a_tagged_linked_clone_into_the_range_with_no_credential() {
        let url = "https://pve.example.test:8006/api2/json";
        let content = clone_recipe(url, "pve1", 7000, 901, "build");
        let builder = &content["builders"][0];
        assert_eq!(builder["type"], "proxmox-clone");
        // The FM-S09 URL trap: the plugin does not append /api2/json.
        assert!(
            builder["proxmox_url"]
                .as_str()
                .unwrap()
                .ends_with("/api2/json")
        );
        assert_eq!(builder["clone_vm_id"], 7000);
        assert_eq!(builder["vm_id"], 901);
        assert_eq!(builder["full_clone"], false);
        assert_eq!(builder["tags"], TAG);
        assert_eq!(builder["scsi_controller"], "virtio-scsi-pci");
        let name = builder["template_name"].as_str().unwrap();
        assert!(name.starts_with(IMAGE_PREFIX) && name.starts_with(NAME_PREFIX));
        // Credentials ride the controller environment, never the recipe
        // the controller stores.
        for key in ["username", "token", "password"] {
            assert!(builder.get(key).is_none(), "{key} is in the recipe");
        }
    }
}
