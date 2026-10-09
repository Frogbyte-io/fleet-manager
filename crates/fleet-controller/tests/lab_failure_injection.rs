//! FM-741 (#262): the Lab failure-injection suite.
//!
//! **Simulated.** A stateful fake Proxmox (guests, tasks, `nextid`) and a
//! restartable controller over one SQLite file (`support/`). Each scenario
//! interrupts the lease saga at one point of `docs/architecture/lab.md`
//! § Failure-injection acceptance and kills the controller. It then
//! restarts the controller over the same file and lets the worker
//! maintenance, the sweeper, and the cleanup converge. Every scenario then
//! checks the same invariants:
//!
//! - the lease reached one of the three allowed outcomes: a valid owned
//!   ready lease; a failed or released lease with no external allocation;
//!   or a `cleanup_failed` lease that visibly owns what remains;
//! - no Fleet guest exists that Lab state does not own;
//! - no VMID is held by two live leases;
//! - a fresh lease still provisions and releases afterwards, so nothing
//!   leaked a reservation.
//!
//! The provider-error scenarios inject a task `ERROR`, HTTP 403, and a lost
//! answer (timeout) at each Proxmox step of provisioning and cleanup.
//!
//! FM-715's capacity reservations are not on `dev` yet (#296). Until then,
//! the reservation invariant covers the clone-target VMID reservation.
//!
//! **Live.** The `live_*` tests drive the real controller binary and
//! `fleetctl` against a PVE fixture: lease → ready → exec → destroy, and
//! TTL expiry across a controller restart. They reuse the FM-611 target
//! contract (`FLEET_PVE_TARGET_<NAME>_*`) behind their own gate,
//! `FLEET_LAB_LIVE=1`. Without it, each prints a skipped result line.
//! `cargo xtask lab-acceptance` runs them and prints the redacted JSON
//! summary.

#[macro_use]
mod proxmox_live_support;
mod support;

use support::fake_pve::{FIRST_LAB_VMID, Fault, Step};
use support::lab_controller::{Controller, HOUR_MS, Run, World};

use fleet_core::{GuestState, LeaseState};

/// The readiness budget for scenarios that reach ready.
const READINESS_SECONDS: u32 = 30;
/// The budget for scenarios whose guest never answers: the executor polls
/// the agent until it runs out.
const SHORT_READINESS_SECONDS: u32 = 3;

fn now() -> i64 {
    fleet_core::SystemClock::now_unix_millis()
}

/// Asserts the lab.md invariants, then proves nothing leaked: a fresh
/// lease on a healthy host provisions to ready and releases cleanly.
async fn assert_converged(world: &World, controller: &Controller) {
    let violations = controller.violations(world).await;
    assert!(violations.is_empty(), "{violations:#?}");
    world.faults.clear();
    let fresh = controller.request_lease().await;
    assert_eq!(controller.drain(world).await, Run::Done(1));
    let lease = controller.lease(&fresh).await;
    assert_eq!(
        lease.state,
        LeaseState::Ready,
        "a fresh lease no longer provisions: {:?}",
        controller.record(&fresh).await
    );
    controller.release(&fresh).await;
    assert!(matches!(controller.drain(world).await, Run::Done(_)));
    assert_eq!(controller.lease(&fresh).await.state, LeaseState::Released);
    let violations = controller.violations(world).await;
    assert!(violations.is_empty(), "{violations:#?}");
}

/// Requests a lease, interrupts its provision at `step`, kills the
/// controller, and restarts it over the same database. Answers the
/// restarted controller and the lease.
async fn crash_and_restart(world: &World, step: Step, fault: Fault) -> (Controller, String) {
    let controller = Controller::start(world).await;
    let lease = controller.request_lease().await;
    world.faults.inject(step, fault, 1);
    assert_eq!(
        controller.drain(world).await,
        Run::Crashed,
        "the provision never reached {step:?}"
    );
    controller.kill().await;
    let restarted = Controller::start(world).await;
    assert_eq!(
        restarted.recover().await,
        1,
        "the interrupted provision fails honestly"
    );
    (restarted, lease)
}

/// [`crash_and_restart`], then an hour passes: past the readiness
/// deadline and the sweeper's grace, well inside the TTL.
async fn crash_provision(world: &World, step: Step, fault: Fault) -> (Controller, String) {
    let (controller, lease) = crash_and_restart(world, step, fault).await;
    controller.settle(world, now() + HOUR_MS).await;
    (controller, lease)
}

/// A ready lease on a healthy controller.
async fn ready_lease(world: &World) -> (Controller, String) {
    let controller = Controller::start(world).await;
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(world).await, Run::Done(1));
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Ready);
    (controller, lease)
}

/// The lease ends released, its guest and Lab machine gone.
async fn assert_released(world: &World, controller: &Controller, lease: &str) {
    let record = controller.record(lease).await;
    assert_eq!(
        controller.lease(lease).await.state,
        LeaseState::Released,
        "{record:?}"
    );
    assert!(
        world
            .pve
            .lab_guests()
            .values()
            .all(|guest| guest.name != format!("fm-lab-{}", record.id)),
        "the released lease's guest is gone"
    );
    assert!(
        !controller.lab_machine_exists(&record.id).await,
        "the released lease's Lab machine is gone"
    );
}

// ---------------------------------------------------------------------
// Controller interruptions during provisioning.
// ---------------------------------------------------------------------

#[tokio::test]
async fn interrupted_after_clone_completion_the_guest_is_cleaned_up() {
    // The clone landed and its UPID is recorded; the controller dies
    // before the start reaches PVE.
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = crash_provision(&world, Step::Start, Fault::CrashBefore).await;
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;
}

#[tokio::test]
async fn interrupted_after_boot_the_guest_is_cleaned_up() {
    // The guest runs; the controller dies before it reads the agent.
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = crash_provision(&world, Step::Agent, Fault::CrashBefore).await;
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;
}

#[tokio::test]
async fn interrupted_after_machine_registration_the_guest_and_machine_go() {
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) =
        crash_and_restart(&world, Step::MachineRegistered, Fault::CrashAfter).await;
    let record = controller.record(&lease).await;
    assert!(record.machine_id.is_some(), "the registration committed");
    assert!(controller.lab_machine_exists(&record.id).await);
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;
}

#[tokio::test]
async fn interrupted_during_ssh_trust_the_guest_and_machine_go() {
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = crash_provision(&world, Step::Trust, Fault::CrashBefore).await;
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;
}

#[tokio::test]
async fn interrupted_after_project_setup_the_guest_is_cleaned_up() {
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = crash_provision(&world, Step::ProjectSetUp, Fault::CrashAfter).await;
    let record = controller.record(&lease).await;
    assert!(
        record.ready_project_operation_id.is_some(),
        "the project child was recorded before the crash"
    );
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;
}

#[tokio::test]
async fn interrupted_at_ready_the_lease_stays_a_valid_ready_lease() {
    // The readiness transaction committed; the controller dies before the
    // operation completes. The ready lease keeps its guest and TTL.
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = crash_provision(&world, Step::Ready, Fault::CrashAfter).await;
    let stored = controller.lease(&lease).await;
    assert_eq!(stored.state, LeaseState::Ready);
    assert_eq!(controller.record(&lease).await.state, GuestState::Ready);
    assert_converged(&world, &controller).await;
    // It still expires and cleans up on schedule.
    controller
        .settle(&world, stored.expires_at.unwrap() + 1)
        .await;
    assert_released(&world, &controller, &lease).await;
}

// ---------------------------------------------------------------------
// Expiry across a restart.
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_expiry_committed_before_its_cleanup_was_queued_cleans_up_after_restart() {
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = ready_lease(&world).await;
    let expires = controller.lease(&lease).await.expires_at.unwrap();
    world.faults.inject(Step::Expired, Fault::CrashAfter, 1);
    assert_eq!(controller.sweep(&world, expires + 1).await, Run::Crashed);
    controller.kill().await;
    let restarted = Controller::start(&world).await;
    assert_eq!(
        restarted.lease(&lease).await.state,
        LeaseState::Releasing,
        "the expiry committed before the crash"
    );
    restarted.recover().await;
    restarted.settle(&world, expires + 1).await;
    assert_released(&world, &restarted, &lease).await;
    assert_converged(&world, &restarted).await;
}

#[tokio::test]
async fn an_expired_lease_whose_cleanup_never_ran_cleans_up_after_restart() {
    // The sweeper expired the lease and queued its cleanup; the controller
    // stopped before the worker claimed it.
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = ready_lease(&world).await;
    let expires = controller.lease(&lease).await.expires_at.unwrap();
    let Run::Done(report) = controller.sweep(&world, expires + 1).await else {
        panic!("the sweep crashed");
    };
    assert_eq!((report.expired, report.cleanups_queued), (1, 1));
    controller.kill().await;
    let restarted = Controller::start(&world).await;
    assert_eq!(restarted.recover().await, 0);
    restarted.settle(&world, expires + 1).await;
    assert_released(&world, &restarted, &lease).await;
    assert_converged(&world, &restarted).await;
}

#[tokio::test]
async fn a_lease_that_expired_while_no_controller_ran_is_cleaned_up_on_start() {
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = ready_lease(&world).await;
    let expires = controller.lease(&lease).await.expires_at.unwrap();
    controller.kill().await;
    // The controller was down across the expiry.
    let restarted = Controller::start(&world).await;
    restarted.settle(&world, expires + HOUR_MS).await;
    assert_released(&world, &restarted, &lease).await;
    assert_converged(&world, &restarted).await;
}

// ---------------------------------------------------------------------
// Provider errors while provisioning.
// ---------------------------------------------------------------------

/// Requests a lease on a host with `fault` scripted `times` at `step`,
/// runs it, and settles an hour later. Answers the controller and lease.
async fn provision_with(
    world: &World,
    step: Step,
    fault: Fault,
    times: u32,
) -> (Controller, String) {
    let controller = Controller::start(world).await;
    let lease = controller.request_lease().await;
    world.faults.inject(step, fault, times);
    assert!(matches!(controller.drain(world).await, Run::Done(_)));
    controller.settle(world, now() + HOUR_MS).await;
    (controller, lease)
}

#[tokio::test]
async fn provider_errors_before_the_reservation_fail_the_lease_without_allocation() {
    for (step, fault) in [
        (Step::Resources, Fault::Forbidden),
        (Step::Resources, Fault::Timeout),
        (Step::NextId, Fault::Forbidden),
        (Step::NextId, Fault::Timeout),
    ] {
        let world = World::new(READINESS_SECONDS).await;
        let (controller, lease) = provision_with(&world, step, fault, 1).await;
        assert_eq!(
            controller.lease(&lease).await.state,
            LeaseState::Failed,
            "{step:?} {fault:?}"
        );
        assert_eq!(controller.record(&lease).await.vmid, None);
        assert!(world.pve.lab_guests().is_empty());
        assert_converged(&world, &controller).await;
    }
}

#[tokio::test]
async fn provider_errors_at_the_clone_release_the_reserved_target() {
    // 403 leaves no guest; a lost answer leaves the landed clone, which
    // cleanup destroys.
    for fault in [Fault::Forbidden, Fault::Timeout] {
        let world = World::new(SHORT_READINESS_SECONDS).await;
        let (controller, lease) = provision_with(&world, Step::Clone, fault, 1).await;
        assert_eq!(controller.record(&lease).await.vmid, Some(FIRST_LAB_VMID));
        assert_released(&world, &controller, &lease).await;
        assert_converged(&world, &controller).await;
    }
}

#[tokio::test]
async fn a_failed_clone_task_releases_the_reserved_target() {
    // The clone task ends in ERROR and leaves no guest: the executor reads
    // the task instead of polling the absent config for the settle bound
    // (#310).
    let world = World::new(SHORT_READINESS_SECONDS).await;
    let (controller, lease) = provision_with(&world, Step::Clone, Fault::TaskError, 1).await;
    assert_eq!(controller.record(&lease).await.vmid, Some(FIRST_LAB_VMID));
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;
}

/// #327: the provision record keeps its saga state (`ready`) and its VMID as
/// history after cleanup, so the read model reports what became of the guest.
#[tokio::test]
async fn a_released_lease_reports_its_guest_as_destroyed_or_kept() {
    let world = World::new(READINESS_SECONDS).await;
    let controller = Controller::start(&world).await;

    // Destroyed: the lease is released, the guest is gone from PVE, and the
    // record no longer reads as a live guest.
    let destroyed = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(
        controller.provision_view(&destroyed).await,
        (
            "ready".to_owned(),
            "present".to_owned(),
            Some("ready".to_owned())
        )
    );
    controller.release(&destroyed).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(
        controller.lease(&destroyed).await.state,
        LeaseState::Released
    );
    let vmid = controller.record(&destroyed).await.vmid;
    assert!(vmid.is_some(), "the VMID stays as history");
    assert_eq!(
        controller.provision_view(&destroyed).await,
        (
            "ready".to_owned(),
            "destroyed".to_owned(),
            Some("released".to_owned())
        )
    );

    // Kept: released too, but the guest stays and says so.
    let kept = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    controller.release_keeping(&kept).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(controller.lease(&kept).await.state, LeaseState::Released);
    assert_eq!(
        controller.provision_view(&kept).await,
        (
            "ready".to_owned(),
            "kept".to_owned(),
            Some("released".to_owned())
        )
    );
    assert!(
        !world.pve.lab_guests().is_empty(),
        "the kept guest is still in PVE"
    );
}

/// #327: a lease the saga failed is compensated releasing -> released; its
/// record ends `never_ready` and the guest reads destroyed, not present.
#[tokio::test]
async fn a_compensated_lease_reports_its_guest_as_destroyed() {
    let world = World::new(SHORT_READINESS_SECONDS).await;
    // A start that fails: the clone landed, so cleanup destroyed a guest.
    let (controller, lease) = provision_with(&world, Step::Start, Fault::TaskError, 1).await;
    assert_released(&world, &controller, &lease).await;
    assert_eq!(
        controller.provision_view(&lease).await,
        (
            "never_ready".to_owned(),
            "destroyed".to_owned(),
            Some("released".to_owned())
        )
    );
    // A refused clone left no guest to destroy; the reserved VMID stays as
    // history on the record.
    let world = World::new(SHORT_READINESS_SECONDS).await;
    let (controller, lease) = provision_with(&world, Step::Clone, Fault::Forbidden, 1).await;
    assert_released(&world, &controller, &lease).await;
    let (_, guest, lease_state) = controller.provision_view(&lease).await;
    assert_eq!(guest, "destroyed");
    assert_eq!(lease_state.as_deref(), Some("released"));
}

#[tokio::test]
async fn provider_errors_at_the_start_end_ready_or_cleaned_up() {
    // 403: nothing started, the provision fails at boot.
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = provision_with(&world, Step::Start, Fault::Forbidden, 1).await;
    assert_eq!(
        controller.record(&lease).await.failed_step.as_deref(),
        Some("boot")
    );
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;

    // A failed start task: the guest never answers, the deadline ends it.
    let world = World::new(SHORT_READINESS_SECONDS).await;
    let (controller, lease) = provision_with(&world, Step::Start, Fault::TaskError, 1).await;
    assert_eq!(
        controller.record(&lease).await.failed_step.as_deref(),
        Some("guest_ip")
    );
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;

    // A lost answer for a start that landed: the executor confirms the
    // guest runs and carries on to ready.
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = provision_with(&world, Step::Start, Fault::Timeout, 1).await;
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Ready);
    assert_converged(&world, &controller).await;
}

#[tokio::test]
async fn transient_agent_errors_are_retried_to_ready() {
    for fault in [Fault::Forbidden, Fault::Timeout] {
        let world = World::new(READINESS_SECONDS).await;
        let (controller, lease) = provision_with(&world, Step::Agent, fault, 1).await;
        assert_eq!(
            controller.lease(&lease).await.state,
            LeaseState::Ready,
            "{fault:?}"
        );
        assert_converged(&world, &controller).await;
    }
}

#[tokio::test]
async fn an_agent_that_never_answers_ends_never_ready_and_cleaned_up() {
    let world = World::new(SHORT_READINESS_SECONDS).await;
    let (controller, lease) = provision_with(&world, Step::Agent, Fault::Forbidden, 1_000).await;
    assert_eq!(
        controller.record(&lease).await.failed_step.as_deref(),
        Some("guest_ip")
    );
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;
}

#[tokio::test]
async fn a_refused_host_key_ends_never_ready_and_cleaned_up() {
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = provision_with(&world, Step::Trust, Fault::Forbidden, 1).await;
    assert_eq!(
        controller.record(&lease).await.failed_step.as_deref(),
        Some("ssh_trust")
    );
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;
}

// ---------------------------------------------------------------------
// Provider errors while destroying.
// ---------------------------------------------------------------------

/// Releases a ready lease on a host with `fault` scripted `times` at
/// `step`, then settles an hour later (past every backoff).
async fn release_with(world: &World, step: Step, fault: Fault, times: u32) -> (Controller, String) {
    let (controller, lease) = ready_lease(world).await;
    controller.release(&lease).await;
    world.faults.inject(step, fault, times);
    assert!(matches!(controller.drain(world).await, Run::Done(_)));
    controller.settle(world, now() + HOUR_MS).await;
    (controller, lease)
}

#[tokio::test]
async fn a_transient_destroy_error_is_retried_to_released() {
    for (step, fault) in [
        (Step::Resources, Fault::Forbidden),
        (Step::Resources, Fault::Timeout),
        (Step::Stop, Fault::Forbidden),
        (Step::Stop, Fault::TaskError),
        // The stop landed, its answer was lost: the retry finds it stopped.
        (Step::Stop, Fault::Timeout),
        (Step::DestroyConfig, Fault::Forbidden),
        (Step::DestroyConfig, Fault::Timeout),
        (Step::Delete, Fault::Forbidden),
        (Step::Delete, Fault::TaskError),
        // The delete landed, its answer was lost: the retry finds nothing.
        (Step::Delete, Fault::Timeout),
    ] {
        let world = World::new(READINESS_SECONDS).await;
        let (controller, lease) = release_with(&world, step, fault, 1).await;
        let stored = controller.lease(&lease).await;
        assert_eq!(stored.cleanup_attempts, 1, "{step:?} {fault:?}");
        assert_released(&world, &controller, &lease).await;
        assert_converged(&world, &controller).await;
    }
}

#[tokio::test]
async fn a_persistent_destroy_error_leaves_a_visible_cleanup_failed_lease() {
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = release_with(&world, Step::Delete, Fault::Forbidden, 1_000).await;
    let stored = controller.lease(&lease).await;
    assert_eq!(stored.state, LeaseState::CleanupFailed);
    assert_eq!(
        stored.cleanup_attempts,
        fleet_application::lab::MAX_CLEANUP_ATTEMPTS
    );
    // The lease still names the guest it owns, the guest is still there,
    // and the exhaustion is audited once.
    let record = controller.record(&lease).await;
    assert_eq!(record.vmid, Some(FIRST_LAB_VMID));
    assert!(world.pve.lab_guests().contains_key(&FIRST_LAB_VMID));
    assert_eq!(controller.audit_events("lab_lease_cleanup_failed").await, 1);
    assert_converged(&world, &controller).await;
}

// ---------------------------------------------------------------------
// Interruptions before boot: no readiness deadline is recorded yet.
// ---------------------------------------------------------------------

/// The interruption points between the VMID reservation and the boot step:
/// right after the reservation, before the clone request reaches PVE, and
/// after the clone landed but before its answer was recorded.
const BEFORE_BOOT: [(Step, Fault); 3] = [
    (Step::Reserved, Fault::CrashAfter),
    (Step::Clone, Fault::CrashBefore),
    (Step::Clone, Fault::CrashAfter),
];

#[tokio::test]
async fn interrupted_before_boot_nothing_is_untracked_and_the_lease_converges_by_its_maximum_lifetime()
 {
    for (step, fault) in BEFORE_BOOT {
        let world = World::new(READINESS_SECONDS).await;
        let (controller, lease) = crash_provision(&world, step, fault).await;
        // Whatever the interrupted clone left is still the lease's.
        let violations = controller.ownership_violations(&world).await;
        assert!(violations.is_empty(), "{step:?} {fault:?}: {violations:#?}");
        let max = controller.lease(&lease).await.max_lifetime_at;
        controller.settle(&world, max).await;
        assert_released(&world, &controller, &lease).await;
        let violations = controller.violations(&world).await;
        assert!(violations.is_empty(), "{step:?} {fault:?}: {violations:#?}");
    }
}

#[tokio::test]
async fn a_queued_lease_never_takes_the_vmid_of_an_interrupted_clone() {
    // Two leases are queued; the controller dies right after the first
    // one's clone landed. After the restart the second provisions into
    // another VMID, and each guest has exactly one owner.
    let world = World::new(READINESS_SECONDS).await;
    let controller = Controller::start(&world).await;
    let first = controller.request_lease().await;
    let second = controller.request_lease().await;
    world.faults.inject(Step::Clone, Fault::CrashAfter, 1);
    assert_eq!(controller.drain(&world).await, Run::Crashed);
    controller.kill().await;
    let restarted = Controller::start(&world).await;
    assert_eq!(restarted.recover().await, 1);
    assert_eq!(restarted.drain(&world).await, Run::Done(1));
    assert_eq!(restarted.lease(&second).await.state, LeaseState::Ready);
    let (a, b) = (
        restarted.record(&first).await.vmid,
        restarted.record(&second).await.vmid,
    );
    assert_eq!(a, Some(FIRST_LAB_VMID));
    assert_eq!(b, Some(FIRST_LAB_VMID + 1));
    assert_eq!(world.pve.lab_guests().len(), 2);
    let violations = restarted.ownership_violations(&world).await;
    assert!(violations.is_empty(), "{violations:#?}");
}

#[tokio::test]
async fn interrupted_before_boot_the_lease_converges_within_an_hour() {
    for (step, fault) in BEFORE_BOOT {
        let world = World::new(READINESS_SECONDS).await;
        let (controller, _) = crash_provision(&world, step, fault).await;
        let violations = controller.violations(&world).await;
        assert!(violations.is_empty(), "{step:?} {fault:?}: {violations:#?}");
    }
}

#[tokio::test]
async fn an_interrupted_reservation_is_freed_once_its_lease_is_released() {
    let world = World::new(READINESS_SECONDS).await;
    let (controller, lease) = crash_provision(&world, Step::Reserved, Fault::CrashAfter).await;
    let max = controller.lease(&lease).await.max_lifetime_at;
    controller.settle(&world, max).await;
    assert_released(&world, &controller, &lease).await;
    assert_converged(&world, &controller).await;
}

// ---------------------------------------------------------------------
// Interruptions mid-destroy.
// ---------------------------------------------------------------------

/// The interruption points inside a cleanup's destroy: after the stop
/// landed, before the delete reached PVE, and after the delete landed.
const MID_DESTROY: [(Step, Fault); 3] = [
    (Step::Stop, Fault::CrashAfter),
    (Step::Delete, Fault::CrashBefore),
    (Step::Delete, Fault::CrashAfter),
];

/// Releases a ready lease, kills the controller at `step` inside the
/// destroy, restarts it, and settles an hour later.
async fn crash_destroy(world: &World, step: Step, fault: Fault) -> (Controller, String) {
    let (controller, lease) = ready_lease(world).await;
    controller.release(&lease).await;
    world.faults.inject(step, fault, 1);
    assert_eq!(controller.drain(world).await, Run::Crashed);
    controller.kill().await;
    let restarted = Controller::start(world).await;
    assert_eq!(
        restarted.recover().await,
        2,
        "the cleanup and its destroy child fail honestly"
    );
    restarted.settle(world, now() + HOUR_MS).await;
    (restarted, lease)
}

#[tokio::test]
async fn interrupted_mid_destroy_nothing_is_untracked() {
    for (step, fault) in MID_DESTROY {
        let world = World::new(READINESS_SECONDS).await;
        let (controller, lease) = crash_destroy(&world, step, fault).await;
        let violations = controller.ownership_violations(&world).await;
        assert!(violations.is_empty(), "{step:?} {fault:?}: {violations:#?}");
        // The record still names its guest, so nothing is forgotten.
        let record = controller.record(&lease).await;
        assert_eq!(record.vmid, Some(FIRST_LAB_VMID));
    }
}

#[tokio::test]
async fn interrupted_mid_destroy_the_cleanup_is_retried() {
    for (step, fault) in MID_DESTROY {
        let world = World::new(READINESS_SECONDS).await;
        let (controller, lease) = crash_destroy(&world, step, fault).await;
        assert_released(&world, &controller, &lease).await;
        assert_converged(&world, &controller).await;
    }
}

// ---------------------------------------------------------------------
// Live mode: `cargo xtask lab-acceptance`.
// ---------------------------------------------------------------------

mod live {
    use std::time::{Duration, Instant};

    use fleet_application::images::RecipePort as _;
    use fleet_application::operation::OperationPort as _;
    use serde_json::{Value, json};

    use super::proxmox_live_support::config::{self, Gate, Target};
    use super::proxmox_live_support::pve::PveAdmin;
    use super::proxmox_live_support::{Outcome, TargetRun, args, redactor_for, result_line};

    /// The marker before every result line `cargo xtask lab-acceptance`
    /// collects.
    pub const RESULT_MARKER: &str = "FLEET_LAB_ACCEPTANCE_RESULT";
    /// The Lab live gate.
    pub const LIVE_GATE: &str = "FLEET_LAB_LIVE";
    /// The scenarios, in report order. Kept in step with
    /// `xtask/src/lab_acceptance.rs`.
    pub const SCENARIOS: [&str; 4] = [
        "lease-exec-destroy",
        "ttl-expiry-restart",
        "put-collect-roundtrip",
        "detached-exec",
    ];
    /// The SSH user the fixture's template accepts the controller's agent
    /// key for; `root` when unset.
    const SSH_USER_PREFIX: &str = "FLEET_LAB_TARGET_";
    /// How long a lease may take to become ready, and to be destroyed.
    const LEASE_BOUND: Duration = Duration::from_secs(900);
    /// The TTL of the expiry scenario's lease.
    const SHORT_TTL_SECONDS: u64 = 60;
    /// The longest the restarted controller's sweeper may take to release
    /// the expired lease: its interval (60 s by default), the destroy, and
    /// margin.
    const SWEEP_BOUND: Duration = Duration::from_secs(600);

    /// The Lab gate over the FM-611 target contract: the target variables
    /// are the same, the gate is `FLEET_LAB_LIVE`.
    fn gate() -> Result<Gate, String> {
        let mut env: std::collections::BTreeMap<String, String> = std::env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        let on = env.get(LIVE_GATE).map(|value| value.trim()) == Some("1");
        if !on {
            return Ok(Gate::Off(format!("{LIVE_GATE} is not 1")));
        }
        env.insert(config::LIVE_GATE.to_owned(), "1".to_owned());
        config::load(&env, config::read_secret_file)
            .map_err(|problems| problems.replace(config::LIVE_GATE, LIVE_GATE))
    }

    /// One result line under the Lab marker.
    fn line(
        scenario: &str,
        target: Option<&str>,
        result: &Result<Outcome, String>,
        duration: Duration,
    ) -> String {
        result_line(scenario, target, result, duration).replacen(
            super::proxmox_live_support::RESULT_MARKER,
            RESULT_MARKER,
            1,
        )
    }

    /// The cross-process lock the FM-611 and FM-704 suites take: live
    /// suites never overlap on a target's VMID range.
    fn suite_lock() -> std::fs::File {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "unknown".to_owned());
        let path = std::env::temp_dir().join(format!("fleet-pve-acceptance-{user}.lock"));
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .unwrap_or_else(|error| panic!("the suite lock {} must open: {error}", path.display()));
        file.lock().expect("the suite lock must acquire");
        file
    }

    /// Runs one scenario on every selected target and reports each.
    pub async fn scenario<F>(id: &'static str, body: F)
    where
        F: AsyncFn(&TargetRun, &Lab) -> Result<Outcome, String>,
    {
        let targets = match gate() {
            Ok(Gate::Off(reason)) => {
                println!(
                    "{}",
                    line(id, None, &Ok(Outcome::Skipped(reason)), Duration::ZERO)
                );
                return;
            }
            Ok(Gate::On(targets)) => targets,
            Err(problems) => panic!("{problems}"),
        };
        if let Err(detail) = super::proxmox_live_support::controller::locate_fleetctl() {
            panic!("{LIVE_GATE}=1 but {detail}");
        }
        let _lock = suite_lock();
        let mut failures = Vec::new();
        for target in targets {
            let started = Instant::now();
            let redactor = redactor_for(&target);
            let target = std::sync::Arc::new(target);
            let result = match Lab::check(&target).await {
                Err(Unfit::Skip(reason)) => Ok(Outcome::Skipped(reason)),
                Err(Unfit::Fail(reason)) => Err(reason),
                Ok(lab) => match TargetRun::start(target.clone(), id).await {
                    Ok(run) => {
                        let before = lab_guests(&run).await;
                        let result = match &before {
                            Ok(_) => body(&run, &lab).await,
                            Err(reason) => Err(reason.clone()),
                        };
                        let leaked = match before {
                            Ok(before) => lab.sweep_leftovers(&run, &before).await,
                            Err(_) => Ok(()),
                        };
                        let result = match (result, leaked) {
                            (result, Ok(())) => result,
                            (Ok(_), Err(leak)) => Err(leak),
                            (Err(reason), Err(leak)) => Err(format!("{reason}; {leak}")),
                        };
                        run.finish(result).await
                    }
                    Err(reason) => Err(reason),
                },
            };
            println!(
                "{}",
                redactor.line(&line(id, Some(&target.name), &result, started.elapsed()))
            );
            if let Err(reason) = result {
                failures.push(redactor.line(&format!("{}: {reason}", target.name)));
            }
        }
        assert!(
            failures.is_empty(),
            "scenario {id} failed:\n  {}",
            failures.join("\n  ")
        );
    }

    /// Why a target cannot run the Lab scenarios.
    enum Unfit {
        /// It is not a Lab fixture: reported as skipped, with the reason.
        Skip(String),
        /// It could not be checked: a failure.
        Fail(String),
    }

    /// One target's Lab fixture facts.
    pub struct Lab {
        ssh_user: String,
    }

    impl Lab {
        /// Whether the target is a Lab fixture; the reason it is not
        /// otherwise. Lab clones into PVE's next free VMID, so the cluster's
        /// `next-id` range must lie inside the suite's `VMID_RANGE`.
        async fn check(target: &Target) -> Result<Self, Unfit> {
            let pve = PveAdmin::new(target);
            let next = pve
                .get("/cluster/nextid")
                .await
                .map_err(|error| Unfit::Fail(format!("/cluster/nextid is unreadable: {error}")))?;
            let next: u32 = match &next {
                Value::String(text) => text.parse().ok(),
                Value::Number(number) => number.as_u64().and_then(|n| u32::try_from(n).ok()),
                _ => None,
            }
            .ok_or_else(|| Unfit::Fail(format!("/cluster/nextid answered {next}")))?;
            if !target.range.contains(next) {
                return Err(Unfit::Skip(format!(
                    "skipped: not a Lab fixture: the cluster's next free VMID {next} lies outside \
                     {} ({}); reserve the range for Fleet with the datacenter.cfg next-id \
                     setting (docs/operations/proxmox-token.md)",
                    target.var("VMID_RANGE"),
                    target.range
                )));
            }
            let ssh_user = std::env::var(format!("{SSH_USER_PREFIX}{}_SSH_USER", target.name))
                .ok()
                .filter(|user| !user.trim().is_empty())
                .unwrap_or_else(|| "root".to_owned());
            Ok(Self { ssh_user })
        }

        /// The safety net after every scenario: a Lab guest in the range
        /// that this scenario created and Fleet did not remove is a leak. It
        /// is destroyed and the scenario fails. `fm-lab-*` guests that
        /// existed before the scenario (`before`) belong to someone else and
        /// are never touched.
        async fn sweep_leftovers(
            &self,
            run: &TargetRun,
            before: &std::collections::BTreeSet<u32>,
        ) -> Result<(), String> {
            let leaked: Vec<_> = run
                .pve
                .resources()
                .await?
                .into_iter()
                .filter(|guest| is_lab_guest(run, guest) && !before.contains(&guest.vmid))
                .collect();
            if leaked.is_empty() {
                return Ok(());
            }
            for guest in &leaked {
                run.pve.destroy(guest).await?;
            }
            Err(format!(
                "Lab left guests behind (destroyed by the harness): {:?}",
                leaked.iter().map(|guest| guest.vmid).collect::<Vec<_>>()
            ))
        }

        /// A trusted account, a promoted image whose build artifact is the
        /// fixture's template, and a published Lab template with `ttl`.
        /// Answers the account and the Lab template version.
        async fn prepare(&self, run: &TargetRun, ttl: u64) -> Result<(String, String), String> {
            let account = run
                .trusted_account("lab-acceptance", &run.target.token)
                .await?;
            let image = promoted_image(run, &account).await?;
            let (status, body) = run
                .controller
                .post(
                    "/api/v1/lab/templates",
                    &json!({
                        "name": "fleet-acceptance-lab",
                        "description": "Fleet Lab acceptance (FM-741); safe to delete",
                        "imageVersionId": image,
                        "cores": 1,
                        "memoryMib": 1024,
                        "diskGib": 4,
                        "bootstrapProjectId": null,
                        "readinessProbe": "guest_agent",
                        "readinessCommand": null,
                        "sshUser": self.ssh_user,
                        "readinessDeadlineSeconds": 600,
                        "ttlSeconds": ttl,
                        "cleanup": "destroy",
                    }),
                )
                .await?;
            check!(
                status == 201 || status == 200,
                "creating the Lab template answered {status}: {body}"
            );
            let template = body["data"]["id"].as_str().unwrap_or_default().to_owned();
            let published = run
                .controller
                .fleetctl(&args(&["lab", "publish", &template]), None)
                .await?;
            check!(
                published.success,
                "lab publish failed: {}",
                published.stderr
            );
            let version = published.json["id"].as_str().unwrap_or_default().to_owned();
            check!(
                !version.is_empty(),
                "lab publish answered no version: {}",
                published.json
            );
            Ok((account, version))
        }
    }

    /// Whether `guest` is a Fleet Lab guest inside the target's range.
    fn is_lab_guest(run: &TargetRun, guest: &super::proxmox_live_support::pve::VmResource) -> bool {
        run.target.range.contains(guest.vmid)
            && guest
                .name
                .as_deref()
                .is_some_and(|name| name.starts_with("fm-lab-"))
    }

    /// The Lab guests already in the range when a scenario starts.
    async fn lab_guests(run: &TargetRun) -> Result<std::collections::BTreeSet<u32>, String> {
        let existing: std::collections::BTreeSet<u32> = run
            .pve
            .resources()
            .await?
            .into_iter()
            .filter(|guest| is_lab_guest(run, guest))
            .map(|guest| guest.vmid)
            .collect();
        if !existing.is_empty() {
            run.log(&format!(
                "warning: Lab guests {existing:?} were in the range before the scenario; left alone"
            ));
        }
        Ok(existing)
    }

    /// Creates and publishes an image recipe through `fleetctl`, records a
    /// succeeded build whose artifact is the fixture's template, and
    /// promotes it through the real promotion gate. The image build itself
    /// is FM-704's suite; only its record is seeded here, in the stopped
    /// controller's store.
    async fn promoted_image(run: &TargetRun, account: &str) -> Result<String, String> {
        let target = &run.target;
        let content = json!({"builders": [{
            "type": "proxmox-clone",
            "proxmox_url": format!("https://{}:{}/api2/json", target.host, target.port),
            "node": target.node,
            "clone_vm_id": target.template_vmid,
            "vm_name": "fleet-acceptance-lab-image",
            "communicator": "none",
        }]});
        let created = run
            .controller
            .fleetctl(
                &args(&[
                    "images",
                    "create",
                    "--name",
                    "fleet-acceptance-lab-image",
                    "--description",
                    "Fleet Lab acceptance (FM-741)",
                    "--node",
                    &target.node,
                    "--storage-pool",
                    &target.storage,
                    "--source",
                    "clone",
                ]),
                Some(content.to_string()),
            )
            .await?;
        check!(created.success, "images create failed: {}", created.stderr);
        let recipe = created.json["id"].as_str().unwrap_or_default().to_owned();
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
            "images publish answered no version: {}",
            published.json
        );
        let (node, vmid) = (target.node.clone(), target.template_vmid);
        let account = account.to_owned();
        let seeded = version.clone();
        run.controller
            .with_store(async move |store| {
                let pool = store.pool().clone();
                let operations = fleet_storage_sqlite::OperationRepository::new(pool.clone());
                let recipes = fleet_storage_sqlite::RecipeRepository::new(pool);
                let version = recipes.get_version(&seeded).await?;
                let operation = operations
                    .create(
                        "image.build",
                        Some(&format!("lab-acceptance-seed:{seeded}")),
                        None,
                        None,
                        Some(&json!({ "versionId": seeded }).to_string()),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let now = fleet_core::SystemClock::now_unix_millis();
                let mut record = fleet_core::ImageBuildRecord {
                    id: uuid::Uuid::now_v7().to_string(),
                    operation_id: operation.id.clone(),
                    recipe_id: version.recipe_id.clone(),
                    version_id: version.id.clone(),
                    content_digest: version.content_digest.clone(),
                    asset_digests: Vec::new(),
                    packer_version: None,
                    proxmox_plugin_version: None,
                    account_id: Some(account),
                    node: version.node.clone(),
                    storage_pool: version.storage_pool.clone(),
                    started_at: now,
                    ended_at: None,
                    outcome: "running".to_owned(),
                    reason: None,
                    template: None,
                };
                recipes.start_build(&record).await?;
                record.ended_at = Some(now + 1);
                record.outcome = "succeeded".to_owned();
                record.packer_version = Some("seeded-by-lab-acceptance".to_owned());
                record.proxmox_plugin_version = Some("seeded-by-lab-acceptance".to_owned());
                record.template = Some(fleet_core::ImageBuildTemplate {
                    node,
                    vmid,
                    name: "fleet-acceptance-lab-image".to_owned(),
                });
                recipes.finish_build(&record).await?;
                operations
                    .transition(&operation.id, "running")
                    .await
                    .map_err(|error| error.to_string())?;
                operations
                    .complete(&operation.id, "succeeded", Some(r#"{"seeded":true}"#), None)
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(())
            })
            .await?;
        let promoted = run
            .controller
            .fleetctl(&args(&["images", "promote", &version]), None)
            .await?;
        check!(
            promoted.success,
            "images promote failed: {}",
            promoted.stderr
        );
        Ok(version)
    }

    /// `fleetctl lab create --wait`: answers the ready lease.
    async fn ready_lease(run: &TargetRun, account: &str, version: &str) -> Result<Value, String> {
        let bound = LEASE_BOUND.as_secs().to_string();
        let created = run
            .controller
            .fleetctl(
                &args(&[
                    "lab",
                    "create",
                    version,
                    "--purpose",
                    "Fleet Lab acceptance (FM-741)",
                    "--account",
                    account,
                    "--wait",
                    "--timeout",
                    &bound,
                ]),
                None,
            )
            .await?;
        check!(
            created.success && created.json["state"] == "ready",
            "lab create --wait did not reach ready ({}): {} {}",
            created.json["state"],
            created.json,
            created.stderr
        );
        let vmid = created.json["vmid"].as_u64().unwrap_or_default();
        if !u32::try_from(vmid).is_ok_and(|vmid| run.target.range.contains(vmid)) {
            // The harness never destroys outside the range itself: Fleet's
            // own cleanup removes the guest it just created there.
            let id = created.json["id"].as_str().unwrap_or_default();
            let bound = LEASE_BOUND.as_secs().to_string();
            let destroyed = run
                .controller
                .fleetctl(
                    &args(&["lab", "destroy", id, "--wait", "--timeout", &bound]),
                    None,
                )
                .await?;
            if destroyed.success
                && destroyed.json["state"] == "released"
                && guest_gone(run, &created.json).await.is_ok()
            {
                return Err(format!(
                    "the Lab guest {vmid} lay outside the VMID range; Fleet destroyed it"
                ));
            }
            // Outside the range the harness may not delete anything, so a
            // failed Fleet cleanup is reported as a leak for the operator.
            return Err(format!(
                "LEAK: the Lab guest {vmid} lies outside the VMID range and Fleet's destroy ended \
                 {} ({}) without removing it from PVE; remove VMID {vmid} on the host by hand",
                destroyed.json["state"], destroyed.stderr
            ));
        }
        run.log(&format!("lease ready on guest {vmid}"));
        Ok(created.json)
    }

    /// The guest is gone from the cluster.
    async fn guest_gone(run: &TargetRun, lease: &Value) -> Result<(), String> {
        let vmid = u32::try_from(lease["vmid"].as_u64().unwrap_or_default())
            .map_err(|_| "the lease names no VMID".to_owned())?;
        check!(
            run.pve.resource(vmid).await?.is_none(),
            "the released lease's guest {vmid} still exists"
        );
        Ok(())
    }

    /// lease → ready → exec → destroy.
    pub async fn lease_exec_destroy(run: &TargetRun, lab: &Lab) -> Result<Outcome, String> {
        let default_key = std::env::var_os("HOME").is_some_and(|home| {
            ["id_rsa", "id_ecdsa", "id_ed25519"].iter().any(|name| {
                std::path::Path::new(&home)
                    .join(".ssh")
                    .join(name)
                    .is_file()
            })
        });
        if std::env::var_os("SSH_AUTH_SOCK").is_none() && !default_key {
            // The gate is on: a missing prerequisite must not read as a pass.
            return Err(String::from(
                "neither SSH_AUTH_SOCK nor a default ~/.ssh key file is present; Lab exec \
                 offers the controller's SSH agent keys, then its default key files, and one \
                 must be accepted by the template's user",
            ));
        }
        let (account, version) = lab.prepare(run, 3_600).await?;
        let lease = ready_lease(run, &account, &version).await?;
        let id = lease["id"].as_str().unwrap_or_default().to_owned();
        let exec = run
            .controller
            .fleetctl(
                &args(&[
                    "lab",
                    "exec",
                    &id,
                    "--wait",
                    "--timeout",
                    "60",
                    "--",
                    "uname",
                    "-s",
                ]),
                None,
            )
            .await?;
        check!(
            exec.success && exec.json["exitCode"] == 0,
            "lab exec did not exit 0: {} {}",
            exec.json,
            exec.stderr
        );
        check!(
            exec.json["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("Linux"),
            "lab exec printed {}",
            exec.json["stdout"]
        );
        let bound = LEASE_BOUND.as_secs().to_string();
        let destroyed = run
            .controller
            .fleetctl(
                &args(&["lab", "destroy", &id, "--wait", "--timeout", &bound]),
                None,
            )
            .await?;
        check!(
            destroyed.success && destroyed.json["state"] == "released",
            "lab destroy --wait ended {}: {}",
            destroyed.json["state"],
            destroyed.stderr
        );
        guest_gone(run, &lease).await?;
        let machines = run
            .controller
            .fleetctl(&args(&["machines", "list", "--tag", "lab"]), None)
            .await?;
        check!(
            machines.success && machines.json["items"].as_array().is_some_and(Vec::is_empty),
            "the Lab machine outlived its lease: {}",
            machines.json
        );
        Ok(Outcome::Pass)
    }

    /// A file larger than 2 MiB goes into a ready lease with `lab put`, is
    /// verified in the guest, is refused when it would clobber, and comes
    /// back byte for byte through `lab collect` and `lab artifact-get`
    /// (#393).
    #[allow(clippy::too_many_lines)]
    pub async fn put_collect_roundtrip(run: &TargetRun, lab: &Lab) -> Result<Outcome, String> {
        use sha2::Digest as _;
        let (account, version) = lab.prepare(run, 3_600).await?;
        let lease = ready_lease(run, &account, &version).await?;
        let id = lease["id"].as_str().unwrap_or_default().to_owned();
        // 3 MiB and 17 bytes of deterministic noise: past axum's 2 MiB body
        // default, and not a multiple of any chunk size.
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let content: Vec<u8> = (0..(3 * 1024 * 1024 + 17))
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect();
        let digest = sha2::Sha256::digest(&content)
            .iter()
            .fold(String::new(), |mut text, byte| {
                use std::fmt::Write as _;
                let _ = write!(text, "{byte:02x}");
                text
            });
        let scratch = tempfile::tempdir().map_err(|error| error.to_string())?;
        let local = scratch.path().join("candidate.bin");
        std::fs::write(&local, &content).map_err(|error| error.to_string())?;
        let local_text = local.to_string_lossy().into_owned();
        let guest = "/tmp/fleet-put-roundtrip.bin";
        let put = async |extra: &[&str], from: &str, to: &str| {
            let mut words = vec!["lab", "put", id.as_str(), from, to];
            words.extend_from_slice(extra);
            words.extend(["--wait", "--timeout", "300"]);
            run.controller.fleetctl(&args(&words), None).await
        };

        let first = put(&[], &local_text, guest).await?;
        check!(
            first.success && first.json["state"] == "succeeded",
            "lab put did not succeed: {} {}",
            first.json,
            first.stderr
        );
        check!(
            first.json["sha256"] == digest.as_str()
                && first.json["sizeBytes"].as_u64() == Some(content.len() as u64),
            "lab put recorded the wrong size or digest: {}",
            first.json
        );
        // The guest's own view: the digest matches and no temporary file
        // is left beside the target.
        let check_guest = run
            .controller
            .fleetctl(
                &args(&[
                    "lab",
                    "exec",
                    &id,
                    "--wait",
                    "--timeout",
                    "60",
                    "--",
                    "sh",
                    "-c",
                    &format!("sha256sum {guest}; ls -A /tmp"),
                ]),
                None,
            )
            .await?;
        let seen = check_guest.json["stdout"].as_str().unwrap_or_default();
        check!(
            check_guest.success && seen.contains(&digest) && !seen.contains(".fleet-put."),
            "the guest disagrees: {}",
            check_guest.json
        );

        // An existing target is refused, and left alone.
        let refused = put(&[], &local_text, guest).await?;
        check!(
            !refused.success && refused.json["reason"] == "target_exists",
            "a second put without --overwrite was not refused: {}",
            refused.json
        );
        // A missing directory is refused.
        let nowhere = put(&[], &local_text, "/tmp/fleet-no-such-dir/x.bin").await?;
        check!(
            !nowhere.success && nowhere.json["reason"] == "no_directory",
            "a put into a missing directory was not refused: {}",
            nowhere.json
        );
        // --overwrite replaces the file.
        let small = scratch.path().join("small.txt");
        std::fs::write(&small, b"replacement\n").map_err(|error| error.to_string())?;
        let replaced = put(&["--overwrite"], &small.to_string_lossy(), guest).await?;
        check!(
            replaced.success && replaced.json["state"] == "succeeded",
            "--overwrite did not replace the file: {}",
            replaced.json
        );
        let back = put(&["--overwrite"], &local_text, guest).await?;
        check!(
            back.success,
            "restoring the candidate failed: {}",
            back.json
        );

        // Round trip: collect the same file and compare every byte.
        let collected = run
            .controller
            .fleetctl(
                &args(&["lab", "collect", &id, guest, "--wait", "--timeout", "300"]),
                None,
            )
            .await?;
        check!(
            collected.success && collected.json["state"] == "succeeded",
            "lab collect did not succeed: {} {}",
            collected.json,
            collected.stderr
        );
        let artifact = collected.json["artifacts"][0]["artifactId"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        check!(
            collected.json["artifacts"][0]["sha256"] == digest.as_str(),
            "the collected digest differs from the put one: {}",
            collected.json
        );
        let out = scratch.path().join("roundtrip.bin");
        let got = run
            .controller
            .fleetctl(
                &args(&[
                    "lab",
                    "artifact-get",
                    &artifact,
                    "--out",
                    &out.to_string_lossy(),
                ]),
                None,
            )
            .await?;
        check!(got.success, "artifact-get failed: {}", got.stderr);
        check!(
            std::fs::read(&out).map_err(|error| error.to_string())? == content,
            "the round-tripped file differs from the one that was put"
        );

        let bound = LEASE_BOUND.as_secs().to_string();
        let destroyed = run
            .controller
            .fleetctl(
                &args(&["lab", "destroy", &id, "--wait", "--timeout", &bound]),
                None,
            )
            .await?;
        check!(
            destroyed.success && destroyed.json["state"] == "released",
            "lab destroy --wait ended {}: {}",
            destroyed.json["state"],
            destroyed.stderr
        );
        guest_gone(run, &lease).await?;
        Ok(Outcome::Pass)
    }

    /// How long the detached command sleeps: past the 900-second bound of a
    /// synchronous exec by default, and the issue's literal 30 minutes with
    /// `FLEET_LAB_DETACH_SECONDS=1800`.
    fn detach_seconds() -> Result<u64, String> {
        match std::env::var("FLEET_LAB_DETACH_SECONDS") {
            Err(_) => Ok(960),
            Ok(value) => value
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|seconds| (30..=7_200).contains(seconds))
                .ok_or_else(|| {
                    "FLEET_LAB_DETACH_SECONDS must be a number from 30 to 7200".to_owned()
                }),
        }
    }

    /// `fleetctl lab exec-status <handle>`: the answer's JSON.
    async fn detached_status(run: &TargetRun, handle: &str) -> Result<Value, String> {
        let status = run
            .controller
            .fleetctl(&args(&["lab", "exec-status", handle]), None)
            .await?;
        check!(
            status.success,
            "lab exec-status failed: {} {}",
            status.json,
            status.stderr
        );
        Ok(status.json)
    }

    /// A command longer than the exec bound runs detached and ends with its
    /// exit code and output, a controller restart while it runs loses no
    /// handle, and a release while another command runs ends it with the
    /// guest and answers `lease_ended` (#394).
    #[allow(clippy::too_many_lines)]
    pub async fn detached_exec(run: &TargetRun, lab: &Lab) -> Result<Outcome, String> {
        let seconds = detach_seconds()?;
        // The TTL must outlast the command, whose bound is the TTL left.
        let (account, version) = lab.prepare(run, seconds + 1_200).await?;
        let lease = ready_lease(run, &account, &version).await?;
        let id = lease["id"].as_str().unwrap_or_default().to_owned();
        let started = Instant::now();
        let script = format!("echo begin; sleep {seconds}; echo finished-ok");
        let detach = async |script: &str, key: &str| {
            run.controller
                .fleetctl(
                    &args(&[
                        "lab",
                        "exec",
                        &id,
                        "--detach",
                        "--idempotency-key",
                        key,
                        "--",
                        "sh",
                        "-c",
                        script,
                    ]),
                    None,
                )
                .await
        };
        let long = detach(&script, "acceptance-long").await?;
        check!(
            long.success && long.json["handle"].is_string(),
            "lab exec --detach did not return a handle: {} {}",
            long.json,
            long.stderr
        );
        let handle = long.json["handle"].as_str().unwrap_or_default().to_owned();
        check!(
            started.elapsed() < Duration::from_secs(120),
            "lab exec --detach held the call open for {:?}",
            started.elapsed()
        );
        check!(
            long.json["timeoutSeconds"].as_u64().unwrap_or(0) >= seconds,
            "the bound {} is below the command's {seconds} seconds",
            long.json["timeoutSeconds"]
        );
        let again = detach(&script, "acceptance-long").await?;
        check!(
            again.json["handle"] == handle.as_str(),
            "a retry with the same key did not return the same handle: {}",
            again.json
        );
        // It is running (the start operation is queued for a moment).
        let deadline = Instant::now() + Duration::from_secs(120);
        let running = loop {
            let status = detached_status(run, &handle).await?;
            if status["state"] == "running" {
                break status;
            }
            check!(
                status["state"] == "starting" && Instant::now() < deadline,
                "the detached command is {}: {status}",
                status["state"]
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        };
        check!(
            running["terminal"] == false && running["stdout"] == "begin\n",
            "a running command's status is wrong: {running}"
        );
        run.log(&format!("detached command {handle} is running"));

        // A second, short command with a known code, polled without --wait.
        let quick = detach(
            "echo quick-out; echo quick-err >&2; exit 7",
            "acceptance-quick",
        )
        .await?;
        let quick = quick.json["handle"].as_str().unwrap_or_default().to_owned();
        let deadline = Instant::now() + Duration::from_secs(120);
        let exited = loop {
            let status = detached_status(run, &quick).await?;
            if status["state"] == "exited" {
                break status;
            }
            check!(
                matches!(status["state"].as_str(), Some("starting" | "running"))
                    && Instant::now() < deadline,
                "the quick command is {}: {status}",
                status["state"]
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        };
        check!(
            exited["exitCode"] == 7
                && exited["terminal"] == true
                && exited["stdout"] == "quick-out\n"
                && exited["stderr"] == "quick-err\n",
            "the quick command's exit code or output is wrong: {exited}"
        );

        // A command that would outlive the lease is capped by it, and one
        // that runs when the lease is released ends with the guest.
        let forever = detach("sleep 100000", "acceptance-forever").await?;
        let forever_handle = forever.json["handle"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        check!(
            forever.json["timeoutSeconds"].as_u64().unwrap_or(u64::MAX) <= seconds + 1_200,
            "the detached bound exceeds the lease's TTL: {}",
            forever.json
        );

        // The controller restarts while both commands run: no handle is lost.
        run.controller
            .with_store(async |_| {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            })
            .await?;
        run.log("controller restarted while detached commands ran");
        let after = detached_status(run, &handle).await?;
        check!(
            matches!(after["state"].as_str(), Some("running")),
            "the handle did not survive the controller restart: {after}"
        );

        // Wait for the long command: exit 0 and the last of its output.
        let wait_bound = (seconds + 600).to_string();
        let waited = run
            .controller
            .fleetctl(
                &args(&[
                    "lab",
                    "exec-status",
                    &handle,
                    "--wait",
                    "--timeout",
                    &wait_bound,
                ]),
                None,
            )
            .await?;
        check!(
            waited.success
                && waited.json["state"] == "exited"
                && waited.json["exitCode"] == 0
                && waited.json["stdout"]
                    .as_str()
                    .is_some_and(|out| out.contains("begin") && out.contains("finished-ok")),
            "the long command did not end 0 with its output: {} {}",
            waited.json,
            waited.stderr
        );
        check!(
            started.elapsed() >= Duration::from_secs(seconds),
            "the command finished in {:?}, before its {seconds} seconds",
            started.elapsed()
        );
        run.log(&format!(
            "a {seconds}-second detached command ended with its exit code after {:?}",
            started.elapsed()
        ));

        // Release while `sleep 100000` runs: a terminal answer, no SSH error.
        let still = detached_status(run, &forever_handle).await?;
        check!(
            still["state"] == "running",
            "the second command should still run: {still}"
        );
        let bound = LEASE_BOUND.as_secs().to_string();
        let destroyed = run
            .controller
            .fleetctl(
                &args(&["lab", "destroy", &id, "--wait", "--timeout", &bound]),
                None,
            )
            .await?;
        check!(
            destroyed.success && destroyed.json["state"] == "released",
            "lab destroy --wait ended {}: {}",
            destroyed.json["state"],
            destroyed.stderr
        );
        guest_gone(run, &lease).await?;
        for handle in [&forever_handle, &handle] {
            let ended = detached_status(run, handle).await?;
            check!(
                ended["state"] == "lease_ended"
                    && ended["terminal"] == true
                    && ended["leaseState"] == "released",
                "status after release is not a terminal lease_ended: {ended}"
            );
        }
        Ok(Outcome::Pass)
    }

    /// A ready lease expires while the controller is down; the restarted
    /// controller's sweeper releases it and destroys its guest.
    pub async fn ttl_expiry_restart(run: &TargetRun, lab: &Lab) -> Result<Outcome, String> {
        let (account, version) = lab.prepare(run, SHORT_TTL_SECONDS).await?;
        let lease = ready_lease(run, &account, &version).await?;
        let id = lease["id"].as_str().unwrap_or_default().to_owned();
        let expires = lease["expiresAt"]
            .as_i64()
            .ok_or("the ready lease has no expiry")?;
        run.controller
            .with_store(async move |_| {
                // The controller is stopped across the expiry.
                let wait = expires + 5_000 - fleet_core::SystemClock::now_unix_millis();
                tokio::time::sleep(Duration::from_millis(u64::try_from(wait).unwrap_or(0))).await;
                Ok(())
            })
            .await?;
        run.log("controller restarted after the lease expired");
        let started = Instant::now();
        let state = loop {
            let (status, body) = run
                .controller
                .get(&format!("/api/v1/lab/leases/{id}"))
                .await?;
            check!(status == 200, "reading the lease answered {status}");
            let state = body["data"]["state"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if matches!(state.as_str(), "released" | "cleanup_failed")
                || started.elapsed() > SWEEP_BOUND
            {
                break state;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        };
        check!(
            state == "released",
            "the expired lease ended {state} after the restart"
        );
        guest_gone(run, &lease).await?;
        Ok(Outcome::Pass)
    }
}

#[tokio::test]
async fn live_lease_exec_destroy() {
    live::scenario(live::SCENARIOS[0], live::lease_exec_destroy).await;
}

#[tokio::test]
async fn live_ttl_expiry_restart() {
    live::scenario(live::SCENARIOS[1], live::ttl_expiry_restart).await;
}

#[tokio::test]
async fn live_put_collect_roundtrip() {
    live::scenario(live::SCENARIOS[2], live::put_collect_roundtrip).await;
}

#[tokio::test]
async fn live_detached_exec() {
    live::scenario(live::SCENARIOS[3], live::detached_exec).await;
}
