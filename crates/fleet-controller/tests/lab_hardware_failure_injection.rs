//! FM-1130 (#576): failure injection and double-lease tests for Lab hardware,
//! the release gate `docs/architecture/lab.md` requires: **no device is
//! reserved twice, and no released lease has a silently assigned device.**
//!
//! The controller is killed (the executor and worker are dropped at the
//! crash point, and a fresh one starts over the same SQLite file and the same
//! fake Proxmox, as the saga's restart tests do) at the reserve, before and
//! after the verify, before and after the write, after the read-back, at
//! ready, at TTL expiry and at the detach. Each run then converges (the
//! worker maintenance, the reconciler's startup pass, the sweeper and the
//! worker, the clock moving on) and must end in a valid owned attachment or
//! in nothing. Where the documented limits of the hardware saga (#587) make
//! the safe answer a refusal to guess, the test asserts that exact fail-closed
//! state (the lease `cleanup_failed`, the row `attach_unknown` or
//! `detach_failed`, the device `quarantined`, the entry still on the guest) and
//! that the operator's override release (or removing the entry) clears it.
//!
//! Every scenario ends in [`Rig::check`], the one invariant checker
//! (`support/hardware_rig.rs`): reservation rows against the fake guests'
//! configs against lease states. It runs at the instant of the kill, after the
//! restart, and after convergence.
//!
//! Two real bugs this suite found in production code are pinned, not fixed
//! (the issue's paths do not own the fix): each has an `#[ignore = "bug: ..."]`
//! test that states the expected behaviour and fails today, and a passing test
//! beside it that asserts the exact behaviour today, so it cannot get worse
//! unnoticed. Run the ignored ones with `-- --ignored`.
//!
//! **Simulated.** The shared fake Proxmox (`support/fake_pve.rs`) behind a
//! USB-aware layer (`support/usb_pve.rs`, which also keeps a passive monitor
//! of any attach that lands on a device already assigned and of any guest
//! destroyed while it holds one), a controller over one SQLite file with the
//! real reservation store, inventory, provider calls, saga, reconciler,
//! hotplug and override use cases. Every device id, VMID and address is
//! invented; there is no real serial. Not measured: real PVE and real
//! hardware (FM-1133), what PVE does with a pending detach once the guest
//! stops, and deleting a pending-only leftover from a running guest.

#[allow(dead_code)]
#[path = "support/fake_pve.rs"]
mod fake_pve;
#[path = "support/hardware_rig.rs"]
mod hardware_rig;
#[path = "support/usb_pve.rs"]
mod usb_pve;

use fake_pve::{Fault, Step};
use fleet_core::{DeviceStatus, HardwareReservationState as State, LeaseState};
use hardware_rig::{HOUR_MS, Level, Point, READER_A, READER_B, Rig, Run, When, World, now, stored};
use usb_pve::{UsbFault, UsbStep};

/// What the scenario does to the controller on its way to the kill.
type Arm = fn(&World);

/// Requests a lease, arms the kill, runs its provision until the controller
/// dies there, checks the invariants at the instant of the kill, restarts the
/// controller over the same database and host, and checks them again.
async fn killed_provision(world: &World, arm: Arm) -> (Rig, String) {
    let rig = Rig::start(world).await;
    rig.refresh_inventory().await;
    let lease = rig.request_lease().await;
    arm(world);
    assert_eq!(
        rig.drain(world).await,
        Run::Crashed,
        "the provision must reach the kill point"
    );
    rig.assert_invariants(world, Level::Safety, "at the kill")
        .await;
    rig.kill().await;
    let rig = Rig::start(world).await;
    rig.assert_invariants(world, Level::Safety, "after the restart")
        .await;
    (rig, lease)
}

/// A ready lease, released, whose cleanup is killed at `arm`; the restarted
/// controller is returned.
async fn killed_cleanup(world: &World, arm: Arm) -> (Rig, String, u32) {
    let rig = Rig::start(world).await;
    let (lease, vmid) = rig.ready_lease(world).await;
    arm(world);
    rig.release(&lease).await;
    assert_eq!(
        rig.drain(world).await,
        Run::Crashed,
        "the cleanup must reach the kill point"
    );
    rig.assert_invariants(world, Level::Safety, "at the kill")
        .await;
    rig.kill().await;
    let rig = Rig::start(world).await;
    rig.assert_invariants(world, Level::Safety, "after the restart")
        .await;
    (rig, lease, vmid)
}

// ---------------------------------------------------------------------
// Killed during the provision: reserve, verify, write, read-back, ready.
// ---------------------------------------------------------------------

#[tokio::test]
async fn killed_at_the_reserve_commit_recovers_to_nothing() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.chaos.crash_at(Point::Reserve, When::After);
    })
    .await;
    // The reservation committed; nothing else happened yet.
    assert_eq!(rig.states().await, vec!["held"]);
    assert!(world.pve.lab_guests().is_empty());
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "reserve").await;
    assert!(world.usb.writes().is_empty(), "nothing was ever attached");
}

#[tokio::test]
async fn killed_before_the_vmid_after_the_reserve_recovers_to_nothing() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.usb.inject(UsbStep::NextId, UsbFault::CrashBefore, 1);
    })
    .await;
    assert_eq!(rig.states().await, vec!["held"]);
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "reserve, before the clone")
        .await;
}

#[tokio::test]
async fn killed_during_the_verify_recovers_to_nothing() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world
            .usb
            .inject(UsbStep::CheckNode, UsbFault::CrashBefore, 1);
    })
    .await;
    assert_eq!(rig.states().await, vec!["held"]);
    assert!(world.usb.writes().is_empty());
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "during the verify")
        .await;
}

#[tokio::test]
async fn killed_after_the_verify_before_the_attach_is_recorded_recovers_to_nothing() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.chaos.crash_at(
            Point::Transition(State::Held, State::Attaching),
            When::Before,
        );
    })
    .await;
    // The verify passed; the row is still `held`, no slot, nothing written.
    assert_eq!(rig.states().await, vec!["held"]);
    assert!(world.usb.writes().is_empty());
    assert!(
        world
            .pve
            .lab_guests()
            .contains_key(&hardware_rig::FIRST_VMID)
    );
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "after the verify").await;
    assert!(world.usb.writes().is_empty(), "nothing was ever attached");
}

#[tokio::test]
async fn killed_after_the_attach_is_recorded_before_the_write_recovers_to_nothing() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.chaos.crash_at(
            Point::Transition(State::Held, State::Attaching),
            When::After,
        );
    })
    .await;
    assert_eq!(rig.states().await, vec!["attaching"]);
    assert!(world.usb.writes().is_empty());
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "attaching, before the write")
        .await;
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn killed_before_the_write_lands_recovers_to_nothing() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.usb.inject(UsbStep::Attach, UsbFault::CrashBefore, 1);
    })
    .await;
    assert_eq!(rig.states().await, vec!["attaching"]);
    assert!(world.usb.writes().is_empty());
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "before the write").await;
}

#[tokio::test]
async fn killed_after_the_write_lands_fails_closed_and_the_override_clears_it() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.usb.inject(UsbStep::Attach, UsbFault::CrashAfter, 1);
    })
    .await;
    // The entry is on the clone and the row only recorded the attempt.
    assert_eq!(rig.states().await, vec!["attaching"]);
    assert_eq!(
        world.usb.stored(hardware_rig::FIRST_VMID),
        stored(&[(0, READER_A)])
    );
    rig.converge(&world, now() + HOUR_MS).await;

    // Fail closed: nothing proves Fleet wrote the entry, so it is not
    // adopted, not deleted and not released on a guess.
    assert_eq!(rig.lease(&lease).await.state, LeaseState::CleanupFailed);
    let row = rig.live_row_of(READER_A).await.expect("the row is live");
    assert_eq!((row.state.as_str(), row.slot), ("attach_unknown", None));
    assert_eq!(rig.device_status(READER_A).await, DeviceStatus::Quarantined);
    assert_eq!(
        world.usb.stored(hardware_rig::FIRST_VMID),
        stored(&[(0, READER_A)])
    );
    assert_eq!(world.usb.writes().len(), 1, "only the attach was written");
    assert!(
        world
            .pve
            .lab_guests()
            .contains_key(&hardware_rig::FIRST_VMID)
    );
    rig.assert_invariants(&world, Level::Quiescent, "fail closed")
        .await;

    // The operator frees the record. The device is still on the guest, so it
    // reads `externally_attached` until the guest is dealt with.
    rig.override_release(&row.id)
        .await
        .expect("the override releases");
    rig.refresh_inventory().await;
    assert_eq!(
        rig.device_status(READER_A).await,
        DeviceStatus::ExternallyAttached
    );
    rig.assert_invariants(&world, Level::Quiescent, "after the override")
        .await;

    // The operator removes the entry by hand; the lease's cleanup then runs.
    world.usb.clear_slot(hardware_rig::FIRST_VMID, 0);
    rig.retry_cleanup(&lease).await;
    rig.converge(&world, now() + 2 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "after the override and cleanup-retry")
        .await;
    assert!(world.usb.destroyed_holding().is_empty());
}

#[tokio::test]
async fn killed_after_the_read_back_before_it_is_recorded_fails_closed_and_the_override_clears_it()
{
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.chaos.crash_at(
            Point::Transition(State::Attaching, State::Attached),
            When::Before,
        );
    })
    .await;
    // The write landed and was read back, but the row never learned it.
    assert_eq!(rig.states().await, vec!["attaching"]);
    assert_eq!(
        world.usb.stored(hardware_rig::FIRST_VMID),
        stored(&[(0, READER_A)])
    );
    rig.converge(&world, now() + HOUR_MS).await;

    assert_eq!(rig.lease(&lease).await.state, LeaseState::CleanupFailed);
    let row = rig.live_row_of(READER_A).await.expect("the row is live");
    assert_eq!((row.state.as_str(), row.slot), ("attach_unknown", None));
    assert_eq!(rig.device_status(READER_A).await, DeviceStatus::Quarantined);
    assert_eq!(
        world.usb.stored(hardware_rig::FIRST_VMID),
        stored(&[(0, READER_A)])
    );
    rig.assert_invariants(&world, Level::Quiescent, "fail closed")
        .await;

    // The override is the way out. The device is still on the guest, so it
    // is visible as externally attached until the guest is dealt with, and
    // the lease's cleanup, which now finds no live reservation, detaches
    // nothing and destroys the guest (the documented runbook behaviour:
    // destroying the guest takes the device with it).
    rig.override_release(&row.id)
        .await
        .expect("the override releases");
    rig.refresh_inventory().await;
    assert_eq!(
        rig.device_status(READER_A).await,
        DeviceStatus::ExternallyAttached
    );
    world.allow_destroy_holding(hardware_rig::FIRST_VMID);
    rig.retry_cleanup(&lease).await;
    rig.converge(&world, now() + 2 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "after the override and cleanup-retry")
        .await;
    assert_eq!(
        world.usb.destroyed_holding(),
        vec!["9000: usb0=mapping=fm-test-reader-a".to_owned()],
        "the guest went with its device and no detach was written"
    );
    assert_eq!(world.usb.writes().len(), 1);
}

#[tokio::test]
async fn killed_after_the_attached_record_before_the_start_is_detached_and_destroyed() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.chaos.crash_at(
            Point::Transition(State::Attaching, State::Attached),
            When::After,
        );
    })
    .await;
    assert_eq!(rig.states().await, vec!["attached"]);
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "attached, before the start")
        .await;
    assert_eq!(world.usb.writes().len(), 2, "one attach, one detach");
}

#[tokio::test]
async fn killed_at_ready_leaves_a_valid_owned_attachment_that_releases_cleanly() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.chaos.crash_at(Point::Ready, When::After);
    })
    .await;
    // The readiness transaction committed before the kill.
    assert_eq!(rig.lease(&lease).await.state, LeaseState::Ready);
    rig.converge(&world, now() + HOUR_MS).await;
    // A valid owned attachment: ready, running, the device attached and read
    // back, and the checker agrees.
    assert_eq!(rig.lease(&lease).await.state, LeaseState::Ready);
    assert_eq!(rig.states().await, vec!["attached"]);
    assert_eq!(
        world.usb.stored(hardware_rig::FIRST_VMID),
        stored(&[(0, READER_A)])
    );
    rig.assert_invariants(&world, Level::Quiescent, "ready after the kill")
        .await;
    // And it still releases to nothing.
    rig.release(&lease).await;
    rig.converge(&world, now() + 2 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "released after the kill at ready")
        .await;
}

#[tokio::test]
async fn killed_before_the_ready_commit_is_compensated_to_nothing() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.chaos.crash_at(Point::Ready, When::Before);
    })
    .await;
    assert_eq!(rig.states().await, vec!["attached"]);
    assert_ne!(rig.lease(&lease).await.state, LeaseState::Ready);
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "before the ready commit")
        .await;
}

#[tokio::test]
async fn killed_while_the_guest_starts_is_detached_and_destroyed() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.faults.inject(Step::Start, Fault::CrashAfter, 1);
    })
    .await;
    assert_eq!(rig.states().await, vec!["attached"]);
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "after the start").await;
}

// ---------------------------------------------------------------------
// Killed at the TTL expiry and at the detach.
// ---------------------------------------------------------------------

#[tokio::test]
async fn killed_at_the_ttl_expiry_resumes_the_cleanup_and_detaches_before_destroy() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, _) = rig.ready_lease(&world).await;
    // The lease is two days old; the sweeper's expiry step commits and the
    // controller dies right after it, before any cleanup is queued.
    let later = now() + 2 * 24 * HOUR_MS;
    world.chaos.crash_at(Point::Expired, When::After);
    assert_eq!(rig.sweep(&world, later).await, Run::Crashed);
    rig.assert_invariants(&world, Level::Safety, "at the kill")
        .await;
    assert_eq!(rig.lease(&lease).await.state, LeaseState::Releasing);
    rig.kill().await;
    let rig = Rig::start(&world).await;
    rig.assert_invariants(&world, Level::Safety, "after the restart")
        .await;
    assert_eq!(rig.states().await, vec!["attached"]);
    rig.converge(&world, later).await;
    rig.assert_nothing(&world, &lease, "after the expiry").await;
    let log = world.usb.log();
    let detach = log
        .iter()
        .position(|line| line.starts_with("Put ") && line.contains("delete"))
        .expect("the detach was written");
    let destroy = log
        .iter()
        .position(|line| line.starts_with("Delete "))
        .expect("the guest was destroyed");
    assert!(detach < destroy, "detach before destroy: {log:#?}");
}

#[tokio::test]
async fn killed_at_each_step_of_the_detach_recovers_to_nothing() {
    let cases: [(&str, Arm); 6] = [
        ("before the detach intent moves the row", |world| {
            world.chaos.crash_at(
                Point::Transition(State::Attached, State::Detaching),
                When::Before,
            );
        }),
        ("after the row is detaching", |world| {
            world.chaos.crash_at(
                Point::Transition(State::Attached, State::Detaching),
                When::After,
            );
        }),
        ("before the delete lands", |world| {
            world.usb.inject(UsbStep::Detach, UsbFault::CrashBefore, 1);
        }),
        ("after the delete lands", |world| {
            world.usb.inject(UsbStep::Detach, UsbFault::CrashAfter, 1);
        }),
        ("before the release commits", |world| {
            world.chaos.crash_at(Point::Release, When::Before);
        }),
        ("after the release commits", |world| {
            world.chaos.crash_at(Point::Release, When::After);
        }),
    ];
    for (label, arm) in cases {
        let world = World::new(&[READER_A]).await;
        let (rig, lease, _) = killed_cleanup(&world, arm).await;
        rig.converge(&world, now() + HOUR_MS).await;
        rig.assert_nothing(&world, &lease, label).await;
        assert_eq!(
            world
                .usb
                .writes()
                .iter()
                .filter(|write| write.starts_with("detach"))
                .count(),
            1,
            "{label}: exactly one delete"
        );
        rig.kill().await;
    }
}

#[tokio::test]
async fn killed_between_the_release_and_the_destroy_destroys_without_detaching_again() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease, _) = killed_cleanup(&world, |world| {
        world.faults.inject(Step::Delete, Fault::CrashBefore, 1);
    })
    .await;
    assert_eq!(rig.states().await, vec!["released"]);
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "between the release and the destroy")
        .await;
    assert_eq!(world.usb.writes().len(), 2);
}

// ---------------------------------------------------------------------
// Two competing leases for one device serialize.
// ---------------------------------------------------------------------

/// The states of the leases, in order.
async fn lease_states(rig: &Rig, leases: &[String]) -> Vec<LeaseState> {
    let mut states = Vec::new();
    for lease in leases {
        states.push(rig.lease(lease).await.state);
    }
    states
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_competing_leases_serialize_and_the_loser_can_once_the_winner_releases() {
    // The race is real (two workers, one SQLite file), so run it several
    // times: which lease wins varies, the outcome must not.
    for round in 0..6 {
        let world = World::new(&[READER_A]).await;
        let rig = Rig::start(&world).await;
        rig.refresh_inventory().await;
        let first = rig.request_lease().await;
        let second = rig.request_lease().await;
        rig.drain_concurrently(2).await;
        rig.drain(&world).await.done();

        let leases = [first.clone(), second.clone()];
        let states = lease_states(&rig, &leases).await;
        let winner = states
            .iter()
            .position(|state| *state == LeaseState::Ready)
            .unwrap_or_else(|| panic!("round {round}: one lease must win: {states:?}"));
        let loser = 1 - winner;
        assert_eq!(
            states
                .iter()
                .filter(|state| **state == LeaseState::Ready)
                .count(),
            1,
            "round {round}: exactly one lease attaches: {states:?}"
        );
        assert_eq!(
            rig.failure_reason(&leases[loser]).await,
            "hardware_busy",
            "round {round}: the other gets hardware_busy"
        );
        assert_eq!(rig.rows().await.len(), 1, "round {round}: one row");
        assert_eq!(rig.states().await, vec!["attached"]);
        assert_eq!(world.usb.writes().len(), 1, "round {round}: one attach");
        assert_eq!(world.pve.lab_guests().len(), 1, "the loser cloned nothing");
        rig.assert_invariants(&world, Level::Safety, "the race")
            .await;

        // The winner releases; now the loser's request can attach.
        rig.release(&leases[winner]).await;
        rig.converge(&world, now() + HOUR_MS).await;
        rig.assert_nothing(&world, &leases[winner], "the winner released")
            .await;
        let retry = rig.request_lease().await;
        rig.drain(&world).await.done();
        assert_eq!(
            rig.lease(&retry).await.state,
            LeaseState::Ready,
            "round {round}: the second request attaches after the first released"
        );
        rig.assert_invariants(&world, Level::Quiescent, "the retry holds it")
            .await;
        rig.release(&retry).await;
        rig.converge(&world, now() + 2 * HOUR_MS).await;
        rig.assert_nothing(&world, &retry, "the retry released")
            .await;
        rig.kill().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_leases_racing_for_one_device_attach_exactly_one() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    rig.refresh_inventory().await;
    let mut leases = Vec::new();
    for _ in 0..6 {
        leases.push(rig.request_lease().await);
    }
    rig.drain_concurrently(4).await;
    rig.drain(&world).await.done();
    let states = lease_states(&rig, &leases).await;
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == LeaseState::Ready)
            .count(),
        1,
        "{states:?}"
    );
    for (lease, state) in leases.iter().zip(&states) {
        if *state != LeaseState::Ready {
            assert_eq!(rig.failure_reason(lease).await, "hardware_busy");
        }
    }
    assert_eq!(world.usb.writes().len(), 1);
    assert!(world.usb.double_assignments().is_empty());
    rig.assert_invariants(&world, Level::Quiescent, "six racing leases")
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leases_wanting_overlapping_device_sets_serialize_and_give_back_what_they_took() {
    // Every template wants B, and two also want A (taken first, in mapping
    // order): the leases that win A and then lose B must give A back, and
    // exactly one lease ends up with B. (Every set shares B so at most one
    // provision gets as far as the next VMID and the clone. With the fake
    // host's zero latency, two provisions that both get that far can finish
    // one inside the other's window and then collide on a VMID, which says
    // nothing about hardware; see the late-cleanup scenarios below.)
    for round in 0..5 {
        let world = World::with_templates(&[
            &[READER_B],
            &[READER_A, READER_B],
            &[READER_B],
            &[READER_A, READER_B],
        ])
        .await;
        let rig = Rig::start(&world).await;
        rig.refresh_inventory().await;
        let mut leases = Vec::new();
        for index in 0..4 {
            leases.push(rig.request_lease_of(&world.version(index)).await);
        }
        rig.drain_concurrently(4).await;
        rig.drain(&world).await.done();

        let states = lease_states(&rig, &leases).await;
        let ready: Vec<usize> = states
            .iter()
            .enumerate()
            .filter(|(_, state)| **state == LeaseState::Ready)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            ready.len(),
            1,
            "round {round}: exactly one lease holds B: {states:?}\n{}",
            rig.dump(&world).await
        );
        for (index, lease) in leases.iter().enumerate() {
            if !ready.contains(&index) {
                assert_eq!(rig.lease(lease).await.state, LeaseState::Failed);
                let reason = rig.failure_reason(lease).await;
                assert_eq!(
                    reason,
                    "hardware_busy",
                    "round {round}: {}",
                    rig.failure_detail(lease).await
                );
            }
        }
        // Whatever A the losers took went back: only the winner's rows live.
        let live = rig.live_rows().await;
        assert_eq!(
            live.len(),
            world.templates[&world.version(ready[0])].len(),
            "round {round}: {live:#?}"
        );
        assert!(live.iter().all(|row| row.owner_id == leases[ready[0]]));
        rig.assert_invariants(&world, Level::Quiescent, "overlapping sets")
            .await;
        rig.release(&leases[ready[0]]).await;
        rig.converge(&world, now() + 2 * HOUR_MS).await;
        for lease in &leases {
            rig.assert_nothing(&world, lease, "all released").await;
        }
        rig.kill().await;
    }
}

#[tokio::test]
async fn a_lease_asking_for_a_device_a_killed_lease_holds_is_refused_until_it_is_cleared() {
    let world = World::new(&[READER_A]).await;
    let (rig, first) = killed_provision(&world, |world| {
        world.usb.inject(UsbStep::Attach, UsbFault::CrashAfter, 1);
    })
    .await;
    rig.converge(&world, now() + HOUR_MS).await;
    assert_eq!(rig.lease(&first).await.state, LeaseState::CleanupFailed);
    let row = rig.live_row_of(READER_A).await.expect("the row is live");

    // The fail-closed device is not allocatable: a second lease is refused,
    // names why, and writes nothing.
    let second = rig.request_lease().await;
    rig.drain(&world).await.done();
    assert_eq!(rig.lease(&second).await.state, LeaseState::Failed);
    let reason = rig.failure_reason(&second).await;
    assert!(
        reason == "hardware_busy" || reason == "hardware_quarantined",
        "{reason}"
    );
    assert_eq!(world.usb.writes().len(), 1, "no second attach");
    rig.assert_invariants(&world, Level::Quiescent, "a second lease refused")
        .await;

    // The operator clears the stuck lease; only then can a third attach.
    rig.override_release(&row.id).await.expect("override");
    world.usb.clear_slot(hardware_rig::FIRST_VMID, 0);
    rig.retry_cleanup(&first).await;
    rig.converge(&world, now() + 2 * HOUR_MS).await;
    rig.assert_nothing(&world, &first, "cleared").await;
    let third = rig.request_lease().await;
    rig.drain(&world).await.done();
    assert_eq!(rig.lease(&third).await.state, LeaseState::Ready);
    assert_eq!(
        rig.states().await.last().map(String::as_str),
        Some("attached")
    );
    rig.assert_invariants(&world, Level::Quiescent, "the third lease holds it")
        .await;
}

#[tokio::test]
async fn a_device_an_operator_attached_by_hand_is_never_taken_by_a_lease() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    // The operator's own guest holds the device (the Decker case).
    world.usb.create_guest(8001, "operator-guest").await;
    world.usb.set_slot(8001, 0, "mapping=fm-test-reader-a");
    rig.refresh_inventory().await;
    assert_eq!(
        rig.device_status(READER_A).await,
        DeviceStatus::ExternallyAttached
    );
    let lease = rig.request_lease().await;
    rig.drain(&world).await.done();
    assert_eq!(
        rig.failure_reason(&lease).await,
        "hardware_externally_attached"
    );
    assert!(world.usb.writes().is_empty(), "Fleet wrote nothing");
    assert_eq!(
        world.usb.stored(8001),
        stored(&[(0, READER_A)]),
        "left alone"
    );
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_invariants(&world, Level::Quiescent, "an external attachment")
        .await;
    assert!(rig.live_rows().await.is_empty());
}

// ---------------------------------------------------------------------
// PVE errors and timeouts at each step, healed and converged.
// ---------------------------------------------------------------------

/// What a fault leaves a lease at once the host is healthy and the
/// controller has converged.
async fn heal_and_finish(world: &World, rig: &Rig, lease: &str, label: &str) {
    world.usb.clear();
    world.faults.clear();
    world.chaos.clear();
    rig.converge(world, now() + HOUR_MS).await;
    if rig.lease(lease).await.state == LeaseState::Ready {
        rig.assert_invariants(world, Level::Quiescent, label).await;
        rig.release(lease).await;
        rig.converge(world, now() + 2 * HOUR_MS).await;
    }
    rig.assert_nothing(world, lease, label).await;
}

#[tokio::test]
async fn a_pve_fault_at_any_step_of_the_provision_ends_in_a_ready_lease_or_nothing() {
    let cases: Vec<(&str, Arm)> = vec![
        ("attach refused (403)", |w| {
            w.usb.inject(UsbStep::Attach, UsbFault::Forbidden, 1);
        }),
        ("attach 500", |w| {
            w.usb.inject(UsbStep::Attach, UsbFault::ServerError, 1);
        }),
        ("attach answer lost (timeout)", |w| {
            w.usb.inject(UsbStep::Attach, UsbFault::Lost, 1);
        }),
        ("attach hotplug fails", |w| {
            w.usb.inject(UsbStep::Attach, UsbFault::HotplugFails, 1);
        }),
        ("attach digest conflict once", |w| {
            w.usb.inject(UsbStep::Attach, UsbFault::DigestMismatch, 1);
        }),
        ("attach digest conflict every time", |w| {
            w.usb.inject(UsbStep::Attach, UsbFault::DigestMismatch, 10);
        }),
        ("pending read fails", |w| {
            w.usb.inject(UsbStep::Pending, UsbFault::ServerError, 1);
        }),
        ("pending read fails twice (read-back)", |w| {
            w.usb.inject(UsbStep::Pending, UsbFault::ServerError, 2);
        }),
        ("check-node 500", |w| {
            w.usb.inject(UsbStep::CheckNode, UsbFault::ServerError, 1);
        }),
        ("check-node refused", |w| {
            w.usb.inject(UsbStep::CheckNode, UsbFault::Forbidden, 1);
        }),
        ("nextid 500", |w| {
            w.usb.inject(UsbStep::NextId, UsbFault::ServerError, 1);
        }),
        ("cluster resources 500", |w| {
            w.usb.inject(UsbStep::Resources, UsbFault::ServerError, 2);
        }),
        ("clone answer lost", |w| {
            w.faults.inject(Step::Clone, Fault::Timeout, 1);
        }),
        ("clone task fails", |w| {
            w.faults.inject(Step::Clone, Fault::TaskError, 1);
        }),
        ("clone refused", |w| {
            w.faults.inject(Step::Clone, Fault::Forbidden, 1);
        }),
        ("start task fails", |w| {
            w.faults.inject(Step::Start, Fault::TaskError, 1);
        }),
        ("start answer lost", |w| {
            w.faults.inject(Step::Start, Fault::Timeout, 1);
        }),
        ("start refused", |w| {
            w.faults.inject(Step::Start, Fault::Forbidden, 1);
        }),
    ];
    for (label, arm) in cases {
        let world = World::new(&[READER_A]).await;
        let rig = Rig::start(&world).await;
        rig.refresh_inventory().await;
        let lease = rig.request_lease().await;
        arm(&world);
        rig.drain(&world).await.done();
        rig.assert_invariants(&world, Level::Safety, label).await;
        heal_and_finish(&world, &rig, &lease, label).await;
        rig.kill().await;
    }
}

#[tokio::test]
async fn a_pve_fault_at_any_step_of_the_cleanup_ends_in_nothing() {
    let cases: Vec<(&str, Arm)> = vec![
        ("detach refused (403)", |w| {
            w.usb.inject(UsbStep::Detach, UsbFault::Forbidden, 1);
        }),
        ("detach 500", |w| {
            w.usb.inject(UsbStep::Detach, UsbFault::ServerError, 1);
        }),
        ("detach answer lost (timeout)", |w| {
            w.usb.inject(UsbStep::Detach, UsbFault::Lost, 1);
        }),
        ("detach digest conflict", |w| {
            w.usb.inject(UsbStep::Detach, UsbFault::DigestMismatch, 1);
        }),
        ("detach digest conflict every time", |w| {
            w.usb.inject(UsbStep::Detach, UsbFault::DigestMismatch, 10);
        }),
        ("pending read fails during the detach", |w| {
            w.usb.inject(UsbStep::Pending, UsbFault::ServerError, 2);
        }),
        ("cluster resources 500 during the cleanup", |w| {
            w.usb.inject(UsbStep::Resources, UsbFault::ServerError, 3);
        }),
        ("stop answer lost", |w| {
            w.faults.inject(Step::Stop, Fault::Timeout, 1);
        }),
        ("stop task fails", |w| {
            w.faults.inject(Step::Stop, Fault::TaskError, 1);
        }),
        ("destroy answer lost", |w| {
            w.faults.inject(Step::Delete, Fault::Timeout, 1);
        }),
        ("destroy task fails", |w| {
            w.faults.inject(Step::Delete, Fault::TaskError, 1);
        }),
        ("destroy refused", |w| {
            w.faults.inject(Step::Delete, Fault::Forbidden, 1);
        }),
    ];
    for (label, arm) in cases {
        let world = World::new(&[READER_A]).await;
        let rig = Rig::start(&world).await;
        let (lease, _) = rig.ready_lease(&world).await;
        arm(&world);
        rig.release(&lease).await;
        rig.drain(&world).await.done();
        rig.assert_invariants(&world, Level::Safety, label).await;
        heal_and_finish(&world, &rig, &lease, label).await;
        rig.kill().await;
    }
}

#[tokio::test]
async fn a_detach_refused_for_good_fails_closed_and_the_restored_role_clears_it() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, vmid) = rig.ready_lease(&world).await;
    // The token lost Mapping.Use: PVE refuses every delete.
    world.usb.inject(UsbStep::Detach, UsbFault::Forbidden, 500);
    rig.release(&lease).await;
    rig.converge(&world, now() + HOUR_MS).await;

    // Fail closed: the lease visibly owns the guest, the row is kept, the
    // device is quarantined, the entry is still on the guest, and the guest
    // was neither stopped nor destroyed. The reconciler's passes changed
    // nothing.
    assert_eq!(rig.lease(&lease).await.state, LeaseState::CleanupFailed);
    let row = rig.live_row_of(READER_A).await.expect("the row is live");
    assert_eq!(row.state, "detach_failed");
    assert_eq!(row.slot, Some(0));
    assert_eq!(rig.device_status(READER_A).await, DeviceStatus::Quarantined);
    assert_eq!(world.usb.stored(vmid), stored(&[(0, READER_A)]));
    assert!(world.pve.lab_guests().contains_key(&vmid));
    assert_eq!(world.usb.count(|line| line.starts_with("Delete ")), 0);
    assert_eq!(world.usb.writes().len(), 1, "only the attach landed");
    rig.assert_invariants(&world, Level::Quiescent, "a detach refused for good")
        .await;

    // The role is restored. The reconciler removes Fleet's own entry and
    // releases the row (the lease is over), and cleanup-retry then destroys.
    world.usb.clear();
    let report = rig.reconcile(&world, now() + 10 * HOUR_MS).await.done();
    assert_eq!(report.entries_removed, 1, "{report:?}");
    assert!(world.usb.stored(vmid).is_empty());
    assert!(rig.live_rows().await.is_empty());
    rig.retry_cleanup(&lease).await;
    rig.converge(&world, now() + 12 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "role restored").await;
}

#[tokio::test]
async fn a_detach_pending_for_good_fails_closed_and_a_restart_of_the_guest_clears_it() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, vmid) = rig.ready_lease(&world).await;
    // The guest's hotplug option lacks usb: PVE keeps the device until the
    // guest restarts, so a pending delete is not a detach.
    world.usb.set_hotplug_usb(vmid, false);
    rig.release(&lease).await;
    rig.converge(&world, now() + HOUR_MS).await;

    assert_eq!(rig.lease(&lease).await.state, LeaseState::CleanupFailed);
    let row = rig.live_row_of(READER_A).await.expect("the row is live");
    assert_eq!(row.state, "detaching");
    assert_eq!(
        rig.device_status(READER_A).await,
        DeviceStatus::Reserved,
        "a detach still in flight keeps the device reserved"
    );
    assert_eq!(
        world.usb.applied(vmid),
        stored(&[(0, READER_A)]),
        "the running guest still holds the device"
    );
    assert!(world.pve.lab_guests().contains_key(&vmid));
    rig.assert_invariants(&world, Level::Quiescent, "a pending detach")
        .await;

    world.usb.apply_pending(vmid);
    rig.retry_cleanup(&lease).await;
    rig.converge(&world, now() + 10 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "guest restarted").await;
}

// ---------------------------------------------------------------------
// The hardware components' audit sink is down.
// ---------------------------------------------------------------------

#[tokio::test]
async fn with_the_audit_sink_down_nothing_is_attached_and_the_lease_ends_in_nothing() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    rig.refresh_inventory().await;
    let lease = rig.request_lease().await;
    world.chaos.set_audit_down(true);
    rig.drain(&world).await.done();
    assert!(
        world.usb.writes().is_empty(),
        "no write without its audited intent: {:?}",
        world.usb.writes()
    );
    assert_ne!(rig.lease(&lease).await.state, LeaseState::Ready);
    rig.assert_invariants(&world, Level::Safety, "audit down at the attach")
        .await;
    world.chaos.set_audit_down(false);
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "audit back").await;
}

#[tokio::test]
async fn with_the_audit_sink_down_nothing_is_detached_until_it_returns() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, vmid) = rig.ready_lease(&world).await;
    world.chaos.set_audit_down(true);
    rig.release(&lease).await;
    rig.drain(&world).await.done();
    rig.settle(&world, now() + HOUR_MS).await;
    assert_eq!(world.usb.writes().len(), 1, "no delete without its intent");
    assert_eq!(world.usb.stored(vmid), stored(&[(0, READER_A)]));
    assert!(
        world.pve.lab_guests().contains_key(&vmid),
        "no destroy either"
    );
    assert_ne!(rig.lease(&lease).await.state, LeaseState::Released);
    rig.assert_invariants(&world, Level::Safety, "audit down at the detach")
        .await;
    // A reconciler pass with the sink still down repairs nothing either.
    rig.reconcile(&world, now() + 2 * HOUR_MS).await.done();
    assert_eq!(world.usb.writes().len(), 1);
    world.chaos.set_audit_down(false);
    world.chaos.clear();
    rig.retry_cleanup_if_failed(&lease).await;
    rig.converge(&world, now() + 12 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "audit back").await;
}

#[tokio::test]
async fn an_override_with_the_audit_sink_down_releases_nothing() {
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.usb.inject(UsbStep::Attach, UsbFault::CrashAfter, 1);
    })
    .await;
    rig.converge(&world, now() + HOUR_MS).await;
    let row = rig.live_row_of(READER_A).await.expect("the row is live");
    world.chaos.set_audit_down(true);
    assert!(rig.override_release(&row.id).await.is_err());
    assert_eq!(
        rig.live_row_of(READER_A).await.map(|row| row.state),
        Some("attach_unknown".to_owned()),
        "no audit, no release"
    );
    world.chaos.set_audit_down(false);
    rig.override_release(&row.id)
        .await
        .expect("the override releases");
    // The runbook's next step: refresh, so the device still on the guest
    // reads externally attached.
    rig.refresh_inventory().await;
    assert_eq!(
        rig.device_status(READER_A).await,
        DeviceStatus::ExternallyAttached
    );
    rig.assert_invariants(&world, Level::Quiescent, "override with audit back")
        .await;
    world.usb.clear_slot(hardware_rig::FIRST_VMID, 0);
    rig.retry_cleanup(&lease).await;
    rig.converge(&world, now() + 12 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "cleared").await;
}

#[tokio::test]
async fn a_device_still_on_a_guest_after_an_override_is_not_attached_to_a_new_lease() {
    let world = World::new(&[READER_A]).await;
    let (rig, first) = killed_provision(&world, |world| {
        world.usb.inject(UsbStep::Attach, UsbFault::CrashAfter, 1);
    })
    .await;
    rig.converge(&world, now() + HOUR_MS).await;
    let row = rig.live_row_of(READER_A).await.expect("the row is live");
    rig.override_release(&row.id).await.expect("override");
    // No refresh yet: the inventory still reads the device as free, so the
    // next lease reserves it. Its verify re-observes first and finds the
    // device on the other guest.
    let second = rig.request_lease().await;
    rig.drain(&world).await.done();
    assert!(matches!(
        rig.lease(&second).await.state,
        LeaseState::Failed | LeaseState::Released
    ));
    assert_eq!(
        rig.failure_reason(&second).await,
        "hardware_externally_attached"
    );
    assert_eq!(world.usb.writes().len(), 1, "no second attach");
    assert!(world.usb.double_assignments().is_empty());
    // The refusal released its reservation, which also returns the device's
    // status to available: it reads free while it is still on the first
    // lease's guest, until the next refresh (the runbook's step after an
    // override). The reconciler's scheduled refresh does it within minutes.
    assert_eq!(rig.device_status(READER_A).await, DeviceStatus::Available);
    rig.refresh_inventory().await;
    assert_eq!(
        rig.device_status(READER_A).await,
        DeviceStatus::ExternallyAttached
    );
    rig.assert_invariants(&world, Level::Quiescent, "a second lease refused")
        .await;
    assert_eq!(
        world.usb.stored(hardware_rig::FIRST_VMID),
        stored(&[(0, READER_A)]),
        "the first lease's guest keeps what it had"
    );
    // The operator finishes the clean-up.
    world.usb.clear_slot(hardware_rig::FIRST_VMID, 0);
    rig.retry_cleanup(&first).await;
    rig.converge(&world, now() + 12 * HOUR_MS).await;
    rig.assert_nothing(&world, &first, "cleared").await;
}

// ---------------------------------------------------------------------
// Concurrent hotplug, cleanup and reconciler on one device.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hotplug_cleanup_and_the_reconciler_racing_on_one_device_converge_to_nothing() {
    for round in 0..8u64 {
        let world = std::sync::Arc::new(World::new(&[READER_A]).await);
        let rig = std::sync::Arc::new(Rig::start(&world).await);
        let (lease, _) = rig.ready_lease(&world).await;
        let delay = std::time::Duration::from_millis(round * 4);

        let hotplug = {
            let rig = rig.clone();
            let lease = lease.clone();
            tokio::spawn(async move {
                for step in 0..4 {
                    let _ = if step % 2 == 0 {
                        rig.hotplug_detach(&lease, READER_A, step == 2).await
                    } else {
                        rig.hotplug_attach(&lease, READER_A).await
                    };
                    tokio::task::yield_now().await;
                }
            })
        };
        let cleanup = {
            let rig = rig.clone();
            let world = world.clone();
            let lease = lease.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                rig.release(&lease).await;
                rig.drain(&world).await.done();
            })
        };
        let reconcile = {
            let rig = rig.clone();
            let world = world.clone();
            tokio::spawn(async move {
                for pass in 0..3 {
                    tokio::time::sleep(delay / 2).await;
                    rig.reconcile(&world, now() + pass * 70 * 60_000)
                        .await
                        .done();
                }
            })
        };
        hotplug.await.unwrap();
        cleanup.await.unwrap();
        reconcile.await.unwrap();

        assert!(
            world.usb.double_assignments().is_empty(),
            "round {round}: {:?}",
            world.usb.double_assignments()
        );
        // No tolerated shape: a released lease holds no live row, whatever
        // the hotplug attach did around its cleanup (#591).
        if rig.lease(&lease).await.state == LeaseState::Released {
            assert!(
                rig.live_rows().await.is_empty(),
                "round {round}: a released lease holds a row: {}",
                rig.dump(&world).await
            );
        }
        rig.assert_invariants(&world, Level::Safety, "after the race")
            .await;
        rig.converge(&world, now() + HOUR_MS).await;
        rig.assert_nothing(&world, &lease, &format!("race round {round}"))
            .await;
        assert!(world.usb.destroyed_holding().is_empty(), "round {round}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cleanup_retry_racing_two_reconciler_passes_releases_the_device_once() {
    let world = std::sync::Arc::new(World::new(&[READER_A]).await);
    let rig = std::sync::Arc::new(Rig::start(&world).await);
    let (lease, vmid) = rig.ready_lease(&world).await;
    world.usb.inject(UsbStep::Detach, UsbFault::Forbidden, 500);
    rig.release(&lease).await;
    rig.converge(&world, now() + HOUR_MS).await;
    assert_eq!(rig.lease(&lease).await.state, LeaseState::CleanupFailed);
    // The role is back; the retry and two reconciler passes all want the
    // same row at once.
    world.usb.clear();
    rig.retry_cleanup(&lease).await;
    let later = now() + 20 * HOUR_MS;
    let passes: Vec<_> = (0..2)
        .map(|_| {
            let rig = rig.clone();
            let world = world.clone();
            tokio::spawn(async move { rig.reconcile(&world, later).await.done() })
        })
        .collect();
    let drain = {
        let rig = rig.clone();
        let world = world.clone();
        tokio::spawn(async move {
            rig.settle(&world, later).await;
        })
    };
    for pass in passes {
        pass.await.unwrap();
    }
    drain.await.unwrap();
    assert!(world.usb.stored(vmid).is_empty());
    rig.assert_invariants(&world, Level::Safety, "after the race")
        .await;
    rig.converge(&world, later).await;
    rig.assert_nothing(&world, &lease, "racing repairs").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_hotplug_requests_on_one_device_never_assign_it_twice() {
    let world = std::sync::Arc::new(World::new(&[READER_A]).await);
    let rig = std::sync::Arc::new(Rig::start(&world).await);
    let (lease, _) = rig.ready_lease(&world).await;
    let mut tasks = Vec::new();
    for index in 0..8 {
        let rig = rig.clone();
        let lease = lease.clone();
        tasks.push(tokio::spawn(async move {
            if index % 2 == 0 {
                let _ = rig.hotplug_detach(&lease, READER_A, false).await;
            } else {
                let _ = rig.hotplug_attach(&lease, READER_A).await;
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert!(world.usb.double_assignments().is_empty());
    rig.assert_invariants(&world, Level::Safety, "after the hotplug storm")
        .await;
    rig.release(&lease).await;
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "after the hotplug storm")
        .await;
}

// ---------------------------------------------------------------------
// The reconciler and a mid-run hotplug are killed too.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_reconciler_killed_mid_repair_is_finished_by_the_next_one() {
    for (label, arm) in [
        (
            "after the delete lands",
            (|world: &World| {
                world.usb.inject(UsbStep::Detach, UsbFault::CrashAfter, 1);
            }) as Arm,
        ),
        ("before the release commits", |world| {
            world.chaos.crash_at(Point::Release, When::Before);
        }),
        ("after the release commits", |world| {
            world.chaos.crash_at(Point::Release, When::After);
        }),
    ] {
        let world = World::new(&[READER_A]).await;
        let rig = Rig::start(&world).await;
        let (lease, vmid) = rig.ready_lease(&world).await;
        world.usb.inject(UsbStep::Detach, UsbFault::Forbidden, 500);
        rig.release(&lease).await;
        rig.converge(&world, now() + HOUR_MS).await;
        assert_eq!(rig.lease(&lease).await.state, LeaseState::CleanupFailed);
        world.usb.clear();

        // The reconciler picks up the over lease's row and is killed.
        arm(&world);
        assert_eq!(
            rig.reconcile(&world, now() + 10 * HOUR_MS).await,
            Run::Crashed,
            "{label}"
        );
        rig.assert_invariants(&world, Level::Safety, label).await;
        rig.kill().await;
        let rig = Rig::start(&world).await;
        rig.assert_invariants(&world, Level::Safety, label).await;
        // The restarted controller's startup pass finishes the repair.
        let report = rig.reconcile(&world, now() + 11 * HOUR_MS).await.done();
        assert!(!report.pass_failed, "{label}: {report:?}");
        assert!(world.usb.stored(vmid).is_empty(), "{label}");
        assert!(rig.live_rows().await.is_empty(), "{label}");
        rig.retry_cleanup(&lease).await;
        rig.converge(&world, now() + 12 * HOUR_MS).await;
        rig.assert_nothing(&world, &lease, label).await;
        rig.kill().await;
    }
}

#[tokio::test]
async fn a_mid_run_detach_killed_after_the_delete_is_finished_by_the_holder_or_by_cleanup() {
    for holder_finishes in [true, false] {
        let world = std::sync::Arc::new(World::new(&[READER_A]).await);
        let rig = Rig::start(&world).await;
        let (lease, vmid) = rig.ready_lease(&world).await;
        world.usb.inject(UsbStep::Detach, UsbFault::CrashAfter, 1);
        let hotplug = rig.hotplug.clone();
        let request = lease.clone();
        let crashed = rig
            .run(&world, async move {
                hotplug
                    .detach(
                        &hardware_rig::AllowAll,
                        &fleet_application::authz::ActingPrincipal {
                            id: hardware_rig::PRINCIPAL.to_owned(),
                        },
                        &request,
                        READER_A,
                        false,
                        now(),
                    )
                    .await
                    .is_ok()
            })
            .await;
        assert_eq!(crashed, Run::Crashed);
        rig.assert_invariants(&world, Level::Safety, "at the kill")
            .await;
        rig.kill().await;
        let rig = Rig::start(&world).await;
        // The delete landed; the row says `detaching`; the lease is ready.
        assert_eq!(rig.states().await, vec!["detaching"]);
        assert!(world.usb.stored(vmid).is_empty());
        rig.assert_invariants(&world, Level::Safety, "after the restart")
            .await;
        if holder_finishes {
            // The holder repeats the request: it confirms by reading.
            let outcome = rig
                .hotplug_detach(&lease, READER_A, false)
                .await
                .expect("the repeat confirms the detach");
            assert_eq!(outcome.reservation_state, State::Held);
            assert_eq!(world.usb.writes().len(), 2, "no second delete");
        }
        rig.release(&lease).await;
        rig.converge(&world, now() + HOUR_MS).await;
        rig.assert_nothing(&world, &lease, "mid-run detach killed")
            .await;
        rig.kill().await;
    }
}

#[tokio::test]
async fn a_mid_run_attach_killed_after_the_write_fails_closed_at_release() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, vmid) = rig.ready_lease(&world).await;
    rig.hotplug_detach(&lease, READER_A, false)
        .await
        .expect("the holder detaches");
    world.usb.inject(UsbStep::Attach, UsbFault::CrashAfter, 1);
    let hotplug = rig.hotplug.clone();
    let request = lease.clone();
    let crashed = rig
        .run(&world, async move {
            hotplug
                .attach(
                    &hardware_rig::AllowAll,
                    &fleet_application::authz::ActingPrincipal {
                        id: hardware_rig::PRINCIPAL.to_owned(),
                    },
                    &request,
                    READER_A,
                    now(),
                )
                .await
                .is_ok()
        })
        .await;
    assert_eq!(crashed, Run::Crashed);
    rig.assert_invariants(&world, Level::Safety, "at the kill")
        .await;
    rig.kill().await;
    let rig = Rig::start(&world).await;
    // The entry landed; the row only recorded the attempt.
    assert_eq!(rig.states().await, vec!["attaching"]);
    assert_eq!(world.usb.stored(vmid), stored(&[(0, READER_A)]));
    rig.assert_invariants(&world, Level::Safety, "after the restart")
        .await;

    // The lease ends: the same documented limit as a provision killed after
    // its write. Nothing proves Fleet wrote the entry, so cleanup leaves it
    // and the lease ends cleanup_failed, visible, until the operator acts.
    rig.release(&lease).await;
    rig.converge(&world, now() + HOUR_MS).await;
    assert_eq!(rig.lease(&lease).await.state, LeaseState::CleanupFailed);
    let row = rig.live_row_of(READER_A).await.expect("the row is live");
    assert_eq!(row.state, "attach_unknown");
    assert_eq!(rig.device_status(READER_A).await, DeviceStatus::Quarantined);
    assert_eq!(world.usb.stored(vmid), stored(&[(0, READER_A)]));
    rig.assert_invariants(&world, Level::Quiescent, "fail closed")
        .await;
    rig.override_release(&row.id).await.expect("override");
    world.usb.clear_slot(vmid, 0);
    rig.retry_cleanup(&lease).await;
    rig.converge(&world, now() + 12 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "cleared").await;
}

/// Sweeps and drains at `at` until the controller dies at its scripted kill
/// point.
async fn run_to_the_kill(rig: &Rig, world: &World, at: i64) {
    for _ in 0..20 {
        if matches!(rig.sweep(world, at).await, Run::Crashed) {
            return;
        }
        if matches!(rig.drain(world).await, Run::Crashed) {
            return;
        }
    }
    panic!("the controller never reached its kill point");
}

#[tokio::test]
async fn a_controller_killed_over_and_over_never_leaves_a_device_assigned_twice_or_silently() {
    // The provision dies before its write; the restarted controller's cleanup
    // dies after it moved the row to `detaching`; the next one dies before it
    // commits the release. Every restart is checked, and the last one
    // finishes.
    let world = World::new(&[READER_A]).await;
    let (rig, lease) = killed_provision(&world, |world| {
        world.usb.inject(UsbStep::Attach, UsbFault::CrashBefore, 1);
    })
    .await;
    rig.recover().await;
    world.chaos.crash_at(
        Point::Transition(State::Attaching, State::Detaching),
        When::After,
    );
    run_to_the_kill(&rig, &world, now() + HOUR_MS).await;
    rig.assert_invariants(&world, Level::Safety, "second kill")
        .await;
    assert_eq!(rig.states().await, vec!["detaching"]);
    rig.kill().await;

    let rig = Rig::start(&world).await;
    rig.assert_invariants(&world, Level::Safety, "second restart")
        .await;
    rig.recover().await;
    world.chaos.crash_at(Point::Release, When::Before);
    run_to_the_kill(&rig, &world, now() + 2 * HOUR_MS).await;
    rig.assert_invariants(&world, Level::Safety, "third kill")
        .await;
    rig.kill().await;

    let rig = Rig::start(&world).await;
    rig.converge(&world, now() + 12 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "after three kills")
        .await;
    assert!(world.usb.writes().is_empty(), "nothing was ever written");
}

// ---------------------------------------------------------------------
// More kill points and hardware that changes under the lease.
// ---------------------------------------------------------------------

#[tokio::test]
async fn killed_during_the_detach_an_expiry_started_resumes_and_detaches_once() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, vmid) = rig.ready_lease(&world).await;
    let later = now() + 2 * 24 * HOUR_MS;
    // The sweeper expires the lease and queues its cleanup; the worker's
    // cleanup is killed right after its delete landed.
    world.usb.inject(UsbStep::Detach, UsbFault::CrashAfter, 1);
    let swept = rig.sweep(&world, later).await.done();
    assert_eq!(swept.expired, 1);
    assert_eq!(rig.drain(&world).await, Run::Crashed);
    rig.assert_invariants(&world, Level::Safety, "at the kill")
        .await;
    assert!(world.usb.stored(vmid).is_empty(), "the delete landed");
    rig.kill().await;
    let rig = Rig::start(&world).await;
    rig.assert_invariants(&world, Level::Safety, "after the restart")
        .await;
    rig.converge(&world, later).await;
    rig.assert_nothing(&world, &lease, "expiry, killed at the detach")
        .await;
    assert_eq!(
        world
            .usb
            .writes()
            .iter()
            .filter(|write| write.starts_with("detach"))
            .count(),
        1,
        "the resume confirmed by reading and wrote nothing"
    );
}

#[tokio::test]
async fn a_device_unplugged_while_attached_is_still_detached_and_released() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, vmid) = rig.ready_lease(&world).await;
    world.usb.set_present(READER_A, false);
    rig.refresh_inventory().await;
    // The row still holds the device and the guest still has the entry.
    assert_eq!(rig.states().await, vec!["attached"]);
    assert_eq!(world.usb.stored(vmid), stored(&[(0, READER_A)]));
    rig.assert_invariants(&world, Level::Safety, "unplugged while attached")
        .await;
    rig.release(&lease).await;
    rig.converge(&world, now() + HOUR_MS).await;
    world.usb.set_present(READER_A, true);
    rig.assert_nothing(&world, &lease, "unplugged, then released")
        .await;
}

#[tokio::test]
async fn a_guest_deleted_by_hand_while_it_held_a_device_fails_closed_and_the_override_clears_it() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, vmid) = rig.ready_lease(&world).await;
    // An operator deletes the guest in Proxmox. An absent guest is not proof
    // of detach (the listing omits guests the token cannot audit), so Fleet
    // does not release on a guess.
    world.usb.remove_guest(vmid).await;
    rig.release(&lease).await;
    rig.converge(&world, now() + HOUR_MS).await;

    assert_eq!(rig.lease(&lease).await.state, LeaseState::CleanupFailed);
    let row = rig.live_row_of(READER_A).await.expect("the row is live");
    assert_eq!(row.vmid, Some(vmid));
    assert!(
        row.state == "detaching" || row.state == "detach_failed" || row.state == "attached",
        "{row:?}"
    );
    rig.assert_invariants(&world, Level::Quiescent, "a hand-deleted guest")
        .await;

    // The operator has confirmed the device is free: the override clears it,
    // and the lease's cleanup then finds nothing left to do.
    rig.override_release(&row.id).await.expect("override");
    rig.retry_cleanup(&lease).await;
    rig.converge(&world, now() + 12 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "guest gone, override")
        .await;
}

// ---------------------------------------------------------------------
// A failed provision whose cleanup runs late (found by this suite, #592).
//
// This is not a hardware rule, but it decides whether a lease's guest (and
// the device attached to it) survives another lease's failure.
// ---------------------------------------------------------------------

/// A provision that fails after it reserved its VMID and before its clone
/// existed (here PVE refuses the clone call) keeps that VMID on its record.
/// Nothing is at the VMID, so `/cluster/nextid` keeps offering it. Its cleanup
/// is the sweeper's, which runs on its own schedule; before it does, a second
/// provision gets the same number.
///
/// The reservation's holder check now refuses that (see
/// `a_failed_provisions_vmid_is_not_handed_to_another_lease_before_its_cleanup`).
/// A database an earlier controller wrote has the other outcome, and the
/// cleanup's own check is what protects the second lease's guest there, so this
/// builds that state by blinding the holder check: the second provision
/// becomes ready on the VMID, and only then does the first one's cleanup run.
/// Answers the rig, the failed lease and the ready one.
async fn failed_provision_then_late_cleanup(
    world: &World,
    failing_template: usize,
    next_template: usize,
) -> (Rig, String, String) {
    use std::sync::atomic::Ordering;
    let rig = Rig::start(world).await;
    rig.refresh_inventory().await;
    let failed = rig.request_lease_of(&world.version(failing_template)).await;
    let next = rig.request_lease_of(&world.version(next_template)).await;
    world.faults.inject(Step::Clone, Fault::Forbidden, 1);
    world.chaos.blind_vmid_holders.store(true, Ordering::SeqCst);
    rig.drain(world).await.done();
    world
        .chaos
        .blind_vmid_holders
        .store(false, Ordering::SeqCst);
    assert_eq!(
        rig.lease(&next).await.state,
        LeaseState::Ready,
        "the second provision became ready: {}",
        rig.dump(world).await
    );
    assert_ne!(rig.lease(&failed).await.state, LeaseState::Ready);
    assert_eq!(
        rig.record(&failed).await.vmid,
        rig.record(&next).await.vmid,
        "both records name the same VMID"
    );
    (rig, failed, next)
}

#[tokio::test]
async fn a_failed_provisions_late_cleanup_must_not_destroy_another_leases_guest() {
    // Neither lease holds a device, so nothing but the guest's name would
    // protect the ready lease's running guest.
    let world = World::with_templates(&[&[], &[]]).await;
    let (rig, failed, next) = failed_provision_then_late_cleanup(&world, 0, 1).await;
    rig.converge(&world, now() + HOUR_MS).await;
    let record = rig.record(&next).await;
    assert_eq!(rig.lease(&next).await.state, LeaseState::Ready);
    assert!(
        world
            .pve
            .lab_guests()
            .get(&record.vmid.unwrap())
            .is_some_and(|guest| guest.name == format!("fm-lab-{}", record.id)),
        "the ready lease's guest is still there: {}",
        rig.dump(&world).await
    );
    // The failed lease never cloned anything: its cleanup finds nothing to
    // destroy and releases, instead of retrying against a guest it never
    // owned.
    assert_eq!(rig.lease(&failed).await.state, LeaseState::Released);
    rig.assert_invariants(&world, Level::Quiescent, "a late cleanup")
        .await;
}

#[tokio::test]
async fn a_failed_provisions_vmid_is_not_handed_to_another_lease_before_its_cleanup() {
    // Both provisions ask for the next free VMID and get the same one (nothing
    // is there). The first fails after reserving it, before any clone. The
    // second is refused the number while the first's lease is unreleased,
    // rather than becoming ready on a VMID the first one's cleanup will aim at.
    let world = World::with_templates(&[&[], &[]]).await;
    let rig = Rig::start(&world).await;
    rig.refresh_inventory().await;
    let failed = rig.request_lease_of(&world.version(0)).await;
    let next = rig.request_lease_of(&world.version(1)).await;
    world.faults.inject(Step::Clone, Fault::Forbidden, 1);
    rig.drain(&world).await.done();
    assert_ne!(rig.lease(&failed).await.state, LeaseState::Ready);
    assert!(rig.record(&failed).await.vmid.is_some());
    assert_eq!(
        rig.lease(&next).await.state,
        LeaseState::Failed,
        "{}",
        rig.dump(&world).await
    );
    assert_eq!(rig.record(&next).await.vmid, None, "it took no VMID");
    assert!(world.pve.lab_guests().is_empty());

    // The failed lease's cleanup releases it; the number is free again and a
    // later lease gets it.
    rig.converge(&world, now() + HOUR_MS).await;
    assert_eq!(rig.lease(&failed).await.state, LeaseState::Released);
    let later = rig.request_lease_of(&world.version(1)).await;
    rig.drain(&world).await.done();
    assert_eq!(rig.lease(&later).await.state, LeaseState::Ready);
    let record = rig.record(&later).await;
    assert_eq!(record.vmid, rig.record(&failed).await.vmid);
    rig.converge(&world, now() + 2 * HOUR_MS).await;
    assert_eq!(rig.lease(&later).await.state, LeaseState::Ready);
    assert!(world.pve.lab_guests().contains_key(&record.vmid.unwrap()));
}

#[tokio::test]
async fn a_device_attached_guest_survives_a_late_cleanup_of_the_same_vmid() {
    // The second lease holds a device. The failed one's cleanup still aims at
    // its VMID, but it never cloned and the guest there is not its own: it
    // destroys nothing, so the ready lease is untouched and its device stays
    // attached. The failed lease, which owned no guest, is released (before
    // #592 it ended `cleanup_failed`, naming a guest it never owned, with the
    // hardware destroy guard the only thing between it and the guest).
    let world = World::with_templates(&[&[], &[READER_B]]).await;
    let (rig, failed, next) = failed_provision_then_late_cleanup(&world, 0, 1).await;
    rig.converge(&world, now() + HOUR_MS).await;
    let record = rig.record(&next).await;
    assert_eq!(rig.lease(&next).await.state, LeaseState::Ready);
    assert_eq!(rig.lease(&failed).await.state, LeaseState::Released);
    assert!(world.pve.lab_guests().contains_key(&record.vmid.unwrap()));
    assert_eq!(
        world.usb.stored(record.vmid.unwrap()),
        stored(&[(0, READER_B)]),
        "the ready lease keeps its device"
    );
    assert_eq!(world.usb.count(|line| line.starts_with("Delete ")), 0);
    rig.assert_invariants(&world, Level::Quiescent, "a late cleanup")
        .await;
    // The ready lease still releases to nothing.
    rig.release(&next).await;
    rig.converge(&world, now() + 2 * HOUR_MS).await;
    assert_eq!(rig.lease(&next).await.state, LeaseState::Released);
}

// ---------------------------------------------------------------------
// A hotplug attach that straddles the lease's cleanup (found by this suite).
// ---------------------------------------------------------------------

/// A hook that signals `signal` (if any), then waits for `wait` (if any).
fn gate(
    signal: Option<std::sync::Arc<tokio::sync::Notify>>,
    wait: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> usb_pve::Hook {
    std::sync::Arc::new(move || {
        let signal = signal.clone();
        let wait = wait.clone();
        Box::pin(async move {
            if let Some(signal) = signal {
                signal.notify_one();
            }
            if let Some(wait) = wait {
                wait.notified().await;
            }
        })
    })
}

/// Where the holder's hotplug attach is when the lease's cleanup runs. Every
/// variant starts the same way: the lease detached its device mid-run (the row
/// is `held`), and the lease is released while the holder's attach request,
/// whose lease check passed just before, is in flight. The attach goes on once
/// the cleanup has destroyed the guest, which is the worst case for it: the
/// guest it would read back to undo itself is gone.
#[derive(Clone, Copy, Debug)]
enum Straddle {
    /// The attach moves the row only after the cleanup finished: the cleanup
    /// found the row `held` and the guest is gone.
    After,
    /// The attach moves the row after the cleanup read it as `held` and right
    /// before the cleanup releases it (the issue's interleaving).
    During,
    /// The attach moved the row before the cleanup read the lease's rows, then
    /// stalls until the guest is gone.
    Before,
}

const STRADDLES: [Straddle; 3] = [Straddle::After, Straddle::During, Straddle::Before];

struct Straddled {
    world: World,
    rig: std::sync::Arc<Rig>,
    lease: String,
    /// What the attach answered.
    attach: Result<
        fleet_application::lab_hardware_hotplug::HotplugOutcome,
        fleet_application::lab_hardware_hotplug::HotplugError,
    >,
    /// The writes that had landed before the attach and the cleanup began.
    writes_before: Vec<String>,
}

/// The interleaving of the race test above, made deterministic.
async fn straddling_attach(how: Straddle) -> Straddled {
    use std::sync::Arc;
    use tokio::sync::Notify;

    let world = World::new(&[READER_A]).await;
    let rig = Arc::new(Rig::start(&world).await);
    let (lease, vmid) = rig.ready_lease(&world).await;
    rig.hotplug_detach(&lease, READER_A, false)
        .await
        .expect("the holder detaches");
    assert_eq!(rig.states().await, vec!["held"]);
    let writes_before = world.usb.writes();

    let reached = Arc::new(Notify::new());
    let guest_destroyed = Arc::new(Notify::new());
    let moving = Point::Transition(State::Held, State::Attaching);
    match how {
        Straddle::After => {
            world.chaos.run_at(
                moving,
                When::Before,
                gate(Some(reached.clone()), Some(guest_destroyed.clone())),
            );
        }
        Straddle::During => {
            let cleanup_at_release = Arc::new(Notify::new());
            let attach_moved = Arc::new(Notify::new());
            // The attach waits right before it moves the row, until the
            // cleanup is about to release it ...
            world.chaos.run_at(
                moving,
                When::Before,
                gate(Some(reached.clone()), Some(cleanup_at_release.clone())),
            );
            // ... the cleanup waits right before that release, until the
            // attach moved the row ...
            world.chaos.run_at(
                Point::Release,
                When::Before,
                gate(Some(cleanup_at_release), Some(attach_moved.clone())),
            );
            // ... and the attach, once it moved the row (and before it checks
            // the lease and reads the guest back), waits for the destroy.
            world.chaos.run_at(
                moving,
                When::After,
                gate(Some(attach_moved), Some(guest_destroyed.clone())),
            );
        }
        Straddle::Before => {
            world.chaos.run_at(
                moving,
                When::After,
                gate(Some(reached.clone()), Some(guest_destroyed.clone())),
            );
        }
    }
    let attach = {
        let rig = rig.clone();
        let lease = lease.clone();
        tokio::spawn(async move { rig.raw_attach(&lease, vmid, READER_A).await })
    };
    let reached = tokio::time::timeout(std::time::Duration::from_secs(10), reached.notified());
    if reached.await.is_err() {
        panic!("the attach never reached its pause ({how:?})");
    }

    // The lease ends and its cleanup runs to the end.
    rig.release(&lease).await;
    // Whoever is watching tells the attach once the guest is gone.
    let watcher = {
        let world_pve = world.pve.clone();
        tokio::spawn(async move {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while world_pve.lab_guests().contains_key(&vmid) && std::time::Instant::now() < deadline
            {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            guest_destroyed.notify_one();
        })
    };
    rig.drain(&world).await.done();
    watcher.await.unwrap();
    let attach = tokio::time::timeout(std::time::Duration::from_secs(10), attach)
        .await
        .expect("the attach finishes once the guest is gone")
        .unwrap();
    Straddled {
        world,
        rig,
        lease,
        attach,
        writes_before,
    }
}

fn refusal(
    attach: &Result<
        fleet_application::lab_hardware_hotplug::HotplugOutcome,
        fleet_application::lab_hardware_hotplug::HotplugError,
    >,
) -> Option<String> {
    match attach {
        Err(fleet_application::lab_hardware_hotplug::HotplugError::Refused { reason, .. }) => {
            Some(reason.clone())
        }
        _ => None,
    }
}

#[tokio::test]
async fn a_hotplug_attach_that_straddles_the_cleanup_never_writes_and_leaves_no_row() {
    // Asserted exactly, per interleaving: the attach never writes (so there is
    // nothing to undo on a guest that is about to go), and the lease's row is
    // released, not left `attach_unknown` on a released lease.
    for how in STRADDLES {
        let Straddled {
            world,
            rig,
            lease,
            attach,
            writes_before,
        } = straddling_attach(how).await;
        let label = format!("{how:?}");
        assert_eq!(
            rig.lease(&lease).await.state,
            LeaseState::Released,
            "{label}"
        );
        assert!(
            attach.is_err(),
            "{label}: a lease that ended gets no attach: {attach:?}"
        );
        if matches!(how, Straddle::After) {
            // The compare-and-set found the row released by the cleanup: a
            // clean refusal, and the audit trail says why.
            assert_eq!(
                refusal(&attach).as_deref(),
                Some("hardware_lease_ended"),
                "{label}: {attach:?}"
            );
        }
        assert_eq!(rig.states().await, vec!["released"], "{label}");
        assert!(rig.live_row_of(READER_A).await.is_none(), "{label}");
        assert_eq!(world.usb.writes(), writes_before, "{label}: no write");
        assert!(world.pve.lab_guests().is_empty(), "{label}");
        assert!(world.usb.double_assignments().is_empty(), "{label}");
        assert!(world.usb.destroyed_holding().is_empty(), "{label}");
        // Nothing for the reconciler or an operator to do.
        rig.refresh_inventory().await;
        assert_eq!(
            rig.device_status(READER_A).await,
            DeviceStatus::Available,
            "{label}"
        );
        rig.assert_invariants(&world, Level::Quiescent, &label)
            .await;
    }
}

#[tokio::test]
async fn a_released_lease_holds_no_reservation_even_when_a_hotplug_attach_straddles_its_cleanup() {
    for how in STRADDLES {
        let Straddled {
            world, rig, lease, ..
        } = straddling_attach(how).await;
        rig.converge(&world, now() + HOUR_MS).await;
        rig.assert_nothing(&world, &lease, &format!("a straddling attach ({how:?})"))
            .await;
    }
}

#[tokio::test]
async fn an_attach_whose_write_was_lost_on_a_live_guest_is_never_released_while_the_guest_may_hold_it()
 {
    // The converse of the straddle: here the write really happened. The holder
    // detached (the row is `held`), the attach's write lands and its answer is
    // lost, so the row is `attach_unknown` with a slot while the guest is
    // alive and holds the device. Nothing may release that row on a guess: not
    // the lease's cleanup (whose detach is refused), not the reconciler, not
    // the release of the lease. Only a confirmed detach does.
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, vmid) = rig.ready_lease(&world).await;
    rig.hotplug_detach(&lease, READER_A, false)
        .await
        .expect("the holder detaches");
    assert!(world.usb.stored(vmid).is_empty());

    world.usb.inject(UsbStep::Attach, UsbFault::Lost, 1);
    let attach = rig.hotplug_attach(&lease, READER_A).await;
    assert!(attach.is_err(), "{attach:?}");
    let row = rig.live_row_of(READER_A).await.expect("the row is live");
    assert_eq!(row.state, "attach_unknown", "{}", rig.dump(&world).await);
    assert!(row.slot.is_some(), "the attempted slot is recorded");
    assert_eq!(
        world.usb.stored(vmid),
        stored(&[(0, READER_A)]),
        "the write landed"
    );

    // The lease ends while the role cannot delete the entry.
    world.usb.inject(UsbStep::Detach, UsbFault::Forbidden, 500);
    rig.release(&lease).await;
    rig.converge(&world, now() + HOUR_MS).await;
    assert_eq!(
        rig.lease(&lease).await.state,
        LeaseState::CleanupFailed,
        "{}",
        rig.dump(&world).await
    );
    let row = rig
        .live_row_of(READER_A)
        .await
        .expect("an uncertain write on a live guest is never released");
    assert!(
        matches!(row.state.as_str(), "attach_unknown" | "detach_failed"),
        "{row:?}"
    );
    assert!(
        world.pve.lab_guests().contains_key(&vmid),
        "the guest that may hold the device is kept"
    );
    assert_eq!(world.usb.stored(vmid), stored(&[(0, READER_A)]));
    assert_ne!(rig.device_status(READER_A).await, DeviceStatus::Available);
    assert!(world.usb.double_assignments().is_empty());
    assert!(world.usb.destroyed_holding().is_empty());
    rig.assert_invariants(&world, Level::Safety, "an uncertain write")
        .await;

    // The role is back: the cleanup removes the entry it can now prove is
    // Fleet's, and only then is the row released.
    world.usb.clear();
    rig.retry_cleanup(&lease).await;
    rig.converge(&world, now() + 20 * HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "after the detach is confirmed")
        .await;
}

// ---------------------------------------------------------------------
// The checker itself can fail: each rule is shown to fire on a state built
// to break it.
// ---------------------------------------------------------------------

#[tokio::test]
async fn the_checker_reports_a_device_on_two_guests() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (_lease, _) = rig.ready_lease(&world).await;
    rig.assert_invariants(&world, Level::Quiescent, "a healthy lease")
        .await;
    // An operator gives a second guest the device the lease holds.
    world.usb.create_guest(8001, "operator-guest").await;
    world.usb.set_slot(8001, 0, "mapping=fm-test-reader-a");
    let violations = rig.check(&world, Level::Safety, &[]).await;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("is on 2 guest slots at once")),
        "{violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("holds fm-test-reader-a with no live reservation")),
        "{violations:?}"
    );
    // Told it is the operator's own entry, the checker lets it be.
    assert!(
        rig.check(&world, Level::Safety, &[(8001, 0)])
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn the_checker_reports_a_silently_assigned_device_and_accepts_a_visible_one() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, _) = rig.ready_lease(&world).await;
    rig.release(&lease).await;
    rig.converge(&world, now() + HOUR_MS).await;
    rig.assert_nothing(&world, &lease, "released").await;
    // The device turns up on a guest no reservation names, and the inventory
    // has not noticed: silently assigned.
    world.usb.create_guest(8001, "operator-guest").await;
    world.usb.set_slot(8001, 0, "mapping=fm-test-reader-a");
    let violations = rig.check(&world, Level::Safety, &[]).await;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("holds fm-test-reader-a with no live reservation")),
        "{violations:?}"
    );
    // Once the inventory shows it, it is visible, and that is accepted.
    rig.refresh_inventory().await;
    assert_eq!(
        rig.device_status(READER_A).await,
        DeviceStatus::ExternallyAttached
    );
    assert!(rig.check(&world, Level::Safety, &[]).await.is_empty());
}

#[tokio::test]
async fn the_checker_reports_a_released_lease_that_still_holds_a_row() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (lease, _) = rig.ready_lease(&world).await;
    // The lease is marked released with nothing having detached its device.
    sqlx::query("UPDATE lab_leases SET state = 'released' WHERE id = ?1")
        .bind(&lease)
        .execute(&rig.pool)
        .await
        .unwrap();
    let violations = rig.check(&world, Level::Safety, &[]).await;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("released lease")
                && violation.contains("still holds")),
        "{violations:?}"
    );
}

#[tokio::test]
async fn the_checker_reports_rows_that_disagree_with_their_guests() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (_lease, vmid) = rig.ready_lease(&world).await;
    // The row says attached, and an operator took the entry off the guest.
    world.usb.clear_slot(vmid, 0);
    let violations = rig.check(&world, Level::Safety, &[]).await;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("is attached to guest")),
        "{violations:?}"
    );
    // And the quiescent rules see a ready lease that does not hold its device.
    let violations = rig.check(&world, Level::Quiescent, &[]).await;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("does not hold fm-test-reader-a attached")),
        "{violations:?}"
    );
}

#[tokio::test]
async fn the_checker_reports_a_write_that_assigned_a_device_twice() {
    // The fake host's own monitor: a second attach lands on a mapping a
    // guest already references. (Built by hand, writing through the same
    // transport the controller uses.)
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (_lease, _) = rig.ready_lease(&world).await;
    world.usb.create_guest(8001, "operator-guest").await;
    world
        .usb
        .operator_attach(8001, 0, "mapping=fm-test-reader-a");
    assert_eq!(world.usb.double_assignments().len(), 1);
    let violations = rig.check(&world, Level::Safety, &[(8001, 0)]).await;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("a write assigned a device twice")),
        "{violations:?}"
    );
}

#[tokio::test]
async fn the_checker_reports_a_guest_destroyed_while_it_held_a_device() {
    let world = World::new(&[READER_A]).await;
    let rig = Rig::start(&world).await;
    let (_lease, vmid) = rig.ready_lease(&world).await;
    // An operator destroys it with its device still on it (the real thing
    // the reviewed destroy route refuses).
    world.usb.operator_destroy(vmid).await;
    let violations = rig.check(&world, Level::Safety, &[]).await;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("a guest was destroyed holding a device")),
        "{violations:?}"
    );
}
