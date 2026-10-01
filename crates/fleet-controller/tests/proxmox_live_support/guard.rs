//! The cleanup guard. Every guest the suite creates lies inside the
//! target's `VMID_RANGE`, is named `fleet-acceptance-*`, and is tagged
//! `fleet-acceptance`. The guard sweeps the range at the start and end of
//! every scenario, and again from `Drop` when a scenario unwinds, so a
//! panic never leaks a guest. A guest outside the range is never touched;
//! a guest inside it that is not the suite's own is reported, not touched.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use super::config::VmidRange;
use super::pve::{PveAdmin, VmResource};
use super::redact::Redactor;

/// The tag on every scratch guest.
pub const TAG: &str = "fleet-acceptance";
/// The name prefix on every scratch guest.
pub const NAME_PREFIX: &str = "fleet-acceptance-";

/// What the sweep does with one guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SweepDecision {
    /// Outside the range: never touched, never reported.
    Outside,
    /// The suite's own leftover: destroy it.
    Destroy,
    /// Inside the range but not the suite's (no tag, foreign name, or a
    /// template): left alone and reported.
    Foreign(String),
}

/// Classifies one guest for the sweep.
#[must_use]
pub fn classify(resource: &VmResource, range: VmidRange) -> SweepDecision {
    if !range.contains(resource.vmid) {
        return SweepDecision::Outside;
    }
    if resource.template {
        return SweepDecision::Foreign(format!(
            "VMID {} inside the range is a template; the suite never destroys templates",
            resource.vmid
        ));
    }
    let tagged = resource.tags.iter().any(|tag| tag == TAG);
    let named = resource
        .name
        .as_deref()
        .is_some_and(|name| name.starts_with(NAME_PREFIX));
    if tagged || named {
        SweepDecision::Destroy
    } else {
        SweepDecision::Foreign(format!(
            "VMID {} inside the range is neither tagged {TAG} nor named {NAME_PREFIX}*; \
             it was left alone (reserve the range for the suite)",
            resource.vmid
        ))
    }
}

/// The lowest VMID in the range that no guest holds and this run has not
/// handed out yet.
#[must_use]
pub fn first_free(range: VmidRange, taken: &BTreeSet<u32>) -> Option<u32> {
    (range.first..=range.last).find(|vmid| !taken.contains(vmid))
}

/// What one sweep did.
#[derive(Debug, Default)]
pub struct SweepReport {
    /// Destroyed VMIDs.
    pub destroyed: Vec<u32>,
    /// Guests left alone, with the reason.
    pub foreign: Vec<String>,
}

/// The per-scenario guard.
#[derive(Debug)]
pub struct ScratchGuard {
    pve: Arc<PveAdmin>,
    redactor: Redactor,
    handed_out: Mutex<BTreeSet<u32>>,
    finished: Mutex<bool>,
    label: String,
}

impl ScratchGuard {
    /// A guard for one scenario on one target.
    #[must_use]
    pub fn new(pve: Arc<PveAdmin>, redactor: Redactor, label: String) -> Self {
        Self {
            pve,
            redactor,
            handed_out: Mutex::new(BTreeSet::new()),
            finished: Mutex::new(false),
            label,
        }
    }

    /// Destroys every guest the classification says is the suite's own.
    ///
    /// # Errors
    ///
    /// Lists every guest the sweep could not destroy.
    pub async fn sweep(&self) -> Result<SweepReport, String> {
        sweep(&self.pve).await
    }

    /// Hands out one free VMID in the range for a guest about to be created
    /// (or for an operation that must target a VMID that does not exist).
    ///
    /// # Errors
    ///
    /// When the range is full or the cluster listing fails.
    pub async fn allocate(&self) -> Result<u32, String> {
        let resources = self.pve.resources().await?;
        let mut handed_out = self
            .handed_out
            .lock()
            .map_err(|_| "the allocation lock is poisoned".to_owned())?;
        let mut taken: BTreeSet<u32> = resources.iter().map(|resource| resource.vmid).collect();
        taken.extend(handed_out.iter().copied());
        let vmid = first_free(self.pve.range(), &taken)
            .ok_or_else(|| format!("the VMID range {} has no free VMID left", self.pve.range()))?;
        handed_out.insert(vmid);
        Ok(vmid)
    }

    /// The end-of-scenario sweep; after it, `Drop` does nothing.
    ///
    /// # Errors
    ///
    /// When the sweep could not destroy every leftover.
    pub async fn finish(&self) -> Result<SweepReport, String> {
        let report = self.sweep().await;
        if let Ok(mut finished) = self.finished.lock() {
            *finished = true;
        }
        report
    }
}

impl Drop for ScratchGuard {
    fn drop(&mut self) {
        let finished = self.finished.lock().map(|done| *done).unwrap_or(false);
        if finished {
            return;
        }
        // The scenario unwound (a panic) before its end sweep. Drop cannot
        // await, and the test's runtime may be the one unwinding, so the
        // sweep runs on its own thread and runtime and is joined here.
        let pve = self.pve.clone();
        let outcome = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("cannot start the cleanup runtime: {error}"))?;
            runtime.block_on(sweep(&pve))
        })
        .join();
        let line = match outcome {
            Ok(Ok(report)) => format!(
                "fleet-acceptance: cleanup after an unwound scenario ({}) destroyed {:?}",
                self.label, report.destroyed
            ),
            Ok(Err(detail)) => format!(
                "fleet-acceptance: CLEANUP FAILED after an unwound scenario ({}): {detail}",
                self.label
            ),
            Err(_) => format!(
                "fleet-acceptance: CLEANUP PANICKED after an unwound scenario ({})",
                self.label
            ),
        };
        eprintln!("{}", self.redactor.line(&line));
    }
}

/// One sweep over the cluster.
async fn sweep(pve: &PveAdmin) -> Result<SweepReport, String> {
    let range = pve.range();
    let mut report = SweepReport::default();
    let mut failures = Vec::new();
    for resource in pve.resources().await? {
        match classify(&resource, range) {
            SweepDecision::Outside => {}
            SweepDecision::Foreign(reason) => report.foreign.push(reason),
            SweepDecision::Destroy => match pve.destroy(&resource).await {
                Ok(()) => report.destroyed.push(resource.vmid),
                Err(detail) => failures.push(format!("VMID {}: {detail}", resource.vmid)),
            },
        }
    }
    if failures.is_empty() {
        Ok(report)
    } else {
        Err(format!(
            "the sweep left guests behind: {}",
            failures.join("; ")
        ))
    }
}
