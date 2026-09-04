//! The node's inventory state: baseline snapshots, revisioned deltas, and
//! the gap rule.
//!
//! Delivery to the controller is at-least-once, so the state machine is
//! built to self-heal: every collection records what it observed as the new
//! baseline (revision + 1), and a dispatch whose `expectedRevision` does not
//! match the node's baseline is answered with a **full snapshot** instead of
//! a delta that would hang on a missing base. A controller that missed a
//! delivery therefore recovers on the next round trip without special
//! handling.
//!
//! The state file is written atomically (temporary file + rename), so a
//! crash mid-write leaves the previous baseline intact.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fleet_core::{CapabilityFact, CapabilityStatus};
use serde::{Deserialize, Serialize};

use crate::probes::ProbeRunner;

/// The inventory schema version this build produces. Ingestion refuses
/// anything else.
pub const INVENTORY_SCHEMA_VERSION: u32 = 1;

/// The node-local inventory state.
#[derive(Debug)]
pub struct InventoryState {
    path: PathBuf,
    baseline: Mutex<Option<Baseline>>,
}

/// The last observed state, as recorded locally.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Baseline {
    revision: u64,
    facts: Vec<CapabilityFact>,
}

/// One collection round's answer, as the command result payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryReport {
    /// The payload schema version.
    pub schema_version: u32,
    /// `full` or `delta`.
    pub mode: String,
    /// The revision this report observes (the new baseline).
    pub revision: u64,
    /// The baseline the delta is against; absent for a full snapshot.
    pub baseline_revision: Option<u64>,
    /// The facts: everything for a full snapshot, only changes for a delta.
    pub facts: Vec<CapabilityFact>,
    /// What failed, per probe, bounded and safe to report.
    pub probe_errors: Vec<crate::probes::ProbeError>,
}

/// An inventory problem; the detail is safe to print (paths and parse
/// state, never fact values).
#[derive(Debug)]
pub enum InventoryError {
    /// The state file could not be written or loaded.
    Io {
        /// What the OS reported.
        detail: String,
    },
}

impl std::fmt::Display for InventoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { detail } => write!(f, "inventory state io failed: {detail}"),
        }
    }
}

impl std::error::Error for InventoryError {}

impl InventoryState {
    /// Opens (or initializes) the inventory state at `path`.
    ///
    /// # Errors
    ///
    /// Fails when the state file cannot be read; a malformed file resets to
    /// no baseline rather than failing the daemon.
    pub fn open(path: &Path) -> Result<Self, InventoryError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| InventoryError::Io {
                detail: error.to_string(),
            })?;
        }
        let baseline = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<Baseline>(&bytes).ok(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(InventoryError::Io {
                    detail: error.to_string(),
                });
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            baseline: Mutex::new(baseline),
        })
    }

    /// The current baseline revision, when the node has one.
    ///
    /// # Panics
    ///
    /// Panics only if the state's mutex is poisoned by a panic while
    /// holding it, which no code path does.
    #[must_use]
    pub fn revision(&self) -> Option<u64> {
        self.baseline
            .lock()
            .expect("uncontended")
            .as_ref()
            .map(|baseline| baseline.revision)
    }

    /// Collects one round and produces the report: a full snapshot when
    /// there is no baseline or the expected revision is a gap, a delta of
    /// changed facts otherwise. The observed state becomes the new baseline
    /// either way, persisted before the report returns.
    ///
    /// # Panics
    ///
    /// Panics only if the state's mutex is poisoned by a panic while
    /// holding it, which no code path does.
    ///
    /// # Errors
    ///
    /// Fails when the new baseline cannot be persisted.
    pub fn collect(
        &self,
        runner: &ProbeRunner,
        expected_revision: Option<u64>,
        now_millis: i64,
    ) -> Result<InventoryReport, InventoryError> {
        let collected = runner.collect(now_millis);
        let mut facts = collected.facts;
        facts.sort_by(|a, b| {
            (&a.namespace, &a.name, &a.value).cmp(&(&b.namespace, &b.name, &b.value))
        });

        let mut baseline = self.baseline.lock().expect("uncontended");
        let (mode, baseline_revision, changed) = match baseline.as_ref() {
            Some(previous) if expected_revision == Some(previous.revision) => {
                // Delta: only what changed since the recorded baseline.
                let previous_facts: std::collections::HashMap<
                    (&str, &str),
                    (&Option<String>, CapabilityStatus),
                > = previous
                    .facts
                    .iter()
                    .map(|fact| {
                        (
                            (fact.namespace.as_str(), fact.name.as_str()),
                            (&fact.value, fact.status),
                        )
                    })
                    .collect();
                let changed: Vec<CapabilityFact> = facts
                    .iter()
                    .filter(|fact| {
                        !previous_facts
                            .get(&(fact.namespace.as_str(), fact.name.as_str()))
                            .is_some_and(|(value, status)| {
                                *value == &fact.value && *status == fact.status
                            })
                    })
                    .cloned()
                    .collect();
                ("delta", Some(previous.revision), changed)
            }
            _ => ("full", None, facts.clone()),
        };

        let new_revision = baseline
            .as_ref()
            .map_or(1, |previous| previous.revision + 1);
        *baseline = Some(Baseline {
            revision: new_revision,
            facts: facts.clone(),
        });
        drop(baseline);
        self.persist(new_revision, &facts)?;

        Ok(InventoryReport {
            schema_version: INVENTORY_SCHEMA_VERSION,
            mode: mode.to_owned(),
            revision: new_revision,
            baseline_revision,
            facts: changed,
            probe_errors: collected.probe_errors,
        })
    }

    fn persist(&self, revision: u64, facts: &[CapabilityFact]) -> Result<(), InventoryError> {
        let baseline = Baseline {
            revision,
            facts: facts.to_vec(),
        };
        let temporary = self.path.with_extension("compact");
        let bytes = serde_json::to_vec(&baseline).map_err(|error| InventoryError::Io {
            detail: error.to_string(),
        })?;
        std::fs::write(&temporary, bytes).map_err(|error| InventoryError::Io {
            detail: error.to_string(),
        })?;
        std::fs::rename(&temporary, &self.path).map_err(|error| InventoryError::Io {
            detail: error.to_string(),
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{Probe, ProbeRunner};
    use fleet_core::CapabilityStatus;
    use std::sync::Arc;

    fn fact(namespace: &str, name: &str, value: &str) -> CapabilityFact {
        CapabilityFact {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            value: Some(value.to_owned()),
            status: CapabilityStatus::Known,
            observed_at: fleet_core::Timestamp::from_unix_millis(0),
            source: String::new(),
        }
    }

    /// A probe whose facts the test drives per round through shared state.
    #[derive(Debug)]
    struct ScriptedProbe {
        round: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        script: Vec<Vec<CapabilityFact>>,
    }

    impl Probe for ScriptedProbe {
        fn name(&self) -> &'static str {
            "scripted"
        }

        fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
            let round = self.round.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self
                .script
                .get(round)
                .cloned()
                .unwrap_or_else(|| self.script.last().cloned().unwrap_or_default()))
        }
    }

    fn state() -> (tempfile::TempDir, InventoryState) {
        let dir = tempfile::tempdir().unwrap();
        let state = InventoryState::open(&dir.path().join("inventory.json")).unwrap();
        (dir, state)
    }

    #[test]
    fn the_first_collection_is_a_full_snapshot_and_starts_the_baseline() {
        let (_dir, state) = state();
        let runner = ProbeRunner::new(vec![Arc::new(ScriptedProbe {
            round: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            script: vec![vec![fact("os", "family", "linux")]],
        })]);
        let report = state.collect(&runner, None, 1).unwrap();
        assert_eq!(report.mode, "full");
        assert_eq!(report.baseline_revision, None);
        assert_eq!(report.revision, 1);
        assert_eq!(report.facts.len(), 1);
        assert_eq!(state.revision(), Some(1));
    }

    #[test]
    fn an_unchanged_round_deltas_to_nothing() {
        let (_dir, state) = state();
        let runner = ProbeRunner::new(vec![Arc::new(ScriptedProbe {
            round: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            script: vec![vec![fact("os", "family", "linux")]],
        })]);
        let first = state.collect(&runner, None, 1).unwrap();
        assert_eq!(first.mode, "full");

        let second = state.collect(&runner, Some(1), 2).unwrap();
        assert_eq!(second.mode, "delta");
        assert_eq!(second.baseline_revision, Some(1));
        assert!(second.facts.is_empty(), "nothing changed");
        assert_eq!(second.revision, 2);
    }

    #[test]
    fn a_changed_round_deltas_only_the_changes() {
        let (_dir, state) = state();
        let runner = ProbeRunner::new(vec![Arc::new(ScriptedProbe {
            round: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            script: vec![
                vec![fact("os", "family", "linux"), fact("tool", "git", "2.40")],
                vec![fact("os", "family", "linux"), fact("tool", "git", "2.41")],
            ],
        })]);
        state.collect(&runner, None, 1).unwrap();
        let delta = state.collect(&runner, Some(1), 2).unwrap();
        assert_eq!(delta.mode, "delta");
        assert_eq!(delta.facts.len(), 1, "only git changed");
        assert_eq!(delta.facts[0].value.as_deref(), Some("2.41"));
    }

    #[test]
    fn a_revision_gap_answers_with_a_full_snapshot() {
        let (_dir, state) = state();
        let runner = ProbeRunner::new(vec![Arc::new(ScriptedProbe {
            round: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            script: vec![vec![fact("os", "family", "linux")]],
        })]);
        state.collect(&runner, None, 1).unwrap();
        // The controller expects a revision the node never recorded.
        let gap = state.collect(&runner, Some(99), 2).unwrap();
        assert_eq!(gap.mode, "full", "a gap must not delta");
        assert_eq!(gap.baseline_revision, None);
        assert_eq!(gap.facts.len(), 1, "the full fact set");
    }

    #[test]
    fn a_lost_baseline_self_heals_on_the_next_round() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.json");
        let runner = ProbeRunner::new(vec![Arc::new(ScriptedProbe {
            round: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            script: vec![vec![fact("os", "family", "linux")]],
        })]);
        {
            let state = InventoryState::open(&path).unwrap();
            state.collect(&runner, None, 1).unwrap();
        }
        // The state file is durable: a reload sees the baseline.
        let state = InventoryState::open(&path).unwrap();
        assert_eq!(state.revision(), Some(1));
        let delta = state.collect(&runner, Some(1), 2).unwrap();
        assert_eq!(delta.mode, "delta");
    }
}
