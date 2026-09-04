//! The node command journal: the local, durable record of accepted commands
//! and their terminal results.
//!
//! Delivery over the gateway is at-least-once, so the journal is what makes
//! re-delivery safe: a `Command` whose operation id already has a terminal
//! result is answered by replaying the record — never re-executed — and one
//! already accepted but unfinished is ignored rather than started twice.
//!
//! The file is append-only NDJSON: one JSON object per line, appended and
//! synced before the command starts. On load, a torn trailing line (the
//! classic crash-mid-write shape) is truncated; records after the last
//! complete line never existed as far as the journal is concerned. When the
//! live record count grows past [`COMPACTION_THRESHOLD`], the file is
//! rewritten atomically (temporary file + rename) keeping only the newest
//! record per operation id.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// The journal is compacted once more live records than this exist.
pub const COMPACTION_THRESHOLD: usize = 512;

/// One journaled command: its acceptance, and its terminal result when one
/// has been recorded.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalRecord {
    /// The operation the command belongs to. The dedupe key.
    pub operation_id: String,
    /// The command kind, for diagnostics.
    pub kind: String,
    /// Acceptance time (epoch milliseconds).
    pub accepted_at: i64,
    /// The terminal result, when the command finished.
    pub result: Option<JournalResult>,
}

/// The terminal result of one command, as recorded and replayed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalResult {
    /// The stable result status: `succeeded`, `failed`, `cancelled`,
    /// `timed_out`, or `rejected`.
    pub status: String,
    /// The process exit code, when the kind has one.
    pub exit_code: Option<i32>,
    /// Whether the result payload was truncated to the output bound.
    pub output_truncated: bool,
    /// How long the command ran (milliseconds).
    pub duration_millis: i64,
    /// Whether the work actually stopped (for cancel/timeout outcomes).
    pub stopped: bool,
    /// The protocol fault, when the command was rejected.
    pub fault: Option<JournalFault>,
    /// The bounded kind-specific result payload (UTF-8 JSON).
    pub payload: String,
}

/// A replayed protocol fault.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalFault {
    /// The stable fault code, as a number (the wire enum's value).
    pub code: i32,
    /// The Fleet-owned fault summary.
    pub message: String,
}

/// A journal problem: the detail is safe to print (paths and parse state,
/// never command payloads).
#[derive(Debug)]
pub enum JournalError {
    /// The journal file could not be opened, written, or synced.
    Io {
        /// What the OS reported.
        detail: String,
    },
    /// The compaction rewrite failed; the original journal is untouched.
    Rewrite {
        /// What the OS reported.
        detail: String,
    },
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { detail } => write!(f, "journal io failed: {detail}"),
            Self::Rewrite { detail } => write!(f, "journal compaction failed: {detail}"),
        }
    }
}

impl std::error::Error for JournalError {}

/// The open journal. Cloning shares the same records and file handle
/// semantics through `Arc` at the call sites that need it; the type itself
/// is used behind `Arc<NodeJournal>`.
pub struct NodeJournal {
    path: PathBuf,
    records: Mutex<HashMap<String, JournalRecord>>,
    append: Mutex<std::fs::File>,
    since_compaction: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for NodeJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Record contents never render: they are command results.
        f.debug_struct("NodeJournal")
            .field("path", &self.path)
            .field("records", &self.records.lock().expect("uncontended").len())
            .finish_non_exhaustive()
    }
}

impl NodeJournal {
    /// Opens (creating if needed) the journal at `path`, loading its
    /// records and healing a torn tail.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be opened, read, or repaired.
    pub fn open(path: &Path) -> Result<Self, JournalError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| JournalError::Io {
                detail: error.to_string(),
            })?;
        }
        let text = match std::fs::read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => {
                return Err(JournalError::Io {
                    detail: error.to_string(),
                });
            }
        };

        let mut records = HashMap::new();
        let mut good_bytes = 0_usize;
        for line in text.lines() {
            match serde_json::from_str::<JournalRecord>(line) {
                Ok(record) => {
                    records.insert(record.operation_id.clone(), record);
                    good_bytes += line.len() + 1;
                }
                Err(_) => break,
            }
        }
        // A torn tail (a crash mid-append) is truncated: every complete
        // line survived, the partial one never made it to a record.
        if good_bytes < text.len() {
            std::fs::write(path, &text.as_bytes()[..good_bytes]).map_err(|error| {
                JournalError::Io {
                    detail: error.to_string(),
                }
            })?;
            eprintln!("fleetd: truncated a torn journal tail ({good_bytes} bytes kept)");
        }

        let append = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| JournalError::Io {
                detail: error.to_string(),
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            records: Mutex::new(records),
            append: Mutex::new(append),
            since_compaction: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// The journal's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The number of live records — one per operation id ever seen. This is
    /// the value reported as the heartbeat's journal position.
    ///
    /// # Panics
    ///
    /// Panics only if the journal's mutex is poisoned by a panic while
    /// holding it, which no code path does.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.lock().expect("uncontended").len()
    }

    /// Whether the command is accepted but has no terminal result yet.
    ///
    /// # Panics
    ///
    /// Panics only if the journal's mutex is poisoned by a panic while
    /// holding it, which no code path does.
    #[must_use]
    pub fn is_in_flight(&self, operation_id: &str) -> bool {
        self.records
            .lock()
            .expect("uncontended")
            .get(operation_id)
            .is_some_and(|record| record.result.is_none())
    }

    /// The terminal result recorded for a command, when any. This is the
    /// dedupe answer: a record here means the command never re-executes.
    ///
    /// # Panics
    ///
    /// Panics only if the journal's mutex is poisoned by a panic while
    /// holding it, which no code path does.
    #[must_use]
    pub fn terminal_result(&self, operation_id: &str) -> Option<JournalResult> {
        self.records
            .lock()
            .expect("uncontended")
            .get(operation_id)
            .and_then(|record| record.result.clone())
    }

    /// Records the acceptance of a command before any work starts.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be appended or synced.
    pub fn record_accepted(&self, operation_id: &str, kind: &str) -> Result<(), JournalError> {
        let record = JournalRecord {
            operation_id: operation_id.to_owned(),
            kind: kind.to_owned(),
            accepted_at: fleet_core::SystemClock::now_unix_millis(),
            result: None,
        };
        self.append_record(&record)
    }

    /// Records the terminal result of a command.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be appended or synced.
    ///
    /// # Panics
    ///
    /// Panics only if the journal's mutex is poisoned by a panic while
    /// holding it, which no code path does.
    pub fn record_result(
        &self,
        operation_id: &str,
        result: JournalResult,
    ) -> Result<(), JournalError> {
        let record = {
            let mut records = self.records.lock().expect("uncontended");
            let record = records
                .get_mut(operation_id)
                .ok_or_else(|| JournalError::Io {
                    detail: format!("no accepted record for operation {operation_id}"),
                })?;
            record.result = Some(result);
            record.clone()
        };
        self.append_record(&record)
    }

    fn append_record(&self, record: &JournalRecord) -> Result<(), JournalError> {
        // The in-memory index and the durable line move together.
        self.records
            .lock()
            .expect("uncontended")
            .insert(record.operation_id.clone(), record.clone());
        let line = serde_json::to_string(record).map_err(|error| JournalError::Io {
            detail: error.to_string(),
        })?;
        {
            let mut file = self.append.lock().expect("uncontended");
            writeln!(file, "{line}").map_err(|error| JournalError::Io {
                detail: error.to_string(),
            })?;
            file.sync_all().map_err(|error| JournalError::Io {
                detail: error.to_string(),
            })?;
        }
        // Compaction is append-driven, not record-driven: it fires roughly
        // once per threshold appends, not on every append once the record
        // count is past the threshold.
        let since = self
            .since_compaction
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if since >= COMPACTION_THRESHOLD {
            self.since_compaction
                .store(0, std::sync::atomic::Ordering::Relaxed);
            self.compact()?;
        }
        Ok(())
    }

    /// Rewrites the journal keeping only the newest record per operation
    /// id, atomically: write a temporary file, sync it, rename over the
    /// original. A crash mid-rewrite leaves the original intact.
    fn compact(&self) -> Result<(), JournalError> {
        let mut lines = Vec::new();
        {
            let records = self.records.lock().expect("uncontended");
            for record in records.values() {
                let line = serde_json::to_string(record).map_err(|error| JournalError::Io {
                    detail: error.to_string(),
                })?;
                lines.push(line);
            }
        }
        let temporary = self.path.with_extension("compact");
        {
            let mut file =
                std::fs::File::create(&temporary).map_err(|error| JournalError::Rewrite {
                    detail: error.to_string(),
                })?;
            for line in &lines {
                writeln!(file, "{line}").map_err(|error| JournalError::Rewrite {
                    detail: error.to_string(),
                })?;
            }
            file.sync_all().map_err(|error| JournalError::Rewrite {
                detail: error.to_string(),
            })?;
        }
        std::fs::rename(&temporary, &self.path).map_err(|error| JournalError::Rewrite {
            detail: error.to_string(),
        })?;
        let reopened = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|error| JournalError::Rewrite {
                detail: error.to_string(),
            })?;
        *self.append.lock().expect("uncontended") = reopened;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> (tempfile::TempDir, NodeJournal) {
        let dir = tempfile::tempdir().unwrap();
        let journal = NodeJournal::open(&dir.path().join("journal.ndjson")).unwrap();
        (dir, journal)
    }

    fn result(status: &str) -> JournalResult {
        JournalResult {
            status: status.to_owned(),
            exit_code: Some(0),
            output_truncated: false,
            duration_millis: 1,
            stopped: true,
            fault: None,
            payload: "{\"kind\":\"node.noop\"}".to_owned(),
        }
    }

    #[test]
    fn acceptance_is_durable_before_the_result() {
        let (_dir, journal) = journal();
        journal.record_accepted("op-1", "node.noop").unwrap();
        assert!(journal.is_in_flight("op-1"));
        assert!(journal.terminal_result("op-1").is_none());
        assert_eq!(journal.record_count(), 1);

        journal.record_result("op-1", result("succeeded")).unwrap();
        assert!(!journal.is_in_flight("op-1"));
        let replayed = journal.terminal_result("op-1").unwrap();
        assert_eq!(replayed.status, "succeeded");
    }

    #[test]
    fn a_reopened_journal_serves_its_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ndjson");
        {
            let journal = NodeJournal::open(&path).unwrap();
            journal.record_accepted("op-1", "node.noop").unwrap();
            journal.record_result("op-1", result("succeeded")).unwrap();
            journal.record_accepted("op-2", "node.diagnostic").unwrap();
        }
        let reopened = NodeJournal::open(&path).unwrap();
        assert_eq!(reopened.record_count(), 2);
        assert_eq!(
            reopened.terminal_result("op-1").unwrap().status,
            "succeeded"
        );
        assert!(reopened.is_in_flight("op-2"));
    }

    #[test]
    fn a_torn_tail_is_truncated_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ndjson");
        {
            let journal = NodeJournal::open(&path).unwrap();
            journal.record_accepted("op-1", "node.noop").unwrap();
        }
        // Simulate a crash mid-append: a complete record plus a partial one.
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!("{text}{{\"operationId\":\"op-2\",\"kind\":\"node.no"),
        )
        .unwrap();
        let journal = NodeJournal::open(&path).unwrap();
        assert_eq!(journal.record_count(), 1);
        // The file on disk no longer carries the partial line.
        let healed = std::fs::read_to_string(&path).unwrap();
        assert!(!healed.contains("op-2"), "{healed}");
    }

    #[test]
    fn compaction_keeps_the_newest_record_per_operation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ndjson");
        let journal = NodeJournal::open(&path).unwrap();
        for index in 0..(COMPACTION_THRESHOLD + 10) {
            let operation_id = format!("op-{index}");
            journal.record_accepted(&operation_id, "node.noop").unwrap();
            journal
                .record_result(&operation_id, result("succeeded"))
                .unwrap();
        }
        assert_eq!(journal.record_count(), COMPACTION_THRESHOLD + 10);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines = text.lines().count();
        // Compaction fires roughly once per threshold appends; the file
        // stays bounded by records plus one un-compacted window.
        assert!(
            lines <= COMPACTION_THRESHOLD + 10 + COMPACTION_THRESHOLD,
            "the journal stays bounded: {lines} lines"
        );
        // Every record survived with its result.
        let reopened = NodeJournal::open(&path).unwrap();
        for index in 0..(COMPACTION_THRESHOLD + 10) {
            let operation_id = format!("op-{index}");
            assert_eq!(
                reopened.terminal_result(&operation_id).unwrap().status,
                "succeeded"
            );
        }
    }
}
