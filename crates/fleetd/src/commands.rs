//! Node command execution: the two kinds a node can be asked to run.
//!
//! `node.noop` does bounded, observable no work; `node.diagnostic` reports
//! the node's own facts — software version, platform, monotonic uptime, and
//! the journal's size. Neither spawns a process, touches a shell, or reads
//! anything but this daemon's own state: those are distinct, privileged
//! command kinds for later issues, per
//! `docs/architecture/controller-node-protocol.md#commands-and-privilege`.
//!
//! Every execution follows the journal contract: acceptance is recorded
//! before work starts, the result is recorded before it is reported, and a
//! command that already has a terminal result is replayed from the journal
//! instead of re-executed.

use std::sync::Arc;
use std::time::Instant;

use fleet_protocol::wire;

use crate::journal::{JournalFault, JournalResult, NodeJournal};
use crate::state::NodeState;

/// The command kinds this build executes. Anything else is rejected.
pub const SUPPORTED_KINDS: [&str; 2] = ["node.noop", "node.diagnostic"];

/// The result of executing (or refusing) one command.
#[derive(Clone, Debug)]
pub struct CommandOutcome {
    /// The wire result status.
    pub status: wire::ResultStatus,
    /// The bounded payload (UTF-8 JSON for these kinds).
    pub payload: String,
    /// The fault, when the command was rejected before executing.
    pub fault: Option<JournalFault>,
    /// Whether the result payload was truncated.
    pub output_truncated: bool,
}

/// The deadline the command carries, in epoch milliseconds.
#[must_use]
pub fn deadline_passed(deadline_unix_millis: i64) -> bool {
    deadline_unix_millis <= fleet_core::SystemClock::now_unix_millis()
}

/// Executes one command to its outcome, honoring the journal contract.
/// The result is recorded in the journal before being returned, so a crash
/// between execution and reporting still replays the result.
///
/// # Errors
///
/// Fails when the journal refuses a write; the caller then answers with a
/// failed result rather than executing twice on a retry.
pub fn execute(
    journal: &Arc<NodeJournal>,
    state: &Arc<NodeState>,
    command: &wire::Command,
) -> Result<CommandOutcome, String> {
    let operation_id = command.operation_id.as_str();
    if operation_id.is_empty() {
        return Ok(rejected(
            wire::FaultCode::MalformedIdentity,
            "the command carries no operation id",
        ));
    }
    if !SUPPORTED_KINDS.contains(&command.kind.as_str()) {
        // The refusal is journaled as terminal, so a redelivery replays it
        // instead of re-evaluating it.
        let outcome = rejected(
            wire::FaultCode::SessionRejected,
            &format!("the node does not execute {:?} commands", command.kind),
        );
        journal
            .record_accepted(operation_id, &command.kind)
            .map_err(|error| error.to_string())?;
        journal
            .record_result(operation_id, to_journal(&outcome))
            .map_err(|error| error.to_string())?;
        return Ok(outcome);
    }
    // A deadline in the past is a timed-out command that never ran.
    if deadline_passed(command.deadline_unix_millis) {
        let outcome = CommandOutcome {
            status: wire::ResultStatus::TimedOut,
            payload: String::new(),
            fault: None,
            output_truncated: false,
        };
        journal
            .record_accepted(operation_id, &command.kind)
            .map_err(|error| error.to_string())?;
        journal
            .record_result(operation_id, to_journal(&outcome))
            .map_err(|error| error.to_string())?;
        return Ok(outcome);
    }

    // Dedupe: a terminal result replays; an in-flight acceptance ignores
    // the duplicate frame (the original execution will report).
    if let Some(replayed) = journal.terminal_result(operation_id) {
        return Ok(CommandOutcome {
            status: status_from(&replayed.status),
            payload: replayed.payload,
            fault: replayed.fault,
            output_truncated: replayed.output_truncated,
        });
    }
    if journal.is_in_flight(operation_id) {
        return Err(format!(
            "operation {operation_id} is already in flight; its result will be reported by the original execution"
        ));
    }

    journal
        .record_accepted(operation_id, &command.kind)
        .map_err(|error| error.to_string())?;

    let started = Instant::now();
    let outcome = match command.kind.as_str() {
        "node.noop" => CommandOutcome {
            status: wire::ResultStatus::Succeeded,
            payload: serde_json::json!({ "kind": "node.noop" }).to_string(),
            fault: None,
            output_truncated: false,
        },
        "node.diagnostic" => CommandOutcome {
            status: wire::ResultStatus::Succeeded,
            payload: serde_json::json!({
                "nodeVersion": env!("CARGO_PKG_VERSION"),
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "uptimeMillis": state_uptime_millis(),
                "machineId": state.machine_id().unwrap_or_default(),
                "journalRecords": journal.record_count(),
            })
            .to_string(),
            fault: None,
            output_truncated: false,
        },
        other => rejected(
            wire::FaultCode::SessionRejected,
            &format!("the node does not execute {other:?} commands"),
        ),
    };
    // BEST_EFFORT cancellation for these kinds: the work is complete before
    // any cancellation could race it, so it trivially stopped.
    let _ = command.cancellation;

    let journal_result = JournalResult {
        status: status_name(outcome.status),
        exit_code: None,
        output_truncated: outcome.output_truncated,
        duration_millis: i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
        stopped: outcome.status != wire::ResultStatus::Failed,
        fault: outcome.fault.clone(),
        payload: outcome.payload.clone(),
    };
    journal
        .record_result(operation_id, journal_result)
        .map_err(|error| error.to_string())?;
    Ok(outcome)
}

/// The node's monotonic uptime. `Instant` cannot be shared across threads
/// through a static without `OnceLock` gymnastics, so the diagnostic
/// command reports the process wall age tracked from first use.
fn state_uptime_millis() -> i64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static STARTED: OnceLock<Instant> = OnceLock::new();
    let started = STARTED.get_or_init(Instant::now);
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

fn rejected(code: wire::FaultCode, message: &str) -> CommandOutcome {
    CommandOutcome {
        status: wire::ResultStatus::Rejected,
        payload: String::new(),
        fault: Some(JournalFault {
            code: code as i32,
            message: message.to_owned(),
        }),
        output_truncated: false,
    }
}

fn status_name(status: wire::ResultStatus) -> String {
    match status {
        wire::ResultStatus::Succeeded => "succeeded".to_owned(),
        wire::ResultStatus::Cancelled => "cancelled".to_owned(),
        wire::ResultStatus::TimedOut => "timed_out".to_owned(),
        wire::ResultStatus::Rejected => "rejected".to_owned(),
        wire::ResultStatus::Failed | wire::ResultStatus::Unspecified => "failed".to_owned(),
    }
}

fn status_from(name: &str) -> wire::ResultStatus {
    match name {
        "succeeded" => wire::ResultStatus::Succeeded,
        "cancelled" => wire::ResultStatus::Cancelled,
        "timed_out" => wire::ResultStatus::TimedOut,
        "rejected" => wire::ResultStatus::Rejected,
        _ => wire::ResultStatus::Failed,
    }
}

fn to_journal(outcome: &CommandOutcome) -> JournalResult {
    JournalResult {
        status: status_name(outcome.status),
        exit_code: None,
        output_truncated: outcome.output_truncated,
        duration_millis: 0,
        stopped: outcome.status != wire::ResultStatus::Failed,
        fault: outcome.fault.clone(),
        payload: outcome.payload.clone(),
    }
}

/// Builds the wire result for an outcome.
#[must_use]
pub fn to_wire(operation_id: &str, outcome: &CommandOutcome) -> wire::CommandResult {
    wire::CommandResult {
        operation_id: operation_id.to_owned(),
        status: outcome.status as i32,
        exit_code: 0,
        output_truncated: outcome.output_truncated,
        duration_millis: 0,
        stopped: outcome.status != wire::ResultStatus::Failed,
        fault: outcome.fault.as_ref().map(|fault| wire::Fault {
            code: fault.code,
            message: fault.message.clone(),
            retry: wire::FaultRetry::Never as i32,
            supported_protocol_versions: None,
        }),
        payload: outcome.payload.clone().into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> (tempfile::TempDir, Arc<NodeJournal>) {
        let dir = tempfile::tempdir().unwrap();
        let journal = Arc::new(NodeJournal::open(&dir.path().join("journal.ndjson")).unwrap());
        (dir, journal)
    }

    fn state() -> Arc<NodeState> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        Arc::new(NodeState::open(dir.path()).unwrap())
    }

    fn command(kind: &str, operation_id: &str) -> wire::Command {
        wire::Command {
            operation_id: operation_id.to_owned(),
            kind: kind.to_owned(),
            kind_schema_version: 1,
            deadline_unix_millis: i64::MAX,
            idempotency_key: String::new(),
            authorization_digest: String::new(),
            max_output_bytes: 256 * 1024,
            cancellation: wire::CancellationPolicy::BestEffort as i32,
            payload: Vec::new(),
        }
    }

    #[test]
    fn an_unknown_kind_is_rejected_without_execution() {
        let (_dir, journal) = journal();
        let state = state();
        let outcome = execute(&journal, &state, &command("shell.exec", "op-x")).unwrap();
        assert_eq!(outcome.status, wire::ResultStatus::Rejected);
        assert!(outcome.fault.is_some());
        // A rejected command is journaled as terminal, so a redelivery
        // replays the refusal instead of re-evaluating it.
        assert_eq!(journal.terminal_result("op-x").unwrap().status, "rejected");
    }

    #[test]
    fn an_expired_deadline_times_out_without_executing() {
        let (_dir, journal) = journal();
        let state = state();
        let mut expired = command("node.noop", "op-y");
        expired.deadline_unix_millis = 0;
        let outcome = execute(&journal, &state, &expired).unwrap();
        assert_eq!(outcome.status, wire::ResultStatus::TimedOut);
        assert_eq!(journal.terminal_result("op-y").unwrap().status, "timed_out");
    }

    #[test]
    fn a_replayed_result_never_re_executes() {
        let (_dir, journal) = journal();
        let state = state();
        let first = execute(&journal, &state, &command("node.noop", "op-z")).unwrap();
        let replay = execute(&journal, &state, &command("node.noop", "op-z")).unwrap();
        assert_eq!(first.status, wire::ResultStatus::Succeeded);
        assert_eq!(replay.status, wire::ResultStatus::Succeeded);
        assert_eq!(replay.payload, first.payload, "the journal replayed it");
    }

    #[test]
    fn an_in_flight_command_refuses_a_duplicate_rather_than_restarting() {
        let (_dir, journal) = journal();
        let state = state();
        // Acceptance without a result stands in for a command that is
        // executing right now.
        journal.record_accepted("op-flight", "node.noop").unwrap();
        let error = execute(&journal, &state, &command("node.noop", "op-flight"))
            .expect_err("a duplicate in flight is refused");
        assert!(error.contains("already in flight"), "{error}");
    }

    #[test]
    fn the_diagnostic_result_carries_bounded_facts() {
        let (_dir, journal) = journal();
        let state = state();
        let outcome = execute(&journal, &state, &command("node.diagnostic", "op-d")).unwrap();
        assert_eq!(outcome.status, wire::ResultStatus::Succeeded);
        let facts: serde_json::Value = serde_json::from_str(&outcome.payload).unwrap();
        assert_eq!(facts["os"], std::env::consts::OS);
        assert!(facts["journalRecords"].as_i64().unwrap() >= 1);
        assert!(outcome.payload.len() < 4096);
    }
}
