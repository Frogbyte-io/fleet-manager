//! `fleetctl requests` (FM-1041): the action broker's approval inbox from
//! the command line, and the bounded wait for a decision that provider
//! action commands reuse.
//!
//! The commands are adapters over `/api/v1/requests`; authorization, policy,
//! and audit are the controller's. `requests get <id> --wait[=<duration>]`
//! polls until the request reaches an outcome or the bound passes, and
//! answers a JSON outcome (see [`Outcome`]). A provider action command that
//! creates a request calls [`wait_for_outcome`] with the duration
//! [`parse_wait_approval`] read from its `--wait-approval[=<duration>]`.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::{CliError, Command, Invocation, Output, RequestShape, usage};

/// The longest a wait may be asked to last.
pub const MAX_WAIT: Duration = Duration::from_hours(1);
/// How long a bare `--wait` waits.
pub const DEFAULT_WAIT: Duration = Duration::from_mins(5);
/// The first poll interval; it doubles up to [`MAX_POLL_INTERVAL`].
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// The longest one read may take, however much of the wait is left.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest pause between polls.
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// One `requests` subcommand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestsAction {
    /// List requests, newest first.
    List {
        /// Only requests in this state.
        state: Option<String>,
        /// The page size.
        limit: Option<u32>,
    },
    /// Read one request, optionally waiting for its outcome.
    Get {
        /// The request's identity.
        id: String,
        /// Wait at most this long for an outcome.
        wait: Option<Duration>,
    },
    /// Approve a pending request.
    Approve {
        /// The request's identity.
        id: String,
    },
    /// Deny a pending request.
    Deny {
        /// The request's identity.
        id: String,
        /// Why.
        note: Option<String>,
    },
}

/// What a wait ended with. The JSON form is the `outcome` field of the
/// answer: `executed` (the action's operation succeeded), `denied` (a
/// person or policy refused it), `expired` (no decision before the
/// deadline), `failed` (it was approved but the operation failed or could
/// not start), or `still_pending` (the bound passed first; the request is
/// durable and a later `requests get` reports what became of it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The action ran and succeeded.
    Executed,
    /// The request was denied.
    Denied,
    /// The request expired undecided.
    Expired,
    /// The request was approved and then failed.
    Failed,
    /// The request had no outcome yet when the wait ended.
    StillPending,
}

impl Outcome {
    /// The stable name in the JSON answer.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::StillPending => "still_pending",
        }
    }

    /// The process exit code: 0 executed, 2 still pending (the caller may
    /// wait again), 1 otherwise.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Executed => 0,
            Self::StillPending => 2,
            Self::Denied | Self::Expired | Self::Failed => 1,
        }
    }

    /// The outcome a request state is final for, or `None` while the
    /// request may still change (`pending`, `approved`, `executing`).
    #[must_use]
    pub fn of_state(state: &str) -> Option<Self> {
        match state {
            "succeeded" => Some(Self::Executed),
            "denied" => Some(Self::Denied),
            "expired" => Some(Self::Expired),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Parses a wait duration: whole seconds (`90`) or a number with an `s`,
/// `m`, or `h` suffix (`30s`, `5m`, `1h`). It must be at least one second
/// and at most [`MAX_WAIT`].
///
/// # Errors
///
/// Fails on a malformed, zero, or too-long duration.
pub fn parse_duration(raw: &str) -> Result<Duration, CliError> {
    let bad = || CliError {
        message: format!("the wait must be 1s to 1h (for example 90, 30s, 5m, 1h), not {raw:?}"),
    };
    let (digits, unit) = if let Some(digits) = raw.strip_suffix('s') {
        (digits, 1)
    } else if let Some(digits) = raw.strip_suffix('m') {
        (digits, 60)
    } else if let Some(digits) = raw.strip_suffix('h') {
        (digits, 3600)
    } else {
        (raw, 1)
    };
    let seconds = digits
        .parse::<u64>()
        .ok()
        .and_then(|count| count.checked_mul(unit))
        .ok_or_else(bad)?;
    let wait = Duration::from_secs(seconds);
    if wait.is_zero() || wait > MAX_WAIT {
        return Err(bad());
    }
    Ok(wait)
}

/// Reads one `--wait-approval[=<duration>]` (or `--wait[=<duration>]`)
/// argument: `Some(duration)` when `arg` is the flag named `flag`, `None`
/// when it is some other argument. A bare flag waits [`DEFAULT_WAIT`].
///
/// # Errors
///
/// Fails when the duration is malformed or out of bounds.
pub fn parse_wait_approval(flag: &str, arg: &str) -> Result<Option<Duration>, CliError> {
    if arg == flag {
        return Ok(Some(DEFAULT_WAIT));
    }
    match arg
        .strip_prefix(flag)
        .and_then(|rest| rest.strip_prefix('='))
    {
        Some(raw) => parse_duration(raw).map(Some),
        None => Ok(None),
    }
}

/// Parses `requests list|get|approve|deny ...`.
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((verb, args)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    let (id, flags) = match *verb {
        "get" | "approve" | "deny" => {
            let Some((id, flags)) = args.split_first() else {
                return Err(CliError { message: usage() });
            };
            // An empty id or a leading `-` is a flag or a typo, never an id.
            if id.is_empty() || id.starts_with('-') {
                return Err(CliError { message: usage() });
            }
            (Some((*id).to_owned()), flags)
        }
        "list" => (None, args),
        _ => return Err(CliError { message: usage() }),
    };
    let mut state = None;
    let mut limit = None;
    let mut note = None;
    let mut wait = None;
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        if *verb == "get"
            && let Some(duration) = parse_wait_approval("--wait", flag)?
        {
            wait = Some(duration);
            continue;
        }
        let mut value = |name: &str| {
            flags
                .next()
                .filter(|candidate| !candidate.starts_with("--"))
                .map(str::to_owned)
                .ok_or_else(|| CliError {
                    message: format!("--{name} requires a value"),
                })
        };
        match (*verb, flag) {
            (_, "--output") => {
                *output = match value("output")?.as_str() {
                    "json" => Output::Json,
                    "text" => Output::Text,
                    other => {
                        return Err(CliError {
                            message: format!("--output must be json or text, not {other:?}"),
                        });
                    }
                };
            }
            ("list", "--state") => state = Some(value("state")?),
            ("list", "--limit") => {
                let raw = value("limit")?;
                limit = Some(raw.parse().map_err(|_| CliError {
                    message: format!("--limit must be a number, not {raw:?}"),
                })?);
            }
            // A blank note is no note: it is trimmed and left out of the body.
            ("deny", "--note") => {
                note = Some(value("note")?.trim().to_owned()).filter(|note| !note.is_empty());
            }
            (_, other) => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let action = match (*verb, id) {
        ("list", _) => RequestsAction::List { state, limit },
        ("get", Some(id)) => RequestsAction::Get { id, wait },
        ("approve", Some(id)) => RequestsAction::Approve { id },
        ("deny", Some(id)) => RequestsAction::Deny { id, note },
        _ => return Err(CliError { message: usage() }),
    };
    Ok(Command::Requests(action))
}

/// The controller request for one subcommand.
pub(crate) fn request(action: &RequestsAction) -> RequestShape {
    let base = "/api/v1/requests";
    match action {
        RequestsAction::List { state, limit } => (
            reqwest::Method::GET,
            base.to_owned(),
            state
                .iter()
                .map(|state| ("state", state.clone()))
                .chain(limit.iter().map(|limit| ("limit", limit.to_string())))
                .collect(),
            None,
        ),
        RequestsAction::Get { id, .. } => (
            reqwest::Method::GET,
            format!("{base}/{}", encode(id)),
            Vec::new(),
            None,
        ),
        RequestsAction::Approve { id } => (
            reqwest::Method::POST,
            format!("{base}/{}/approve", encode(id)),
            Vec::new(),
            None,
        ),
        RequestsAction::Deny { id, note } => (
            reqwest::Method::POST,
            format!("{base}/{}/deny", encode(id)),
            Vec::new(),
            note.as_ref().map(|note| json!({ "note": note })),
        ),
    }
}

/// Percent-encodes one path segment: only unreserved characters pass.
fn encode(segment: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// One failed read of a request, and whether a retry may succeed.
#[derive(Debug)]
pub struct ReadFailure {
    /// What went wrong.
    pub error: CliError,
    /// The controller did not answer or answered 5xx; a refusal is not.
    pub transient: bool,
}

/// How many reads in a row may fail transiently and be retried; the next
/// failure ends the wait.
const MAX_TRANSIENT_FAILURES: u32 = 3;

/// Waits for the request's outcome: reads it (through `fetch`, which is
/// given the time left in the wait to cap that one read and answers the
/// request object) with exponential backoff until it reaches a final state
/// or `bound` has passed, and answers `(outcome, request)`. A request still
/// `pending`, `approved`, or `executing` at the bound is
/// [`Outcome::StillPending`]; the bound never makes the wait hang and never
/// cancels the request. Up to [`MAX_TRANSIENT_FAILURES`] consecutive
/// transient read failures are retried on the same backoff; a refusal, or
/// a fourth consecutive transient failure, ends the wait with that error. `sleep`
/// pauses between reads (a test passes a recorder).
///
/// # Errors
///
/// Fails when a read is refused or keeps failing transiently.
pub fn poll_outcome(
    mut fetch: impl FnMut(Duration) -> Result<Value, ReadFailure>,
    bound: Duration,
    mut sleep: impl FnMut(Duration),
) -> Result<(Outcome, Value), CliError> {
    let started = Instant::now();
    // The time spent is the larger of the wall clock and the pauses asked
    // for, so a slow controller cannot stretch the bound and an injected
    // `sleep` that returns at once still ends the wait.
    let mut slept = Duration::ZERO;
    let mut interval = MIN_POLL_INTERVAL;
    let mut failures = 0;
    let mut last_failure = None;
    let mut last_request: Option<Value> = None;
    loop {
        let remaining = bound.saturating_sub(started.elapsed().max(slept));
        let request = match fetch(remaining) {
            Ok(request) => {
                failures = 0;
                last_request = Some(request.clone());
                Some(request)
            }
            Err(failure) => {
                failures += 1;
                if !failure.transient || failures > MAX_TRANSIENT_FAILURES {
                    return Err(failure.error);
                }
                last_failure = Some(failure.error);
                None
            }
        };
        if let Some(request) = &request
            && let Some(outcome) = request["state"].as_str().and_then(Outcome::of_state)
        {
            return Ok((outcome, request.clone()));
        }
        let remaining = bound.saturating_sub(started.elapsed().max(slept));
        if remaining.is_zero() {
            // The last read that did answer stands: a final read cut short
            // by the bound is not a failure of the wait.
            return match last_request {
                Some(request) => Ok((Outcome::StillPending, request)),
                None => Err(last_failure.unwrap_or_else(|| CliError {
                    message: "the wait ended before the controller answered".to_owned(),
                })),
            };
        }
        let pause = interval.min(remaining);
        sleep(pause);
        slept += pause;
        interval = (interval * 2).min(MAX_POLL_INTERVAL);
    }
}

/// The JSON answer of a wait: the outcome beside the request it concerns.
#[must_use]
pub fn outcome_body(outcome: Outcome, request: &Value) -> Value {
    json!({ "outcome": outcome.id(), "request": request })
}

/// Waits for the outcome of request `id` on the controller `invocation`
/// names. This is the helper provider action commands call after creating
/// a request.
///
/// # Errors
///
/// Fails when a read is refused or the controller keeps not answering.
pub fn wait_for_outcome(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    id: &str,
    bound: Duration,
) -> Result<(Outcome, Value), CliError> {
    poll_outcome(
        |remaining| {
            let (method, path, query, body) = request(&RequestsAction::Get {
                id: id.to_owned(),
                wait: None,
            });
            // A read never outlasts what is left of the wait.
            let answer = crate::send_classified(
                client,
                invocation,
                method,
                &path,
                &query,
                body.as_ref(),
                uuid::Uuid::now_v7().to_string(),
                None,
                Some(remaining.min(READ_TIMEOUT)),
            )
            .map_err(|(error, transient)| ReadFailure { error, transient })?;
            Ok(answer.get("data").cloned().unwrap_or(answer))
        },
        bound,
        std::thread::sleep,
    )
}

/// After a brokered request was filed (`dns set`, `services restart`, ...),
/// waits for its outcome when asked and answers the value to render and the
/// exit code. Without a wait the filed request is the answer (exit 0): it is
/// durable, and `requests get <id> --wait` follows it later. With a wait the
/// answer is `{outcome, request, result}`, where `result` is the operation's
/// result. When the request was executed but the result could not be read,
/// `resultWarning` says so (the outcome and exit code still describe the
/// request, which did execute).
///
/// # Errors
///
/// Fails when a read is refused or the controller keeps not answering.
pub(crate) fn finish_filed_request(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    created: &Value,
    wait: Option<Duration>,
) -> Result<(Value, u8), CliError> {
    let request = created.get("data").unwrap_or(created);
    let Some(bound) = wait else {
        return Ok((request.clone(), 0));
    };
    let id = request["id"].as_str().ok_or_else(|| CliError {
        message: "the controller's answer carried no request id".to_owned(),
    })?;
    let (outcome, request) = wait_for_outcome(client, invocation, id, bound)?;
    let mut answer = outcome_body(outcome, &request);
    if outcome == Outcome::Executed
        && let Some(operation_id) = request["operationId"].as_str()
    {
        let read = crate::send_classified(
            client,
            invocation,
            reqwest::Method::GET,
            &format!("/api/v1/operations/{}", encode(operation_id)),
            &[],
            None,
            uuid::Uuid::now_v7().to_string(),
            None,
            Some(Duration::from_secs(30)),
        );
        match read {
            Ok(operation) => {
                let data = operation.get("data").unwrap_or(&operation);
                match data["resultJson"]
                    .as_str()
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
                {
                    Some(result) => answer["result"] = result,
                    None => {
                        answer["resultWarning"] =
                            json!("the operation carried no readable result");
                    }
                }
            }
            Err((error, _)) => {
                answer["resultWarning"] = json!(format!(
                    "the request executed, but its operation result could not be read: {}",
                    clean(&error.message)
                ));
            }
        }
    }
    Ok((answer, outcome.exit_code()))
}

/// Server-supplied text for a terminal: control characters become spaces.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn text_of(value: &Value) -> String {
    clean(value.as_str().unwrap_or("-"))
}

/// Renders a list page, one request, or a wait's answer as human text.
pub(crate) fn render(value: &Value) -> String {
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        if items.is_empty() {
            return "(no requests)".to_owned();
        }
        let mut lines = vec![format!(
            "{:<38} {:<10} {:<8} {:<32} {:<24} REQUESTER",
            "ID", "STATE", "RISK", "ACTION", "TARGET"
        )];
        lines.extend(items.iter().map(row));
        return lines.join("\n");
    }
    if let Some(outcome) = value["outcome"].as_str() {
        let mut lines = vec![format!("outcome: {}", clean(outcome))];
        lines.extend(detail(&value["request"]));
        return lines.join("\n");
    }
    let request = value.get("data").unwrap_or(value);
    if request.get("id").is_none() {
        return String::new();
    }
    detail(request).join("\n")
}

fn row(request: &Value) -> String {
    format!(
        "{:<38} {:<10} {:<8} {:<32} {:<24} {}",
        text_of(&request["id"]),
        text_of(&request["state"]),
        text_of(&request["riskClass"]),
        text_of(&request["actionId"]),
        text_of(&request["target"]),
        text_of(&request["requester"]),
    )
}

fn detail(request: &Value) -> Vec<String> {
    let mut lines = vec![row(request)];
    lines.push(format!("  reason: {}", text_of(&request["reason"])));
    if let Some(by) = request["decidedBy"].as_str() {
        lines.push(format!("  decided by: {}", clean(by)));
    }
    if let Some(note) = request["decisionNote"].as_str() {
        lines.push(format!("  note: {}", clean(note)));
    }
    if let Some(operation) = request["operationId"].as_str() {
        lines.push(format!("  operation: {}", clean(operation)));
    }
    if let Some(failure) = request["failure"].as_str() {
        lines.push(format!("  failure: {}", clean(failure)));
    }
    lines
}
