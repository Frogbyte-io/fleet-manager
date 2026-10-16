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
            ("deny", "--note") => note = Some(value("note")?),
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

/// Waits for the request's outcome: reads it (through `fetch`, which
/// answers the request object) with exponential backoff until it reaches a
/// final state or `bound` has passed, and answers `(outcome, request)`.
/// A request still `pending`, `approved`, or `executing` at the bound is
/// [`Outcome::StillPending`]; the bound never makes the wait hang and never
/// cancels the request. `sleep` pauses between reads (a test passes a
/// recorder).
///
/// # Errors
///
/// Fails when a read fails.
pub fn poll_outcome(
    mut fetch: impl FnMut() -> Result<Value, CliError>,
    bound: Duration,
    mut sleep: impl FnMut(Duration),
) -> Result<(Outcome, Value), CliError> {
    let started = Instant::now();
    // The time spent is the larger of the wall clock and the pauses asked
    // for, so a slow controller cannot stretch the bound and an injected
    // `sleep` that returns at once still ends the wait.
    let mut slept = Duration::ZERO;
    let mut interval = MIN_POLL_INTERVAL;
    loop {
        let request = fetch()?;
        if let Some(outcome) = request["state"].as_str().and_then(Outcome::of_state) {
            return Ok((outcome, request));
        }
        let remaining = bound.saturating_sub(started.elapsed().max(slept));
        if remaining.is_zero() {
            return Ok((Outcome::StillPending, request));
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
/// Fails when a read is refused or the controller does not answer.
pub fn wait_for_outcome(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    id: &str,
    bound: Duration,
) -> Result<(Outcome, Value), CliError> {
    poll_outcome(
        || {
            let (method, path, query, body) = request(&RequestsAction::Get {
                id: id.to_owned(),
                wait: None,
            });
            let answer = crate::send(
                client,
                invocation,
                method,
                &path,
                &query,
                body.as_ref(),
                uuid::Uuid::now_v7().to_string(),
            )?;
            Ok(answer.get("data").cloned().unwrap_or(answer))
        },
        bound,
        std::thread::sleep,
    )
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
