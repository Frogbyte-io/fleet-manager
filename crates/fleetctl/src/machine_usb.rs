//! `fleetctl machines usb` (FM-1125, M11): attach a USB device to a persistent
//! machine's guest and give it back.
//!
//! - `machines usb attach <machine-id> --mapping <id> [--yes] [--review-only]
//!   [--output json|text]` reviews the attach
//!   (`POST /api/v1/machines/{id}/usb/attach/review`), asks for confirmation
//!   (`--yes` skips it) and runs it with the review token
//!   (`POST /api/v1/machines/{id}/usb/attach`).
//! - `machines usb detach <machine-id> --mapping <id> [--yes] [--review-only]
//!   [--output json|text]` does the same for `.../usb/detach/review` and
//!   `.../usb/detach`; a confirmed detach releases the machine's reservation.
//!
//! The controller decides everything (who may act, which guest, what PVE
//! did); with `--output json` this adapter prints the controller's `data`
//! unchanged. A `detach_pending` answer, in which PVE keeps the device on the
//! guest until it restarts, exits with status 2: the device is still
//! attached and still reserved. Any refusal exits non-zero through the usual
//! error path.

use serde_json::{Value, json};

use crate::{CliError, Command, Invocation, Output, RequestShape, usage};

/// One `machines usb` subcommand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineUsbAction {
    /// Attach a device to the machine's guest and reserve it.
    Attach(MachineUsbArgs),
    /// Detach a device from the machine's guest and release it.
    Detach(MachineUsbArgs),
}

/// The arguments both subcommands take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineUsbArgs {
    /// The machine.
    pub machine_id: String,
    /// The PVE USB resource mapping id.
    pub mapping: String,
    /// Skip the confirmation.
    pub yes: bool,
    /// Print the review and stop.
    pub review_only: bool,
}

impl MachineUsbAction {
    fn args(&self) -> &MachineUsbArgs {
        match self {
            Self::Attach(args) | Self::Detach(args) => args,
        }
    }

    fn verb(&self) -> &'static str {
        match self {
            Self::Attach(_) => "attach",
            Self::Detach(_) => "detach",
        }
    }
}

/// Parses `machines usb attach|detach ...` (the words after `machines usb`).
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((verb, args)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    if !matches!(*verb, "attach" | "detach") {
        return Err(CliError { message: usage() });
    }
    let mut positional: Vec<&str> = Vec::new();
    let (mut mapping, mut yes, mut review_only) = (None, false, false);
    let mut flags = args.iter().copied();
    while let Some(arg) = flags.next() {
        match arg {
            "--yes" => yes = true,
            "--review-only" => review_only = true,
            "--mapping" => {
                mapping = Some(
                    flags
                        .next()
                        .filter(|candidate| !candidate.starts_with("--"))
                        .ok_or_else(|| CliError {
                            message: "--mapping requires a value".to_owned(),
                        })?
                        .to_owned(),
                );
            }
            "--output" => {
                let value = flags
                    .next()
                    .filter(|candidate| !candidate.starts_with("--"))
                    .ok_or_else(|| CliError {
                        message: "--output requires a value".to_owned(),
                    })?;
                *output = match value {
                    "json" => Output::Json,
                    "text" => Output::Text,
                    other => {
                        return Err(CliError {
                            message: format!("--output must be json or text, not {other:?}"),
                        });
                    }
                };
            }
            flag if flag.starts_with("--") => {
                return Err(CliError {
                    message: format!("unknown flag {flag:?}; see the usage below\n\n{}", usage()),
                });
            }
            word => positional.push(word),
        }
    }
    let ([machine_id], Some(mapping)) = (positional.as_slice(), mapping) else {
        return Err(CliError {
            message: format!(
                "machines usb {verb} needs <machine-id> and --mapping <id>; see the usage below\n\n{}",
                usage()
            ),
        });
    };
    let args = MachineUsbArgs {
        machine_id: (*machine_id).to_owned(),
        mapping,
        yes,
        review_only,
    };
    Ok(Command::MachineUsb(match *verb {
        "attach" => MachineUsbAction::Attach(args),
        _ => MachineUsbAction::Detach(args),
    }))
}

/// The first controller request of a subcommand: its review.
pub(crate) fn request(action: &MachineUsbAction) -> RequestShape {
    let args = action.args();
    (
        reqwest::Method::POST,
        format!(
            "/api/v1/machines/{}/usb/{}/review",
            args.machine_id,
            action.verb()
        ),
        Vec::new(),
        Some(json!({ "mapping": args.mapping })),
    )
}

/// The exit status an answer implies: a pending detach left the device on
/// the guest, so it is not a plain success.
pub(crate) fn exit_code(payload: &Value) -> u8 {
    if payload["outcome"] == "detach_pending" {
        2
    } else {
        0
    }
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("-")
}

/// What the confirmation asks, from the review.
fn question(action: &MachineUsbAction, review: &Value) -> String {
    let args = action.args();
    match action {
        MachineUsbAction::Attach(_) => format!(
            "Attach {} to machine {}'s guest {} (VMID {} on node {}) and reserve it for the machine until it is detached?",
            args.mapping,
            args.machine_id,
            text(&review["guest"]["name"]),
            review["guest"]["vmid"],
            text(&review["guest"]["node"]),
        ),
        MachineUsbAction::Detach(_) => format!(
            "Detach {} from machine {} (reservation {} is {}) and release it?",
            args.mapping,
            args.machine_id,
            text(&review["reservation"]["id"]),
            text(&review["reservation"]["state"]),
        ),
    }
}

/// Reviews, confirms and runs one subcommand. Answers the rendered payload
/// and the exit code.
pub(crate) fn run(
    invocation: &Invocation,
    action: &MachineUsbAction,
) -> Result<(String, u8), CliError> {
    let args = action.args();
    let client = crate::http_client()?;
    let base = format!("/api/v1/machines/{}/usb/{}", args.machine_id, action.verb());
    let reviewed = crate::send(
        &client,
        invocation,
        reqwest::Method::POST,
        &format!("{base}/review"),
        &[],
        Some(&json!({ "mapping": args.mapping })),
        uuid::Uuid::now_v7().to_string(),
    )?;
    if args.review_only {
        return Ok((crate::render(invocation, &reviewed["data"]), 0));
    }
    let token = reviewed["data"]["reviewToken"]
        .as_str()
        .ok_or_else(|| CliError {
            message: "the review did not answer with a token".to_owned(),
        })?;
    crate::persistent::confirm(args.yes, &question(action, &reviewed["data"]))?;
    let done = crate::send(
        &client,
        invocation,
        reqwest::Method::POST,
        &base,
        &[],
        Some(&json!({ "mapping": args.mapping, "reviewToken": token })),
        uuid::Uuid::now_v7().to_string(),
    )?;
    let payload = &done["data"];
    Ok((crate::render(invocation, payload), exit_code(payload)))
}

/// Renders an answer or a review as human text.
pub(crate) fn render(payload: &Value) -> String {
    if payload.get("reviewToken").is_some() {
        return render_review(payload);
    }
    let outcome = text(&payload["outcome"]);
    let mut lines = vec![format!(
        "{} on machine {}: {outcome}",
        text(&payload["mapping"]),
        text(&payload["machineId"]),
    )];
    let state = text(&payload["reservationState"]);
    let slot = payload["usbSlot"]
        .as_str()
        .map_or(String::new(), |slot| format!(", in {slot}"));
    lines.push(format!(
        "  reservation {} is {state}{slot}",
        text(&payload["reservationId"])
    ));
    lines.push(
        match outcome {
            "detach_pending" => {
                "  PVE keeps the device on the guest until it restarts (its hotplug option lacks usb): it is still attached and still reserved by the machine; detach again after the restart"
            }
            "detached" | "already_detached" => "  the machine gave the device up",
            _ => "  the guest has the device; the machine holds it until `machines usb detach`",
        }
        .to_owned(),
    );
    lines.join("\n")
}

fn render_review(payload: &Value) -> String {
    let mut lines = vec![format!(
        "review of {} {} on machine {}",
        text(&payload["action"]),
        text(&payload["mapping"]),
        text(&payload["machineId"]),
    )];
    if payload["guest"].is_object() {
        lines.push(format!(
            "  guest {} (VMID {} on node {}, account {})",
            text(&payload["guest"]["name"]),
            payload["guest"]["vmid"],
            text(&payload["guest"]["node"]),
            text(&payload["guest"]["accountId"]),
        ));
    }
    if payload["reservation"].is_object() {
        lines.push(format!(
            "  reservation {} is {}",
            text(&payload["reservation"]["id"]),
            text(&payload["reservation"]["state"]),
        ));
    }
    lines.push(format!("  review token {}", text(&payload["reviewToken"])));
    lines.join("\n")
}
