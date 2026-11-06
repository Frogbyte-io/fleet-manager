//! `fleetctl lab hardware` (FM-1126, M11): mid-run hotplug of a USB device a
//! Lab lease reserved.
//!
//! - `lab hardware attach <lease-id> <mapping> [--output json|text]` posts
//!   `POST /api/v1/lab/leases/{id}/hardware/attach`.
//! - `lab hardware detach <lease-id> <mapping> [--release] [--output
//!   json|text]` posts `POST /api/v1/lab/leases/{id}/hardware/detach`. The
//!   lease keeps the device reserved unless `--release` is given.
//!
//! The controller decides everything (who may act, which devices, what PVE
//! did); with `--output json` this adapter prints the controller's `data`
//! unchanged. A `detach_pending` answer, in which PVE keeps the device on the
//! guest until it restarts, exits with status 2: the device is still
//! attached. Any refusal exits non-zero through the usual error path.

use serde_json::{Value, json};

use crate::{CliError, Command, Output, RequestShape, usage};

/// One `lab hardware` subcommand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabHardwareAction {
    /// Attach a device the lease reserved to its running guest.
    Attach {
        /// The lease.
        lease_id: String,
        /// The PVE USB resource mapping id.
        mapping: String,
    },
    /// Detach a device from the lease's running guest.
    Detach {
        /// The lease.
        lease_id: String,
        /// The PVE USB resource mapping id.
        mapping: String,
        /// Also give the device up after the read-back confirms it is gone.
        release: bool,
    },
}

/// Parses `lab hardware attach|detach ...` (the words after `lab hardware`).
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((verb, args)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    if !matches!(*verb, "attach" | "detach") {
        return Err(CliError { message: usage() });
    }
    let mut positional: Vec<&str> = Vec::new();
    let mut release = false;
    let mut flags = args.iter().copied();
    while let Some(arg) = flags.next() {
        match arg {
            "--release" if *verb == "detach" => release = true,
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
    let [lease_id, mapping] = positional.as_slice() else {
        return Err(CliError {
            message: format!(
                "lab hardware {verb} needs <lease-id> <mapping>; see the usage below\n\n{}",
                usage()
            ),
        });
    };
    let (lease_id, mapping) = ((*lease_id).to_owned(), (*mapping).to_owned());
    Ok(Command::LabHardware(match *verb {
        "attach" => LabHardwareAction::Attach { lease_id, mapping },
        _ => LabHardwareAction::Detach {
            lease_id,
            mapping,
            release,
        },
    }))
}

/// The controller request for one subcommand.
pub(crate) fn request(action: &LabHardwareAction) -> RequestShape {
    match action {
        LabHardwareAction::Attach { lease_id, mapping } => (
            reqwest::Method::POST,
            format!("/api/v1/lab/leases/{lease_id}/hardware/attach"),
            Vec::new(),
            Some(json!({ "mapping": mapping })),
        ),
        LabHardwareAction::Detach {
            lease_id,
            mapping,
            release,
        } => (
            reqwest::Method::POST,
            format!("/api/v1/lab/leases/{lease_id}/hardware/detach"),
            Vec::new(),
            Some(json!({ "mapping": mapping, "release": release })),
        ),
    }
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

/// Renders an answer as human text.
pub(crate) fn render(payload: &Value) -> String {
    let outcome = text(&payload["outcome"]);
    let mut lines = vec![format!(
        "{} on lease {}: {outcome}",
        text(&payload["mapping"]),
        text(&payload["leaseId"]),
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
                "  PVE keeps the device on the guest until it restarts (its hotplug option lacks usb): it is still attached"
            }
            "detached" | "already_detached" if payload["released"] == true => {
                "  the lease gave the device up"
            }
            "detached" | "already_detached" => {
                "  the lease still holds the device until it is released; attach it again with `lab hardware attach`"
            }
            _ => "  the guest has the device",
        }
        .to_owned(),
    );
    lines.join("\n")
}
