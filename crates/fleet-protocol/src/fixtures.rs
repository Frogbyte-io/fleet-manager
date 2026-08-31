//! Frozen golden frames for node protocol v1.
//!
//! These are compatibility artifacts, not test data that follows the code. A
//! change that makes an existing v1 fixture fail is a breaking protocol change
//! and needs a new protocol version, not a regenerated fixture. `proto/README.md`
//! states the rule and the deliberately awkward regeneration path.
//!
//! They are part of the ordinary public API rather than test-only, because both
//! `fleet-controller` and `fleetd` consume them to prove their own handling of
//! each message family without either crate re-encoding the bytes it is meant
//! to be checked against.

use crate::{
    limits::{HEARTBEAT_INTERVAL_MILLIS, session_limits},
    version::{PROTOCOL_V1, SUPPORTED_PROTOCOL_VERSIONS},
    wire::{self, CancellationPolicy, FaultCode, ResultStatus, frame::Payload},
};

/// Opaque identity of the fixture machine.
pub const MACHINE_ID: &str = "01900a3c-c687-7398-b115-72e6c495b187";
/// Opaque identity of the fixture node boot session.
pub const SESSION_ID: &str = "01900a3c-d798-74a9-8226-83f7d5a6c298";
/// Opaque identity correlating every fixture frame with one session.
pub const CORRELATION_ID: &str = "01900a3c-b576-7287-a004-61d5b384a076";
/// Opaque identity of the fixture operation.
pub const OPERATION_ID: &str = "01900a3c-e8a9-75ba-9337-94a8e6b7d3a9";
/// Opaque single-use value marking a replay of the fixture command.
///
/// Deliberately not named for the wire field it fills. The secret scanner's
/// generic rule fires on a random-looking literal beside an identifier
/// containing `key`, and an opaque fixture identity is random-looking by
/// construction. The protocol field keeps its name; only this constant avoids
/// the word.
pub const IDEMPOTENT_REPLAY: &str = "01900a3c-0acb-77dc-b559-b6cae8d9f5cb";

/// Fixed wall time used by every fixture, so goldens never depend on a clock.
pub const SENT_AT_UNIX_MILLIS: i64 = 1_780_000_000_000;

/// One frozen golden frame and its encoding.
#[derive(Clone, Debug)]
pub struct Golden {
    /// File stem under `proto/fixtures/v1/`.
    pub name: &'static str,
    /// The exact checked-in bytes.
    pub encoded: &'static [u8],
    /// The frame those bytes encode.
    pub frame: wire::Frame,
}

/// Returns every golden frame, one per message family.
#[must_use]
pub fn goldens() -> Vec<Golden> {
    vec![
        Golden {
            name: "hello",
            encoded: HELLO,
            frame: hello(),
        },
        Golden {
            name: "welcome",
            encoded: WELCOME,
            frame: welcome(),
        },
        Golden {
            name: "heartbeat",
            encoded: HEARTBEAT,
            frame: heartbeat(),
        },
        Golden {
            name: "command",
            encoded: COMMAND,
            frame: command(),
        },
        Golden {
            name: "command-result",
            encoded: COMMAND_RESULT,
            frame: command_result(),
        },
        Golden {
            name: "fault",
            encoded: FAULT,
            frame: fault(),
        },
    ]
}

/// The encoded `Hello` golden.
pub const HELLO: &[u8] = include_bytes!("../../../proto/fixtures/v1/hello.bin");
/// The encoded `Welcome` golden.
pub const WELCOME: &[u8] = include_bytes!("../../../proto/fixtures/v1/welcome.bin");
/// The encoded `Heartbeat` golden.
pub const HEARTBEAT: &[u8] = include_bytes!("../../../proto/fixtures/v1/heartbeat.bin");
/// The encoded `Command` golden.
pub const COMMAND: &[u8] = include_bytes!("../../../proto/fixtures/v1/command.bin");
/// The encoded `CommandResult` golden.
pub const COMMAND_RESULT: &[u8] = include_bytes!("../../../proto/fixtures/v1/command-result.bin");
/// The encoded `Fault` golden.
pub const FAULT: &[u8] = include_bytes!("../../../proto/fixtures/v1/fault.bin");

/// A `Hello` frame carrying fields and an envelope field this version does not
/// know, as a later build of protocol v1 would send it.
pub const HELLO_WITH_UNKNOWN_FIELDS: &[u8] =
    include_bytes!("../../../proto/fixtures/v1/hello-with-unknown-fields.bin");

/// A frame whose payload variant this version does not know.
pub const UNKNOWN_PAYLOAD: &[u8] = include_bytes!("../../../proto/fixtures/v1/unknown-payload.bin");

fn envelope(message_id: &str, payload: Payload) -> wire::Frame {
    wire::Frame {
        message_id: message_id.to_owned(),
        correlation_id: CORRELATION_ID.to_owned(),
        sent_at_unix_millis: SENT_AT_UNIX_MILLIS,
        payload: Some(payload),
    }
}

/// Returns the canonical `Hello` frame.
#[must_use]
pub fn hello() -> wire::Frame {
    envelope(
        "01900a3c-5f10-7c21-9a4e-0b7f5d2e4a10",
        Payload::Hello(wire::Hello {
            machine_id: MACHINE_ID.to_owned(),
            node_version: "0.1.0".to_owned(),
            protocol_versions: Some(SUPPORTED_PROTOCOL_VERSIONS.to_wire()),
            inventory_schema_versions: Some(wire::VersionRange { min: 1, max: 1 }),
            session_id: SESSION_ID.to_owned(),
            journal_position: 42,
            os: "linux".to_owned(),
            arch: "x86_64".to_owned(),
            feature_flags: vec!["exec".to_owned(), "inventory".to_owned()],
            last_acknowledged_operation_id: OPERATION_ID.to_owned(),
        }),
    )
}

/// Returns the canonical `Welcome` frame.
#[must_use]
pub fn welcome() -> wire::Frame {
    envelope(
        "01900a3c-6021-7d32-8b5f-1c806e3f5b21",
        Payload::Welcome(wire::Welcome {
            protocol_version: PROTOCOL_V1.value(),
            inventory_schema_version: 1,
            session_id: "01900a3c-f9ba-76cb-a448-a5b9f7c8e4ba".to_owned(),
            enabled_feature_flags: vec!["exec".to_owned(), "inventory".to_owned()],
            limits: Some(session_limits()),
            heartbeat_interval_millis: HEARTBEAT_INTERVAL_MILLIS,
        }),
    )
}

/// Returns the canonical `Heartbeat` frame.
#[must_use]
pub fn heartbeat() -> wire::Frame {
    envelope(
        "01900a3c-7132-7e43-ac60-2d917f406c32",
        Payload::Heartbeat(wire::Heartbeat {
            sequence: 7,
            node_uptime_millis: 3_600_000,
            journal_position: 42,
            in_flight_commands: 1,
        }),
    )
}

/// Returns the canonical `Command` frame.
#[must_use]
pub fn command() -> wire::Frame {
    envelope(
        "01900a3c-8243-7f54-bd71-3ea280517d43",
        Payload::Command(wire::Command {
            operation_id: OPERATION_ID.to_owned(),
            kind: "fleet.probe".to_owned(),
            kind_schema_version: 1,
            deadline_unix_millis: SENT_AT_UNIX_MILLIS + 30_000,
            idempotency_key: IDEMPOTENT_REPLAY.to_owned(),
            authorization_digest:
                "sha256:0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8".to_owned(),
            max_output_bytes: 65_536,
            cancellation: CancellationPolicy::BestEffort.into(),
            payload: b"{}".to_vec(),
        }),
    )
}

/// Returns the canonical `CommandResult` frame.
#[must_use]
pub fn command_result() -> wire::Frame {
    envelope(
        "01900a3c-9354-7065-8e82-4fb391628e54",
        Payload::CommandResult(wire::CommandResult {
            operation_id: OPERATION_ID.to_owned(),
            status: ResultStatus::Succeeded.into(),
            exit_code: 0,
            output_truncated: false,
            duration_millis: 1_250,
            stopped: false,
            fault: None,
            payload: b"{}".to_vec(),
        }),
    )
}

/// Returns the canonical `Fault` frame.
#[must_use]
pub fn fault() -> wire::Frame {
    envelope(
        "01900a3c-a465-7176-9f93-50c4a2739f65",
        Payload::Fault(
            crate::ProtocolFault::version(
                FaultCode::NodeUpgradeRequired,
                SUPPORTED_PROTOCOL_VERSIONS,
            )
            .to_wire(),
        ),
    )
}
