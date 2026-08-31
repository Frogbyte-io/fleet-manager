use crate::wire;

/// Maximum encoded size of one frame, in bytes.
///
/// Log bodies and artifacts move over HTTP against an operation ID rather than
/// growing this bound; see `docs/architecture/controller-node-protocol.md`.
pub const MAX_FRAME_BYTES: u32 = 1 << 20;

/// Maximum size of a command's kind-specific payload, in bytes.
pub const MAX_COMMAND_PAYLOAD_BYTES: u32 = 256 * 1024;

/// Maximum size of a terminal result's kind-specific payload, in bytes.
pub const MAX_RESULT_PAYLOAD_BYTES: u32 = 256 * 1024;

/// Maximum number of commands the controller may have outstanding on one node.
pub const MAX_IN_FLIGHT_COMMANDS: u32 = 32;

/// Interval at which a node sends heartbeats, in milliseconds.
pub const HEARTBEAT_INTERVAL_MILLIS: i64 = 15_000;

// Payload bounds are useless if a conforming payload cannot fit in a frame, so
// the relationship is checked at compile time rather than trusted to review.
const _: () = assert!(MAX_COMMAND_PAYLOAD_BYTES < MAX_FRAME_BYTES);
const _: () = assert!(MAX_RESULT_PAYLOAD_BYTES < MAX_FRAME_BYTES);

/// Returns the limits a controller advertises in [`wire::Welcome`].
///
/// Limits are advertised rather than assumed so that a later controller can
/// lower them for a specific node without a protocol version bump.
#[must_use]
pub const fn session_limits() -> wire::Limits {
    wire::Limits {
        max_frame_bytes: MAX_FRAME_BYTES,
        max_command_payload_bytes: MAX_COMMAND_PAYLOAD_BYTES,
        max_result_payload_bytes: MAX_RESULT_PAYLOAD_BYTES,
        max_in_flight_commands: MAX_IN_FLIGHT_COMMANDS,
    }
}
