use std::str::FromStr as _;

use fleet_core::CorrelationId;
use prost::Message as _;

use crate::{
    fault::ProtocolFault,
    limits::MAX_FRAME_BYTES,
    wire::{self, FaultCode},
};

/// Returns a frame's opaque per-frame identity.
///
/// # Errors
///
/// Returns a [`FaultCode::MalformedIdentity`] fault when the field is absent or
/// is not a canonical opaque Fleet identity.
pub fn message_id(frame: &wire::Frame) -> Result<CorrelationId, ProtocolFault> {
    CorrelationId::from_str(&frame.message_id)
        .map_err(|_| ProtocolFault::new(FaultCode::MalformedIdentity))
}

/// Returns a frame's correlation identity, or `None` when it starts its own.
///
/// # Errors
///
/// Returns a [`FaultCode::MalformedIdentity`] fault when a non-empty field is
/// not a canonical opaque Fleet identity.
pub fn correlation_id(frame: &wire::Frame) -> Result<Option<CorrelationId>, ProtocolFault> {
    if frame.correlation_id.is_empty() {
        return Ok(None);
    }
    CorrelationId::from_str(&frame.correlation_id)
        .map(Some)
        .map_err(|_| ProtocolFault::new(FaultCode::MalformedIdentity))
}

/// Encodes a frame for transmission.
///
/// # Errors
///
/// Returns a typed fault when the frame carries a malformed identity, has no
/// payload, or would exceed [`MAX_FRAME_BYTES`]. Encoding is checked as well as
/// decoding so that a local defect fails on the sender rather than arriving as
/// an unexplained fault from the peer.
pub fn encode_frame(frame: &wire::Frame) -> Result<Vec<u8>, ProtocolFault> {
    validate(frame)?;
    if frame.encoded_len() > max_frame_bytes() {
        return Err(ProtocolFault::new(FaultCode::FrameTooLarge));
    }
    Ok(frame.encode_to_vec())
}

/// Decodes one received frame.
///
/// Fields this version does not know are ignored: a peer running a later build
/// of the same protocol version stays understandable. A payload variant this
/// version does not know is reported instead of ignored, because a frame whose
/// meaning is entirely unknown cannot be acted on.
///
/// # Errors
///
/// Returns a typed fault when the frame is oversized, undecodable, carries a
/// malformed identity, or carries no payload this version understands.
pub fn decode_frame(bytes: &[u8]) -> Result<wire::Frame, ProtocolFault> {
    if bytes.len() > max_frame_bytes() {
        return Err(ProtocolFault::new(FaultCode::FrameTooLarge));
    }
    let frame =
        wire::Frame::decode(bytes).map_err(|_| ProtocolFault::new(FaultCode::MalformedFrame))?;
    validate(&frame)?;
    Ok(frame)
}

fn max_frame_bytes() -> usize {
    usize::try_from(MAX_FRAME_BYTES).unwrap_or(usize::MAX)
}

fn validate(frame: &wire::Frame) -> Result<(), ProtocolFault> {
    message_id(frame)?;
    correlation_id(frame)?;
    if frame.payload.is_none() {
        return Err(ProtocolFault::new(FaultCode::UnknownPayload));
    }
    Ok(())
}
