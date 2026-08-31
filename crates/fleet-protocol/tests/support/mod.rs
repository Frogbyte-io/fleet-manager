//! Hand-built protobuf bytes for frames no current encoder produces.
//!
//! Written by hand rather than with a helper library so that the compatibility
//! fixtures do not depend on the same code path they are meant to check.

use fleet_protocol::wire::{self, frame::Payload};
use prost::Message as _;

/// Envelope tag of the `hello` payload variant.
const HELLO_TAG: u32 = 16;
/// A payload variant no version of this protocol defines.
const UNKNOWN_PAYLOAD_TAG: u32 = 99;
/// A `Hello` field a later build of v1 might add.
const UNKNOWN_HELLO_FIELD_TAG: u32 = 500;
/// An envelope field a later build of v1 might add.
const UNKNOWN_ENVELOPE_FIELD_TAG: u32 = 1_000;

const VARINT: u32 = 0;
const LENGTH_DELIMITED: u32 = 2;

fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = u8::try_from(value & 0x7f).expect("seven bits fit in a byte");
        value >>= 7;
        if value == 0 {
            bytes.push(byte);
            return bytes;
        }
        bytes.push(byte | 0x80);
    }
}

fn key(tag: u32, wire_type: u32) -> Vec<u8> {
    varint(u64::from(tag << 3 | wire_type))
}

fn length_delimited(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut bytes = key(tag, LENGTH_DELIMITED);
    bytes.extend(varint(
        u64::try_from(value.len()).expect("a fixture field fits in a 64-bit length"),
    ));
    bytes.extend(value);
    bytes
}

/// Encodes a frame's scalar envelope fields, leaving the payload out.
fn envelope_without_payload(frame: &wire::Frame) -> Vec<u8> {
    wire::Frame {
        payload: None,
        ..frame.clone()
    }
    .encode_to_vec()
}

/// Returns a `Hello` frame carrying one unknown field inside `Hello` and one in
/// the envelope, in ascending tag order as a conforming encoder would write it.
///
/// # Panics
///
/// Panics if `frame` does not carry a `Hello` payload.
pub fn hello_with_unknown_fields(frame: &wire::Frame) -> Vec<u8> {
    let Some(Payload::Hello(hello)) = &frame.payload else {
        panic!("the hello fixture must carry a Hello payload");
    };

    let mut inner = hello.encode_to_vec();
    inner.extend(key(UNKNOWN_HELLO_FIELD_TAG, VARINT));
    inner.extend(varint(7));

    let mut bytes = envelope_without_payload(frame);
    bytes.extend(length_delimited(HELLO_TAG, &inner));
    bytes.extend(length_delimited(UNKNOWN_ENVELOPE_FIELD_TAG, b"future"));
    bytes
}

/// Returns a frame whose only payload is a variant this version cannot read.
pub fn unknown_payload() -> Vec<u8> {
    let mut bytes = envelope_without_payload(&fleet_protocol::fixtures::heartbeat());
    bytes.extend(length_delimited(
        UNKNOWN_PAYLOAD_TAG,
        b"from a later protocol",
    ));
    bytes
}
