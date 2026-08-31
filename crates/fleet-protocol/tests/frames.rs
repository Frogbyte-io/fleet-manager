//! Bounded-input behaviour of the frame decoder.
//!
//! A node channel accepts bytes from a peer that may be older, newer, buggy, or
//! hostile. The decoder's contract is total: every input either produces a
//! frame or a typed fault, and none of them panic or allocate without bound.

use fleet_protocol::{
    MAX_FRAME_BYTES, decode_frame, encode_frame, fixtures, wire::FaultCode, wire::frame::Payload,
};
use proptest::prelude::*;

fn max_frame_bytes() -> usize {
    usize::try_from(MAX_FRAME_BYTES).expect("the frame limit fits in a pointer-sized integer")
}

#[test]
fn a_frame_over_the_limit_is_rejected_before_it_is_parsed() {
    let oversized = vec![0_u8; max_frame_bytes() + 1];

    let fault = decode_frame(&oversized).expect_err("an oversized frame must be refused");

    assert_eq!(fault.code(), FaultCode::FrameTooLarge);
}

#[test]
fn encoding_refuses_to_produce_a_frame_the_peer_would_reject() {
    let mut frame = fixtures::command();
    let Some(Payload::Command(command)) = &mut frame.payload else {
        panic!("the command fixture must carry a Command payload");
    };
    command.payload = vec![0_u8; max_frame_bytes()];

    let fault = encode_frame(&frame).expect_err("an oversized frame must not be sent");

    assert_eq!(fault.code(), FaultCode::FrameTooLarge);
}

#[test]
fn a_frame_without_a_valid_message_identity_is_refused_in_both_directions() {
    let mut frame = fixtures::heartbeat();
    frame.message_id = "not-an-identity".to_owned();

    assert_eq!(
        encode_frame(&frame)
            .expect_err("a malformed identity must not be sent")
            .code(),
        FaultCode::MalformedIdentity
    );

    let bytes = prost::Message::encode_to_vec(&frame);
    assert_eq!(
        decode_frame(&bytes)
            .expect_err("a malformed identity must not be accepted")
            .code(),
        FaultCode::MalformedIdentity
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary bytes are never a panic and never an untyped failure.
    #[test]
    fn arbitrary_bytes_decode_to_a_frame_or_a_typed_fault(bytes in proptest::collection::vec(any::<u8>(), 0..2_048)) {
        match decode_frame(&bytes) {
            Ok(frame) => prop_assert!(frame.payload.is_some()),
            Err(fault) => prop_assert_ne!(fault.code(), FaultCode::Unspecified),
        }
    }

    /// A frame truncated by a dropped connection is a fault, not a partial read.
    #[test]
    fn truncated_valid_frames_never_decode_to_a_different_frame(cut in 0_usize..fixtures::HELLO.len()) {
        let truncated = &fixtures::HELLO[..cut];
        if let Ok(frame) = decode_frame(truncated) {
            prop_assert_eq!(frame, fixtures::hello());
        }
    }

    /// Trailing bytes appended to a valid frame are unknown fields, not a way to
    /// smuggle a different payload past the decoder.
    #[test]
    fn appended_bytes_never_replace_a_known_payload(suffix in proptest::collection::vec(any::<u8>(), 1..64)) {
        let mut bytes = fixtures::HELLO.to_vec();
        bytes.extend(&suffix);
        if let Ok(frame) = decode_frame(&bytes) {
            prop_assert!(matches!(frame.payload, Some(Payload::Hello(_))));
        }
    }
}
