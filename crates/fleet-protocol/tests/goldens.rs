//! Golden encode/decode coverage for every node protocol v1 message family.
//!
//! The checked-in fixtures are frozen. If a change here fails, the question is
//! whether the protocol change was breaking, not whether the fixture is stale.
//! Regenerating deliberately is `FLEET_PROTOCOL_BLESS=1 cargo test -p
//! fleet-protocol --test goldens`, followed by a second run so the embedded
//! copies are rebuilt from the new files.

use std::{fs, path::PathBuf};

use fleet_protocol::{
    decode_frame, encode_frame,
    fixtures::{self, CORRELATION_ID, SENT_AT_UNIX_MILLIS},
    wire::FaultCode,
};

mod support;

const BLESS: &str = "FLEET_PROTOCOL_BLESS";

fn blessing() -> bool {
    std::env::var_os(BLESS).is_some()
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the protocol crate lives two directories below the repository root")
        .join("proto/fixtures/v1")
        .join(format!("{name}.bin"))
}

/// Returns the checked-in fixture, first overwriting it when blessing.
fn checked_in(name: &str, produced: &[u8]) -> Vec<u8> {
    let path = fixture_path(name);
    if blessing() {
        fs::write(&path, produced).expect("fixture is writable");
    }
    fs::read(&path).unwrap_or_else(|error| panic!("missing fixture {}: {error}", path.display()))
}

#[test]
fn every_message_family_round_trips_through_its_frozen_fixture() {
    for golden in fixtures::goldens() {
        let encoded = encode_frame(&golden.frame).expect("a canonical frame encodes");
        let checked_in = checked_in(golden.name, &encoded);

        assert_eq!(encoded, checked_in, "{} encoding changed", golden.name);
        assert_eq!(
            decode_frame(&checked_in).expect("a frozen fixture decodes"),
            golden.frame,
            "{} decoding changed",
            golden.name
        );
        if !blessing() {
            assert_eq!(
                golden.encoded, checked_in,
                "{} embedded copy is stale",
                golden.name
            );
        }
    }
}

#[test]
fn fields_a_later_build_of_v1_adds_are_ignored_rather_than_rejected() {
    let hello = fixtures::hello();
    let checked_in = checked_in(
        "hello-with-unknown-fields",
        &support::hello_with_unknown_fields(&hello),
    );

    assert_ne!(
        checked_in,
        encode_frame(&hello).expect("a canonical frame encodes"),
        "the fixture must actually carry bytes this version does not know"
    );
    assert_eq!(
        decode_frame(&checked_in).expect("unknown fields must not fail the frame"),
        hello,
        "known fields must survive unchanged"
    );
    if !blessing() {
        assert_eq!(fixtures::HELLO_WITH_UNKNOWN_FIELDS, checked_in);
    }
}

#[test]
fn a_payload_variant_this_version_cannot_read_faults_instead_of_passing_silently() {
    let checked_in = checked_in("unknown-payload", &support::unknown_payload());

    let fault = decode_frame(&checked_in).expect_err("an unreadable payload must fault");

    assert_eq!(fault.code(), FaultCode::UnknownPayload);
    if !blessing() {
        assert_eq!(fixtures::UNKNOWN_PAYLOAD, checked_in);
    }
}

#[test]
fn envelope_identities_are_readable_from_a_frozen_fixture() {
    let frame = decode_frame(fixtures::HELLO).expect("the hello fixture decodes");

    assert_eq!(
        fleet_protocol::message_id(&frame)
            .expect("a frozen fixture carries a valid identity")
            .to_string(),
        "01900a3c-5f10-7c21-9a4e-0b7f5d2e4a10"
    );
    assert_eq!(
        fleet_protocol::correlation_id(&frame)
            .expect("a frozen fixture carries a valid correlation")
            .expect("the hello fixture is correlated")
            .to_string(),
        CORRELATION_ID
    );
    assert_eq!(frame.sent_at_unix_millis, SENT_AT_UNIX_MILLIS);
}
