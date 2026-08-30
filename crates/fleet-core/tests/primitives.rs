use std::{collections::BTreeMap, error::Error, fmt, str::FromStr};

use fleet_core::{
    Clock, CorrelationId, Deadline, ErrorCode, FixedClock, FleetError, IdGenerator, PublicError,
    ResourceId, RetryClass, Revision, SecretReference, SensitiveString, Slug, SystemClock,
    Timestamp, UuidV7Generator,
};
use proptest::prelude::*;
use uuid::Uuid;

const V7_ID: &str = "01890f3e-9b4a-7cc2-98c3-d24e8f58f2a1";
const OTHER_V7_ID: &str = "01890f3e-9b4a-7cc2-98c3-d24e8f58f2a2";

#[test]
fn resource_ids_have_one_canonical_uuid_v7_encoding() {
    let id = ResourceId::from_str(V7_ID).expect("valid UUIDv7 resource ID");

    assert_eq!(id.to_string(), V7_ID);
    assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{V7_ID}\""));
    assert_eq!(
        serde_json::from_str::<ResourceId>(&format!("\"{V7_ID}\"")).unwrap(),
        id
    );

    assert!(ResourceId::from_str(&V7_ID.to_uppercase()).is_err());
    assert!(ResourceId::from_str("550e8400-e29b-41d4-a716-446655440000").is_err());
    assert!(ResourceId::from_str("host-192.0.2.1").is_err());
}

proptest! {
    #[test]
    fn resource_id_text_round_trips(mut bytes in any::<[u8; 16]>()) {
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let id = ResourceId::try_from(Uuid::from_bytes(bytes)).unwrap();

        prop_assert_eq!(id.to_string().parse::<ResourceId>().unwrap(), id);
    }
}

#[test]
fn correlation_ids_are_distinct_types_with_the_same_canonical_rules() {
    let id = CorrelationId::from_str(V7_ID).unwrap();
    assert_eq!(id.to_string(), V7_ID);
    assert!(CorrelationId::from_str("550e8400-e29b-41d4-a716-446655440000").is_err());
}

#[derive(Debug)]
struct PredictableIds {
    next_resource: ResourceId,
    next_correlation: CorrelationId,
}

impl IdGenerator for PredictableIds {
    fn next_resource_id(&mut self) -> ResourceId {
        self.next_resource
    }

    fn next_correlation_id(&mut self) -> CorrelationId {
        self.next_correlation
    }
}

#[test]
fn id_generation_is_injectable() {
    let mut fake = PredictableIds {
        next_resource: V7_ID.parse().unwrap(),
        next_correlation: OTHER_V7_ID.parse().unwrap(),
    };
    assert_eq!(fake.next_resource_id().to_string(), V7_ID);
    assert_eq!(fake.next_correlation_id().to_string(), OTHER_V7_ID);

    let mut production = UuidV7Generator;
    assert_eq!(production.next_resource_id().as_uuid().get_version_num(), 7);
    assert_eq!(
        production.next_correlation_id().as_uuid().get_version_num(),
        7
    );
}

#[test]
fn slugs_are_mutable_labels_with_a_small_portable_alphabet() {
    let mut slug = Slug::from_str("build-runner-07").unwrap();
    slug.replace("gpu-runner").unwrap();
    assert_eq!(slug.as_str(), "gpu-runner");
    assert_eq!(serde_json::to_string(&slug).unwrap(), "\"gpu-runner\"");

    for invalid in [
        "",
        "UPPER",
        "-edge",
        "edge-",
        "two--hyphens",
        "an_ip:192.0.2.1",
    ] {
        assert!(Slug::from_str(invalid).is_err(), "accepted {invalid:?}");
    }
}

#[test]
fn revisions_are_explicit_and_checked() {
    let revision = Revision::new(41);
    assert_eq!(revision.value(), 41);
    assert_eq!(revision.checked_next(), Some(Revision::new(42)));
    assert_eq!(Revision::new(u64::MAX).checked_next(), None);
}

#[test]
fn clocks_and_deadlines_are_deterministic_under_test() {
    let clock = FixedClock::new(Timestamp::from_unix_millis(1_000));
    let deadline = Deadline::at(Timestamp::from_unix_millis(1_500));

    assert!(!deadline.is_expired(&clock));
    assert_eq!(deadline.remaining_millis(&clock), 500);
    clock.set(Timestamp::from_unix_millis(1_500));
    assert!(deadline.is_expired(&clock));
    assert_eq!(deadline.remaining_millis(&clock), 0);

    let system_now = SystemClock.now();
    assert!(system_now.unix_millis() > 0);
}

#[derive(Debug)]
struct InternalFailure(&'static str);

impl fmt::Display for InternalFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for InternalFailure {}

#[test]
fn public_errors_serialize_without_the_internal_source() {
    let public = PublicError::new(
        ErrorCode::from_str("provider_unavailable").unwrap(),
        "The provider is temporarily unavailable",
        RetryClass::Backoff,
    )
    .with_details(BTreeMap::from([("provider".to_owned(), "ssh".to_owned())]));
    let error = FleetError::with_source(public, InternalFailure("token super-secret failed"));

    let serialized = serde_json::to_string(error.public()).unwrap();
    assert!(serialized.contains("provider_unavailable"));
    assert!(serialized.contains("temporarily unavailable"));
    assert!(!serialized.contains("super-secret"));
    assert!(!error.to_string().contains("super-secret"));
    assert!(!format!("{error:?}").contains("super-secret"));
    assert_eq!(
        error.source().unwrap().to_string(),
        "token super-secret failed"
    );
}

#[test]
fn error_codes_reject_unstable_or_display_oriented_text() {
    for invalid in ["", "UPPER_CASE", "has-hyphen", "has spaces"] {
        assert!(ErrorCode::from_str(invalid).is_err());
    }
}

#[test]
fn secret_references_and_values_are_redacted_by_default() {
    let reference = SecretReference::from_str(V7_ID).unwrap();
    assert_eq!(format!("{reference:?}"), "SecretReference([REDACTED])");
    assert_eq!(
        serde_json::to_string(&reference).unwrap(),
        format!("\"{V7_ID}\"")
    );

    let secret = SensitiveString::new("correct horse battery staple");
    assert_eq!(format!("{secret:?}"), "SensitiveString([REDACTED])");
    assert_eq!(secret.expose(), "correct horse battery staple");
}
