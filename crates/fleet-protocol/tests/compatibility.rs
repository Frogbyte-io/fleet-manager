//! The version and feature-flag compatibility matrix.
//!
//! A controller and a node upgrade independently and reconnect across those
//! upgrades, so the interesting cases are the asymmetric ones: which peer is
//! behind, and whether the error says so without a second round trip.

use fleet_protocol::{
    ProtocolVersion, VersionRange, negotiate_feature_flags, negotiate_protocol_version,
    wire::FaultCode,
};

fn range(min: u32, max: u32) -> VersionRange {
    VersionRange::new(
        ProtocolVersion::new(min).expect("a fixture version is nonzero"),
        ProtocolVersion::new(max).expect("a fixture version is nonzero"),
    )
    .expect("a fixture range is ordered")
}

#[derive(Debug)]
enum Expected {
    Selects(u32),
    Faults(FaultCode),
}

#[test]
fn the_negotiation_matrix_is_stable() {
    let cases = [
        (
            "identical single versions",
            (1, 1),
            (1, 1),
            Expected::Selects(1),
        ),
        (
            "node ahead within a shared range",
            (1, 3),
            (1, 2),
            Expected::Selects(2),
        ),
        (
            "controller ahead within a shared range",
            (1, 2),
            (1, 3),
            Expected::Selects(2),
        ),
        (
            "overlap of exactly one version",
            (2, 4),
            (4, 7),
            Expected::Selects(4),
        ),
        (
            "both moved on together",
            (2, 5),
            (3, 5),
            Expected::Selects(5),
        ),
        (
            "node too old for the controller",
            (1, 2),
            (3, 4),
            Expected::Faults(FaultCode::NodeUpgradeRequired),
        ),
        (
            "controller too old for the node",
            (5, 6),
            (1, 4),
            Expected::Faults(FaultCode::ControllerUpgradeRequired),
        ),
        (
            "adjacent but disjoint ranges",
            (1, 1),
            (2, 2),
            Expected::Faults(FaultCode::NodeUpgradeRequired),
        ),
    ];

    for (name, node, controller, expected) in cases {
        let node = range(node.0, node.1);
        let controller = range(controller.0, controller.1);
        let result = negotiate_protocol_version(node, controller);

        match expected {
            Expected::Selects(version) => {
                assert_eq!(
                    result.expect(name).value(),
                    version,
                    "{name}: wrong version selected"
                );
            }
            Expected::Faults(code) => {
                let fault = result.expect_err(name);
                assert_eq!(fault.code(), code, "{name}: wrong fault code");
                assert_eq!(
                    fault.supported_protocol_versions(),
                    Some(controller),
                    "{name}: a version fault must report the controller's range"
                );
            }
        }
    }
}

#[test]
fn a_version_fault_survives_a_wire_round_trip_with_its_range() {
    let fault = negotiate_protocol_version(range(1, 1), range(4, 9))
        .expect_err("disjoint ranges cannot negotiate");

    let read_back = fleet_protocol::ProtocolFault::from_wire(&fault.to_wire());

    assert_eq!(read_back, fault);
    assert_eq!(read_back.supported_protocol_versions(), Some(range(4, 9)));
}

#[test]
fn feature_flags_negotiate_independently_of_the_protocol_version() {
    let selected = negotiate_protocol_version(range(1, 2), range(1, 3)).expect("ranges overlap");
    let flags = negotiate_feature_flags(
        &["exec", "inventory", "node-only-experiment"],
        &["controller-only-experiment", "inventory", "exec"],
    );

    assert_eq!(selected.value(), 2);
    assert_eq!(flags, ["exec", "inventory"]);
}
