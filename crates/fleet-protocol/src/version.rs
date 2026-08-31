use std::{error::Error, fmt};

use crate::{fault::ProtocolFault, wire};

/// A node-protocol version. Version zero is never valid on the wire; it is the
/// proto3 default and therefore indistinguishable from an absent field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    /// Creates a version, rejecting the reserved zero value.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Returns the wire representation.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v{}", self.0)
    }
}

/// The first node protocol version.
pub const PROTOCOL_V1: ProtocolVersion = ProtocolVersion(1);

/// The range this build of Fleet accepts.
pub const SUPPORTED_PROTOCOL_VERSIONS: VersionRange = VersionRange {
    min: PROTOCOL_V1,
    max: PROTOCOL_V1,
};

/// An error returned when a wire version range is not a usable closed range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseVersionRangeError;

impl fmt::Display for ParseVersionRangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a version range must be a nonzero minimum no greater than its maximum")
    }
}

impl Error for ParseVersionRangeError {}

/// An inclusive range of supported versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionRange {
    min: ProtocolVersion,
    max: ProtocolVersion,
}

impl VersionRange {
    /// Creates a range, rejecting an inverted one.
    #[must_use]
    pub const fn new(min: ProtocolVersion, max: ProtocolVersion) -> Option<Self> {
        if min.0 <= max.0 {
            Some(Self { min, max })
        } else {
            None
        }
    }

    /// Returns the lowest supported version.
    #[must_use]
    pub const fn min(self) -> ProtocolVersion {
        self.min
    }

    /// Returns the highest supported version.
    #[must_use]
    pub const fn max(self) -> ProtocolVersion {
        self.max
    }

    /// Returns the wire representation.
    #[must_use]
    pub const fn to_wire(self) -> wire::VersionRange {
        wire::VersionRange {
            min: self.min.0,
            max: self.max.0,
        }
    }

    /// Reads a peer's advertised range.
    ///
    /// # Errors
    ///
    /// Returns [`ParseVersionRangeError`] when the range is absent, zero, or
    /// inverted. An absent range decodes as zeroes under proto3, so a peer that
    /// omits it is rejected rather than silently treated as supporting v0.
    pub fn from_wire(range: &wire::VersionRange) -> Result<Self, ParseVersionRangeError> {
        let min = ProtocolVersion::new(range.min).ok_or(ParseVersionRangeError)?;
        let max = ProtocolVersion::new(range.max).ok_or(ParseVersionRangeError)?;
        Self::new(min, max).ok_or(ParseVersionRangeError)
    }
}

impl fmt::Display for VersionRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.min == self.max {
            write!(formatter, "{}", self.min)
        } else {
            write!(formatter, "{}..={}", self.min, self.max)
        }
    }
}

/// Selects the protocol version a session will use.
///
/// The highest version both peers accept wins, so a rolling upgrade converges
/// on the newer protocol as soon as both sides support it.
///
/// # Errors
///
/// Returns a typed fault when the ranges do not overlap. The fault names which
/// peer is behind and carries `controller`'s range, so the mismatch can be
/// reported without a second round trip.
pub fn negotiate_protocol_version(
    node: VersionRange,
    controller: VersionRange,
) -> Result<ProtocolVersion, ProtocolFault> {
    if node.max < controller.min {
        return Err(ProtocolFault::version(
            wire::FaultCode::NodeUpgradeRequired,
            controller,
        ));
    }
    if controller.max < node.min {
        return Err(ProtocolFault::version(
            wire::FaultCode::ControllerUpgradeRequired,
            controller,
        ));
    }
    Ok(node.max.min(controller.max))
}

#[cfg(test)]
mod tests {
    use super::{ProtocolVersion, VersionRange, negotiate_protocol_version};
    use crate::wire;

    fn range(min: u32, max: u32) -> VersionRange {
        VersionRange::new(
            ProtocolVersion::new(min).expect("nonzero"),
            ProtocolVersion::new(max).expect("nonzero"),
        )
        .expect("ordered")
    }

    #[test]
    fn an_absent_wire_range_is_rejected_rather_than_read_as_version_zero() {
        assert!(VersionRange::from_wire(&wire::VersionRange::default()).is_err());
    }

    #[test]
    fn an_inverted_wire_range_is_rejected() {
        assert!(VersionRange::from_wire(&wire::VersionRange { min: 3, max: 2 }).is_err());
    }

    #[test]
    fn a_valid_range_survives_a_wire_round_trip() {
        let original = range(1, 4);
        assert_eq!(
            VersionRange::from_wire(&original.to_wire()).expect("valid"),
            original
        );
    }

    #[test]
    fn negotiation_selects_the_highest_common_version() {
        let selected = negotiate_protocol_version(range(1, 3), range(2, 5)).expect("overlapping");
        assert_eq!(selected.value(), 3);
    }
}
