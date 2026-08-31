use std::{error::Error, fmt, str::FromStr as _};

use fleet_core::{ErrorCode, PublicError, RetryClass};

use crate::{
    version::VersionRange,
    wire::{self, FaultCode, FaultRetry},
};

/// A typed node-protocol failure.
///
/// The code is the contract. Message text is derived from the code rather than
/// carried across the wire, so a peer can never influence what Fleet logs or
/// shows an operator, and the text stays stable for a given code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolFault {
    code: FaultCode,
    supported_protocol_versions: Option<VersionRange>,
}

impl ProtocolFault {
    /// Creates a fault carrying only its code.
    #[must_use]
    pub const fn new(code: FaultCode) -> Self {
        Self {
            code,
            supported_protocol_versions: None,
        }
    }

    /// Creates a version fault that reports the range this peer supports.
    #[must_use]
    pub const fn version(code: FaultCode, supported: VersionRange) -> Self {
        Self {
            code,
            supported_protocol_versions: Some(supported),
        }
    }

    /// Returns the stable failure code.
    #[must_use]
    pub const fn code(self) -> FaultCode {
        self.code
    }

    /// Returns the range the reporting peer supports, for version faults.
    #[must_use]
    pub const fn supported_protocol_versions(self) -> Option<VersionRange> {
        self.supported_protocol_versions
    }

    /// Returns the stable Fleet-owned summary for this fault's code.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self.code {
            FaultCode::Unspecified => "the peer reported an unspecified protocol fault",
            FaultCode::NodeUpgradeRequired => {
                "the node supports no protocol version the controller still accepts"
            }
            FaultCode::ControllerUpgradeRequired => {
                "the controller supports no protocol version the node offers"
            }
            FaultCode::MalformedFrame => "the frame could not be decoded as node protocol v1",
            FaultCode::FrameTooLarge => "the frame exceeded the negotiated frame limit",
            FaultCode::UnknownPayload => "the frame carried no payload this version understands",
            FaultCode::MalformedIdentity => "the frame carried a malformed opaque identity",
            FaultCode::SessionRejected => "the controller refused the node session",
        }
    }

    /// Returns whether and how the peer may retry the frame that faulted.
    #[must_use]
    pub const fn retry(self) -> RetryClass {
        match self.code {
            // A resend of the same bytes fails the same way; the sender must
            // change the frame, the software version, or the session.
            FaultCode::Unspecified
            | FaultCode::NodeUpgradeRequired
            | FaultCode::ControllerUpgradeRequired
            | FaultCode::MalformedFrame
            | FaultCode::FrameTooLarge
            | FaultCode::UnknownPayload
            | FaultCode::MalformedIdentity => RetryClass::Never,
            // Enrollment or credential state may change without the node doing
            // anything, so reconnecting later is meaningful.
            FaultCode::SessionRejected => RetryClass::Backoff,
        }
    }

    /// Returns the stable machine-readable public error code.
    ///
    /// # Panics
    ///
    /// Panics only if a code's text stops being valid [`ErrorCode`] syntax,
    /// which the unit tests in this module prevent.
    #[must_use]
    pub fn error_code(self) -> ErrorCode {
        let code = match self.code {
            FaultCode::Unspecified => "node_protocol_unspecified",
            FaultCode::NodeUpgradeRequired => "node_protocol_node_upgrade_required",
            FaultCode::ControllerUpgradeRequired => "node_protocol_controller_upgrade_required",
            FaultCode::MalformedFrame => "node_protocol_malformed_frame",
            FaultCode::FrameTooLarge => "node_protocol_frame_too_large",
            FaultCode::UnknownPayload => "node_protocol_unknown_payload",
            FaultCode::MalformedIdentity => "node_protocol_malformed_identity",
            FaultCode::SessionRejected => "node_protocol_session_rejected",
        };
        ErrorCode::from_str(code).expect("protocol fault codes are valid public error codes")
    }

    /// Returns the caller-safe representation used by audit and API layers.
    #[must_use]
    pub fn public_error(self) -> PublicError {
        PublicError::new(self.error_code(), self.message(), self.retry())
    }

    /// Returns this fault as the wire message sent to the peer.
    #[must_use]
    pub fn to_wire(self) -> wire::Fault {
        wire::Fault {
            code: self.code.into(),
            message: self.message().to_owned(),
            retry: match self.retry() {
                RetryClass::Never => FaultRetry::Never,
                RetryClass::Immediate => FaultRetry::Immediate,
                RetryClass::Backoff => FaultRetry::Backoff,
            }
            .into(),
            supported_protocol_versions: self
                .supported_protocol_versions
                .map(VersionRange::to_wire),
        }
    }

    /// Reads a peer's fault, keeping the code and discarding its text.
    ///
    /// An unrecognised code becomes [`FaultCode::Unspecified`] rather than an
    /// error: a newer peer may fault for a reason this version cannot name, and
    /// dropping the session over that would be worse than reporting it plainly.
    #[must_use]
    pub fn from_wire(fault: &wire::Fault) -> Self {
        Self {
            code: FaultCode::try_from(fault.code).unwrap_or(FaultCode::Unspecified),
            supported_protocol_versions: fault
                .supported_protocol_versions
                .as_ref()
                .and_then(|range| VersionRange::from_wire(range).ok()),
        }
    }
}

impl fmt::Display for ProtocolFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.error_code(), self.message())?;
        if let Some(range) = self.supported_protocol_versions {
            write!(formatter, " (peer supports {range})")?;
        }
        Ok(())
    }
}

impl Error for ProtocolFault {}

#[cfg(test)]
mod tests {
    use super::{FaultCode, ProtocolFault};

    const ALL_CODES: &[FaultCode] = &[
        FaultCode::Unspecified,
        FaultCode::NodeUpgradeRequired,
        FaultCode::ControllerUpgradeRequired,
        FaultCode::MalformedFrame,
        FaultCode::FrameTooLarge,
        FaultCode::UnknownPayload,
        FaultCode::MalformedIdentity,
        FaultCode::SessionRejected,
    ];

    #[test]
    fn every_code_has_a_valid_public_error() {
        for &code in ALL_CODES {
            let fault = ProtocolFault::new(code);
            let public = fault.public_error();
            assert_eq!(public.code(), &fault.error_code());
            assert!(!public.message().is_empty());
        }
    }

    #[test]
    fn peer_message_text_is_discarded_on_read() {
        let mut wire = ProtocolFault::new(FaultCode::MalformedFrame).to_wire();
        wire.message = "controller stack trace at /srv/fleet/secret".to_owned();

        let fault = ProtocolFault::from_wire(&wire);

        assert_eq!(fault.code(), FaultCode::MalformedFrame);
        assert_eq!(
            fault.message(),
            "the frame could not be decoded as node protocol v1"
        );
    }

    #[test]
    fn an_unrecognised_peer_code_reads_as_unspecified() {
        let wire = super::wire::Fault {
            code: 4_242,
            ..ProtocolFault::new(FaultCode::MalformedFrame).to_wire()
        };

        assert_eq!(
            ProtocolFault::from_wire(&wire).code(),
            FaultCode::Unspecified
        );
    }
}
