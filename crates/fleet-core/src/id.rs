use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use uuid::Uuid;

/// An error returned when an opaque Fleet identifier is not canonical `UUIDv7`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseIdError;

impl fmt::Display for ParseIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("identifier must be a lowercase, hyphenated UUIDv7")
    }
}

impl std::error::Error for ParseIdError {}

fn parse_v7(value: &str) -> Result<Uuid, ParseIdError> {
    let uuid = Uuid::parse_str(value).map_err(|_| ParseIdError)?;
    if uuid.get_version_num() != 7 || uuid.hyphenated().to_string() != value {
        return Err(ParseIdError);
    }
    Ok(uuid)
}

macro_rules! opaque_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Returns the underlying UUID for boundary integrations.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl TryFrom<Uuid> for $name {
            type Error = ParseIdError;

            fn try_from(value: Uuid) -> Result<Self, Self::Error> {
                if value.get_version_num() == 7 {
                    Ok(Self(value))
                } else {
                    Err(ParseIdError)
                }
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_v7(value).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.hyphenated().fmt(formatter)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.to_string())
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = <String>::deserialize(deserializer)?;
                value.parse().map_err(de::Error::custom)
            }
        }
    };
}

opaque_id!(
    ResourceId,
    "A stable opaque identity for a Fleet resource. Labels, hostnames, and addresses are not identities."
);
opaque_id!(
    CorrelationId,
    "A stable opaque identity used to correlate work and audit events."
);

/// Generates opaque identities without coupling domain behavior to randomness or time.
pub trait IdGenerator {
    /// Generates a resource identity.
    fn next_resource_id(&mut self) -> ResourceId;

    /// Generates a correlation identity.
    fn next_correlation_id(&mut self) -> CorrelationId;
}

/// Production identifier generator backed by time-ordered `UUIDv7` values.
#[derive(Clone, Copy, Debug, Default)]
pub struct UuidV7Generator;

impl IdGenerator for UuidV7Generator {
    fn next_resource_id(&mut self) -> ResourceId {
        ResourceId(Uuid::now_v7())
    }

    fn next_correlation_id(&mut self) -> CorrelationId {
        CorrelationId(Uuid::now_v7())
    }
}
