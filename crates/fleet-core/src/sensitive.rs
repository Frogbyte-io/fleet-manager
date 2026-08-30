use std::{fmt, str::FromStr};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ParseIdError, ResourceId};

/// An opaque reference to secret material held outside Fleet's domain state.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretReference(ResourceId);

impl SecretReference {
    /// Creates a secret reference from an opaque resource identity.
    #[must_use]
    pub const fn new(id: ResourceId) -> Self {
        Self(id)
    }

    /// Returns the opaque identity used to resolve the secret at a trusted boundary.
    #[must_use]
    pub const fn id(self) -> ResourceId {
        self.0
    }
}

impl FromStr for SecretReference {
    type Err = ParseIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self)
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretReference([REDACTED])")
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        ResourceId::deserialize(deserializer).map(Self)
    }
}

/// Secret text that is zeroized on drop and redacted from debug output.
pub struct SensitiveString(SecretString);

impl SensitiveString {
    /// Moves text into redacted, zeroizing storage.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::from(value.into()))
    }

    /// Explicitly exposes the contained secret to a trusted integration boundary.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveString([REDACTED])")
    }
}
