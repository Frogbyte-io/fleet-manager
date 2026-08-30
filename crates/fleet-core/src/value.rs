use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// Maximum accepted slug length.
pub const MAX_SLUG_LEN: usize = 63;

/// An error returned when a mutable resource label is not a valid slug.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseSlugError;

impl fmt::Display for ParseSlugError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "slug must be 1-63 lowercase ASCII letters or digits separated by single hyphens",
        )
    }
}

impl std::error::Error for ParseSlugError {}

/// A mutable, human-facing resource label, never a resource identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Slug(String);

impl Slug {
    /// Returns this label as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Replaces this mutable label after validating the new value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseSlugError`] if `value` is outside the portable slug syntax.
    pub fn replace(&mut self, value: &str) -> Result<(), ParseSlugError> {
        *self = value.parse()?;
        Ok(())
    }
}

impl FromStr for Slug {
    type Err = ParseSlugError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let valid_len = !value.is_empty() && value.len() <= MAX_SLUG_LEN;
        let valid_parts = value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        });
        if valid_len && valid_parts {
            Ok(Self(value.to_owned()))
        } else {
            Err(ParseSlugError)
        }
    }
}

impl<'de> Deserialize<'de> for Slug {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A monotonically increasing optimistic-concurrency revision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    /// Creates a revision from its stored integer representation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the stored integer representation.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the next revision, or `None` when the integer is exhausted.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}
