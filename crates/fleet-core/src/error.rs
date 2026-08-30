use std::{collections::BTreeMap, error::Error, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// An error returned when a public error code is not stable machine syntax.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseErrorCodeError;

impl fmt::Display for ParseErrorCodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("error code must contain lowercase ASCII letters, digits, or underscores")
    }
}

impl Error for ParseErrorCodeError {}

/// A stable machine-readable public error code.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ErrorCode(String);

impl ErrorCode {
    /// Returns the stable code as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ErrorCode {
    type Err = ParseErrorCodeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(ParseErrorCodeError)
        }
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
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

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Guidance for whether and how a caller may retry an operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    /// Retrying the same request is not expected to succeed.
    Never,
    /// The request may be retried immediately.
    Immediate,
    /// The request may be retried after exponential backoff.
    Backoff,
}

/// Safe error information suitable for serialization to an untrusted caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicError {
    code: ErrorCode,
    message: String,
    retry: RetryClass,
    details: BTreeMap<String, String>,
}

impl PublicError {
    /// Creates public error data with no details.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>, retry: RetryClass) -> Self {
        Self {
            code,
            message: message.into(),
            retry,
            details: BTreeMap::new(),
        }
    }

    /// Replaces the caller-safe detail map.
    #[must_use]
    pub fn with_details(mut self, details: BTreeMap<String, String>) -> Self {
        self.details = details;
        self
    }

    /// Returns the stable machine code.
    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// Returns the caller-safe human message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns retry guidance.
    #[must_use]
    pub const fn retry(&self) -> RetryClass {
        self.retry
    }

    /// Returns caller-safe structured details.
    #[must_use]
    pub const fn details(&self) -> &BTreeMap<String, String> {
        &self.details
    }
}

/// A domain failure containing safe public data and an optional internal cause.
pub struct FleetError {
    public: PublicError,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl FleetError {
    /// Creates a failure with no internal cause.
    #[must_use]
    pub const fn new(public: PublicError) -> Self {
        Self {
            public,
            source: None,
        }
    }

    /// Creates a failure with an internal cause excluded from public formatting and serialization.
    pub fn with_source(public: PublicError, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            public,
            source: Some(Box::new(source)),
        }
    }

    /// Returns the caller-safe representation.
    #[must_use]
    pub const fn public(&self) -> &PublicError {
        &self.public
    }
}

impl fmt::Display for FleetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.public.code, self.public.message)
    }
}

impl fmt::Debug for FleetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FleetError")
            .field("public", &self.public)
            .field("has_source", &self.source.is_some())
            .finish()
    }
}

impl Error for FleetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}
