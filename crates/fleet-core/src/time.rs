use std::{
    sync::atomic::{AtomicI64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

/// A wall-clock instant represented as Unix epoch milliseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Creates a timestamp from Unix epoch milliseconds.
    #[must_use]
    pub const fn from_unix_millis(value: i64) -> Self {
        Self(value)
    }

    /// Returns Unix epoch milliseconds.
    #[must_use]
    pub const fn unix_millis(self) -> i64 {
        self.0
    }
}

/// Supplies wall time to domain rules.
pub trait Clock {
    /// Returns the current wall-clock timestamp.
    fn now(&self) -> Timestamp;
}

/// Production wall clock backed by [`SystemTime`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        Timestamp(i64::try_from(millis).unwrap_or(i64::MAX))
    }
}

/// A deterministic clock that tests can move explicitly.
#[derive(Debug)]
pub struct FixedClock(AtomicI64);

impl FixedClock {
    /// Creates a clock fixed at `now`.
    #[must_use]
    pub const fn new(now: Timestamp) -> Self {
        Self(AtomicI64::new(now.0))
    }

    /// Moves the clock to `now`.
    pub fn set(&self, now: Timestamp) {
        self.0.store(now.0, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.0.load(Ordering::SeqCst))
    }
}

/// A wall-clock cutoff for starting or continuing domain work.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Deadline(Timestamp);

impl Deadline {
    /// Creates a deadline at an absolute wall-clock timestamp.
    #[must_use]
    pub const fn at(timestamp: Timestamp) -> Self {
        Self(timestamp)
    }

    /// Returns the absolute timestamp represented by this deadline.
    #[must_use]
    pub const fn timestamp(self) -> Timestamp {
        self.0
    }

    /// Returns whether the deadline is at or before the supplied clock's current time.
    #[must_use]
    pub fn is_expired(self, clock: &dyn Clock) -> bool {
        clock.now() >= self.0
    }

    /// Returns whole milliseconds until expiry, clamped to zero.
    #[must_use]
    pub fn remaining_millis(self, clock: &dyn Clock) -> i64 {
        self.0.0.saturating_sub(clock.now().0).max(0)
    }
}
