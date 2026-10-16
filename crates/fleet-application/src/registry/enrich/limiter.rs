//! Per-server request spacing: public RDAP servers are shared
//! infrastructure and several of them throttle aggressively, so Fleet
//! never sends one server two queries closer together than a minimum gap.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Hands out request slots per server, at least `gap` apart. Pure: the
/// caller supplies the clock and does the sleeping.
#[derive(Debug)]
pub struct RateLimiter {
    gap: Duration,
    next_free: HashMap<String, Instant>,
}

impl RateLimiter {
    /// A limiter spacing each server's slots by `gap`.
    #[must_use]
    pub fn new(gap: Duration) -> Self {
        Self {
            gap,
            next_free: HashMap::new(),
        }
    }

    /// Reserves the next slot on `server` and returns how long to wait
    /// before using it. Reserved slots are never released, so concurrent
    /// callers queue behind one another.
    pub fn reserve(&mut self, server: &str, now: Instant) -> Duration {
        let slot = self
            .next_free
            .get(server)
            .copied()
            .map_or(now, |free| free.max(now));
        self.next_free.insert(server.to_owned(), slot + self.gap);
        slot.saturating_duration_since(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_query_goes_at_once_and_later_ones_queue_by_the_gap() {
        let mut limiter = RateLimiter::new(Duration::from_secs(2));
        let now = Instant::now();
        assert_eq!(limiter.reserve("a", now), Duration::ZERO);
        assert_eq!(limiter.reserve("a", now), Duration::from_secs(2));
        assert_eq!(limiter.reserve("a", now), Duration::from_secs(4));
    }

    #[test]
    fn servers_do_not_share_a_budget() {
        let mut limiter = RateLimiter::new(Duration::from_secs(2));
        let now = Instant::now();
        limiter.reserve("a", now);
        assert_eq!(limiter.reserve("b", now), Duration::ZERO);
    }

    #[test]
    fn an_old_reservation_has_expired() {
        let mut limiter = RateLimiter::new(Duration::from_secs(2));
        let now = Instant::now();
        limiter.reserve("a", now);
        assert_eq!(
            limiter.reserve("a", now + Duration::from_secs(5)),
            Duration::ZERO
        );
    }
}
