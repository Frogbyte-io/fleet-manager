//! Per-guest locks that make a persistent machine's device attach and a
//! destructive operation on the same guest (destroy, snapshot revert,
//! template, clone) exclude each other (FM-1125).
//!
//! The destructive executor refuses a guest a machine holds a device on, but
//! it checks once and then works for minutes. An attach that starts after that
//! check could write `usbN` into a guest that is about to be deleted or
//! reverted. Both sides therefore take the guest's lock, and exactly one wins:
//!
//! - the destructive executor **waits** for the lock, then checks the
//!   reservations under it, so it sees whatever an attach left;
//! - an attach **does not wait**: if a destructive operation holds the lock it
//!   is refused at once (`hardware_guest_busy`), like `hardware_busy`; nothing
//!   queues.
//!
//! The registry is in process (one controller), keyed by (account, VMID), and
//! is shared by handing the same `Arc` to the executor and to the machine USB
//! port.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

type LockMap = HashMap<(String, u32), Arc<tokio::sync::Mutex<()>>>;

/// The registry of per-guest locks.
#[derive(Debug, Default)]
pub struct GuestLocks {
    locks: StdMutex<LockMap>,
}

/// A held guest lock; the guest is free again when it is dropped.
pub type GuestGuard = tokio::sync::OwnedMutexGuard<()>;

impl GuestLocks {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn entry(&self, account_id: &str, vmid: u32) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Entries nobody holds or waits on are dropped as the map is used.
        locks.retain(|_, lock| Arc::strong_count(lock) > 1);
        locks
            .entry((account_id.to_owned(), vmid))
            .or_default()
            .clone()
    }

    /// Waits for the guest's lock.
    pub async fn lock(&self, account_id: &str, vmid: u32) -> GuestGuard {
        self.entry(account_id, vmid).lock_owned().await
    }

    /// The guest's lock when nobody holds it, without waiting.
    #[must_use]
    pub fn try_lock(&self, account_id: &str, vmid: u32) -> Option<GuestGuard> {
        self.entry(account_id, vmid).try_lock_owned().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_holder_per_guest_and_a_try_never_waits() {
        let locks = GuestLocks::new();
        let held = locks.lock("acct", 100).await;
        assert!(locks.try_lock("acct", 100).is_none());
        // Another guest, and another account's guest, are free.
        assert!(locks.try_lock("acct", 101).is_some());
        assert!(locks.try_lock("other", 100).is_some());
        drop(held);
        assert!(locks.try_lock("acct", 100).is_some());
    }

    #[tokio::test]
    async fn a_waiter_gets_the_lock_when_the_holder_lets_go() {
        let locks = GuestLocks::new();
        let held = locks.lock("acct", 100).await;
        let waiter = {
            let locks = locks.clone();
            tokio::spawn(async move {
                let _guard = locks.lock("acct", 100).await;
            })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(held);
        waiter.await.unwrap();
    }
}
