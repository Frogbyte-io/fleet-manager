//! Bounded, payload-free notifications for clients to invalidate cached reads.
//!
//! Notifications deliberately contain only an event name and a cursor. A
//! client must refetch the resource through its normal authorized API.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

/// The kinds of state changes clients may use to invalidate cached queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// Machine status or inventory may have changed.
    MachineChanged,
    /// An operation's state or progress may have changed.
    OperationChanged,
    /// A Lab lease may have changed.
    LeaseChanged,
    /// An onboarding draft may have changed.
    OnboardingChanged,
    /// Proxmox observations may have changed.
    ProxmoxChanged,
    /// Tailnet observations may have changed.
    TailnetChanged,
}

impl EventKind {
    /// The stable SSE event name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MachineChanged => "machine.changed",
            Self::OperationChanged => "operation.changed",
            Self::LeaseChanged => "lease.changed",
            Self::OnboardingChanged => "onboarding.changed",
            Self::ProxmoxChanged => "proxmox.changed",
            Self::TailnetChanged => "tailnet.changed",
        }
    }
}

/// One notification with an opaque, process-scoped cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FleetEvent {
    /// The SSE `id` / `Last-Event-ID` token.
    pub id: String,
    /// The notification type. No resource data is included.
    pub kind: EventKind,
}

#[derive(Debug)]
struct EventState {
    epoch: String,
    sequence: u64,
    history: VecDeque<FleetEvent>,
}

/// The result of subscribing, including retained events to replay.
pub struct EventSubscription {
    /// Retained events after the caller's cursor, in sequence order.
    pub replay: VecDeque<FleetEvent>,
    /// Present when the requested cursor cannot be resumed and the client
    /// must refetch all authorized reads.
    pub gap_id: Option<String>,
    /// The bounded live receiver. A lagged receiver must be disconnected.
    pub receiver: broadcast::Receiver<FleetEvent>,
}

impl std::fmt::Debug for EventSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EventSubscription")
            .field("replay", &self.replay)
            .field("gap_id", &self.gap_id)
            .finish_non_exhaustive()
    }
}

/// A bounded in-process publisher and replay buffer for fleet change events.
#[derive(Debug)]
pub struct EventHub {
    state: Mutex<EventState>,
    sender: broadcast::Sender<FleetEvent>,
    capacity: usize,
}

impl EventHub {
    /// Creates a hub with a fixed replay and live-delivery capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        // Keep a minimally useful replay window and live ring. A one-event
        // window would turn an ordinary reconnect into a gap immediately.
        let capacity = capacity.max(2);
        let (sender, _) = broadcast::channel(capacity);
        let mut ids = fleet_core::UuidV7Generator;
        let epoch = fleet_core::IdGenerator::next_correlation_id(&mut ids).to_string();
        Self {
            state: Mutex::new(EventState {
                epoch,
                sequence: 0,
                history: VecDeque::with_capacity(capacity),
            }),
            sender,
            capacity,
        }
    }

    /// Publishes a payload-free event to the bounded replay buffer and
    /// currently connected clients.
    #[allow(clippy::must_use_candidate)]
    pub fn publish(&self, kind: EventKind) -> FleetEvent {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sequence = state.sequence.saturating_add(1);
        let event = FleetEvent {
            id: format!("{}:{}", state.epoch, state.sequence),
            kind,
        };
        if state.history.len() == self.capacity {
            state.history.pop_front();
        }
        state.history.push_back(event.clone());
        let _ = self.sender.send(event.clone());
        event
    }

    /// Subscribes atomically with respect to publishing. A matching retained
    /// cursor replays the missing events; an unknown, stale, or malformed
    /// cursor returns a gap marker.
    #[must_use]
    pub fn subscribe(&self, last_event_id: Option<&str>) -> EventSubscription {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let receiver = self.sender.subscribe();
        let latest_id = format!("{}:{}", state.epoch, state.sequence);
        let mut replay = VecDeque::new();
        let mut gap_id = None;

        if let Some(cursor) = last_event_id {
            let parsed = cursor
                .split_once(':')
                .and_then(|(epoch, sequence)| sequence.parse::<u64>().ok().map(|seq| (epoch, seq)));
            match parsed {
                Some((epoch, sequence)) if epoch == state.epoch && sequence <= state.sequence => {
                    let oldest = state
                        .history
                        .front()
                        .and_then(|event| event.id.rsplit_once(':'))
                        .and_then(|(_, value)| value.parse::<u64>().ok())
                        .unwrap_or(state.sequence.saturating_add(1));
                    if sequence.saturating_add(1) < oldest {
                        gap_id = Some(latest_id);
                    } else {
                        replay.extend(
                            state
                                .history
                                .iter()
                                .filter(|event| {
                                    event
                                        .id
                                        .rsplit_once(':')
                                        .and_then(|(_, value)| value.parse::<u64>().ok())
                                        .is_some_and(|event_sequence| event_sequence > sequence)
                                })
                                .cloned(),
                        );
                    }
                }
                _ => gap_id = Some(latest_id),
            }
        }

        EventSubscription {
            replay,
            gap_id,
            receiver,
        }
    }

    /// Returns the current cursor for a gap marker.
    #[must_use]
    pub fn current_id(&self) -> String {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        format!("{}:{}", state.epoch, state.sequence)
    }
}

/// The application service that authorizes subscriptions to event metadata.
#[derive(Debug)]
pub struct Events {
    hub: Arc<EventHub>,
}

impl Events {
    /// Composes the authorized event query service.
    #[must_use]
    pub fn new(hub: Arc<EventHub>) -> Self {
        Self { hub }
    }

    /// Publishes a payload-free change notification.
    #[allow(clippy::must_use_candidate)]
    pub fn publish(&self, kind: EventKind) -> FleetEvent {
        self.hub.publish(kind)
    }

    /// Returns the current cursor for a gap marker.
    #[must_use]
    pub fn current_id(&self) -> String {
        self.hub.current_id()
    }

    /// Returns a bounded stream subscription for an authorized caller.
    ///
    /// # Errors
    ///
    /// Returns the authorization denial when this principal lacks
    /// `events.read`.
    pub fn subscribe(
        &self,
        authorizer: &dyn crate::authz::Authorizer,
        principal_id: &str,
        last_event_id: Option<&str>,
    ) -> Result<EventSubscription, crate::authz::Decision> {
        self.authorize(authorizer, principal_id)?;
        Ok(self.hub.subscribe(last_event_id))
    }

    /// Rechecks a connected subscriber's permission before delivering an event.
    ///
    /// # Errors
    ///
    /// Returns the authorization denial when this principal lacks
    /// `events.read`.
    pub fn authorize(
        &self,
        authorizer: &dyn crate::authz::Authorizer,
        principal_id: &str,
    ) -> Result<(), crate::authz::Decision> {
        crate::authz::authorize(
            authorizer,
            crate::authz::AccessRequest {
                principal_id,
                action: crate::authz::Permission::EventsRead,
                resource: None,
            },
        )
        .map(|_| ())
    }
}

/// A useful default capacity for one controller process.
pub const DEFAULT_EVENT_CAPACITY: usize = 256;

#[cfg(test)]
mod tests {
    use super::{EventHub, EventKind};

    #[test]
    fn a_retained_cursor_replays_only_later_events() {
        let hub = EventHub::new(4);
        let first = hub.publish(EventKind::MachineChanged);
        let second = hub.publish(EventKind::LeaseChanged);
        let subscription = hub.subscribe(Some(&first.id));
        assert_eq!(
            subscription.replay.into_iter().collect::<Vec<_>>(),
            [second]
        );
        assert!(subscription.gap_id.is_none());
    }

    #[test]
    fn an_expired_or_foreign_cursor_requests_a_full_refetch() {
        let hub = EventHub::new(2);
        let first = hub.publish(EventKind::OperationChanged);
        hub.publish(EventKind::LeaseChanged);
        hub.publish(EventKind::MachineChanged);
        hub.publish(EventKind::OnboardingChanged);
        assert!(hub.subscribe(Some(&first.id)).gap_id.is_some());
        assert!(hub.subscribe(Some("foreign:1")).gap_id.is_some());
        assert!(hub.subscribe(Some("malformed-cursor")).gap_id.is_some());
        let epoch = first.id.split_once(':').unwrap().0;
        assert!(
            hub.subscribe(Some(&format!("{epoch}:999")))
                .gap_id
                .is_some()
        );
    }

    #[tokio::test]
    async fn slow_subscribers_are_detected_by_the_bounded_live_channel() {
        let hub = EventHub::new(1);
        let mut subscription = hub.subscribe(None);
        hub.publish(EventKind::MachineChanged);
        hub.publish(EventKind::LeaseChanged);
        hub.publish(EventKind::OperationChanged);
        assert!(matches!(
            subscription.receiver.recv().await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(1))
        ));
        assert_eq!(
            subscription.receiver.recv().await.unwrap().kind,
            EventKind::LeaseChanged
        );
        assert_eq!(
            subscription.receiver.recv().await.unwrap().kind,
            EventKind::OperationChanged
        );
    }
}
