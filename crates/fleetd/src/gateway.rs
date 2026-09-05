//! The gateway client: the node side of the WebSocket session.
//!
//! One connection, negotiated once and kept alive by heartbeats, exactly as
//! `controller-node-protocol.md` describes: `Hello` opens the session,
//! `Welcome` fixes its terms (protocol version, limits, heartbeat interval),
//! and the node sends `Heartbeat` at the agreed interval with monotonically
//! increasing sequences and monotonic node uptime. Anything else — a fault,
//! a close, a transport error — ends the connection, and the run loop
//! reconnects with bounded jitter after re-proving the session over HTTP.
//!
//! The journal position is reported as zero until the command journal
//! (FM-207) exists; the protocol field is present so the reconciliation
//! contract is exercised from day one.

use std::time::Duration;

use fleet_protocol::wire;
use fleet_protocol::{ProtocolFault, SUPPORTED_PROTOCOL_VERSIONS, decode_frame, encode_frame};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;

use crate::http::Controller;
use crate::inventory::InventoryState;
use crate::journal::NodeJournal;
use crate::state::{Jitter, NodeState};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The WebSocket subprotocol the client offers. Must match the controller's
/// `NODE_SUBPROTOCOL`; the negotiation is checked on both sides.
pub const NODE_SUBPROTOCOL: &str = "fleet.node.v1";

/// The longest a reconnect backoff may grow, before jitter.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// The first reconnect backoff, before jitter.
pub const FIRST_BACKOFF: Duration = Duration::from_millis(500);

/// An outcome of one connection attempt: keep the loop going or stop.
pub enum Attempt {
    /// The session ended; the run loop reconnects with backoff.
    Reconnect(String),
    /// The node must stop (shutdown signal or a fatal fault).
    Stop(String),
}

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Runs one connection to completion, from proof to heartbeat drain, and
/// reports what the run loop should do next.
#[allow(clippy::too_many_lines)]
pub async fn connect_once(
    controller: &Controller,
    state: &std::sync::Arc<NodeState>,
    journal: &std::sync::Arc<NodeJournal>,
    inventory: &std::sync::Arc<InventoryState>,
    shutdown: &mut (dyn std::future::Future<Output = ()> + Unpin + Send),
) -> Attempt {
    connect_once_with_status(
        controller,
        state,
        journal,
        inventory,
        &Arc::new(AtomicBool::new(false)),
        shutdown,
    )
    .await
}

/// The connection attempt with an observed connection flag, which the
/// local status surface reads.
#[allow(clippy::too_many_lines)]
pub async fn connect_once_with_status(
    controller: &Controller,
    state: &std::sync::Arc<NodeState>,
    journal: &std::sync::Arc<NodeJournal>,
    inventory: &std::sync::Arc<InventoryState>,
    connected: &Arc<AtomicBool>,
    shutdown: &mut (dyn std::future::Future<Output = ()> + Unpin + Send),
) -> Attempt {
    // The key proof happens over blocking HTTP on purpose: it is one small
    // LAN request per connection, not part of the async session loop.
    let session = match tokio::task::spawn_blocking({
        let controller = controller.clone();
        let state = state.clone();
        move || crate::session::prove(&controller, &state)
    })
    .await
    {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => return Attempt::Reconnect(error),
        Err(error) => return Attempt::Reconnect(format!("the proof task failed: {error}")),
    };

    let mut request = match controller.gateway_url().into_client_request() {
        Ok(request) => request,
        Err(error) => return Attempt::Reconnect(format!("the gateway URL is invalid: {error}")),
    };
    if let Err(error) = HeaderValue::from_str(&session.token)
        .map(|value| request.headers_mut().insert("x-fleet-node-session", value))
    {
        return Attempt::Reconnect(format!("the session token is not header-safe: {error}"));
    }
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(NODE_SUBPROTOCOL),
    );

    let (stream, _response) = match connect_async(request).await {
        Ok(connect) => connect,
        Err(error) => return Attempt::Reconnect(format!("the upgrade failed: {error}")),
    };
    let (mut sender, mut receiver) = stream.split();
    // Outbound frames (heartbeats and command results) flow through one
    // channel into the loop, so a command execution task can reply without
    // owning the connection.
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<wire::Frame>(16);
    eprintln!("fleetd: session proved (expires at {})", session.expires_at);

    // Hello: the node states what it is and what it supports.
    let hello = wire::Frame {
        message_id: uuid::Uuid::now_v7().to_string(),
        correlation_id: String::new(),
        sent_at_unix_millis: fleet_core::SystemClock::now_unix_millis(),
        payload: Some(wire::frame::Payload::Hello(wire::Hello {
            machine_id: state.machine_id().unwrap_or_default().to_owned(),
            node_version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_versions: Some(SUPPORTED_PROTOCOL_VERSIONS.to_wire()),
            inventory_schema_versions: Some(SUPPORTED_PROTOCOL_VERSIONS.to_wire()),
            session_id: uuid::Uuid::now_v7().to_string(),
            journal_position: u64::try_from(journal.record_count()).unwrap_or(u64::MAX),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            feature_flags: Vec::new(),
            last_acknowledged_operation_id: String::new(),
        })),
    };
    if let Err(error) = send_frame(&mut sender, hello).await {
        return Attempt::Reconnect(error);
    }

    // Welcome or a typed fault: both are actionable.
    let Some(wire::Frame {
        payload: Some(wire::frame::Payload::Welcome(welcome)),
        ..
    }) = receive_frame(&mut receiver).await
    else {
        return Attempt::Reconnect("the controller did not send a Welcome".to_owned());
    };
    let interval = Duration::from_millis(
        u64::try_from(welcome.heartbeat_interval_millis.max(1_000)).unwrap_or(15_000),
    );
    eprintln!(
        "fleetd: session accepted (protocol v{}, schema v{}, heartbeat {interval:?}, flags {:?})",
        welcome.protocol_version, welcome.inventory_schema_version, welcome.enabled_feature_flags
    );
    connected.store(true, Ordering::Relaxed);

    // The heartbeat loop. Monotonic uptime so clock steps cannot rewind it.
    let started = tokio::time::Instant::now();
    let mut sequence: u64 = 0;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut shutdown = shutdown;
    loop {
        tokio::select! {
            () = &mut shutdown => {
                let _ = sender.close().await;
                return Attempt::Stop("shutdown signal received; session drained".to_owned());
            }
            frame = outbound_rx.recv() => {
                match frame {
                    Some(frame) => {
                        if let Err(error) = send_frame(&mut sender, frame).await {
                            return Attempt::Reconnect(error);
                        }
                    }
                    None => {
                        return Attempt::Reconnect("the outbound channel closed".to_owned());
                    }
                }
            }
            _ = ticker.tick() => {
                sequence += 1;
                let heartbeat = wire::Frame {
                    message_id: uuid::Uuid::now_v7().to_string(),
                    correlation_id: String::new(),
                    sent_at_unix_millis: fleet_core::SystemClock::now_unix_millis(),
                    payload: Some(wire::frame::Payload::Heartbeat(wire::Heartbeat {
                        sequence,
                        node_uptime_millis: i64::try_from(
                            started.elapsed().as_millis(),
                        )
                        .unwrap_or(i64::MAX),
                        journal_position: u64::try_from(journal.record_count()).unwrap_or(u64::MAX),
                        in_flight_commands: 0,
                    })),
                };
                if let Err(error) = send_frame(&mut sender, heartbeat).await {
                    return Attempt::Reconnect(error);
                }
            }
            frame = receive_frame(&mut receiver) => {
                match frame {
                    Some(wire::Frame {
                        payload: Some(wire::frame::Payload::Fault(fault)),
                        ..
                    }) => {
                        let fault = ProtocolFault::from_wire(&fault);
                        let message = format!("the controller faulted: {}", fault.message());
                        return match fault.code() {
                            // Session state may heal on its own: re-prove and
                            // try again. Everything else is a build or wire
                            // problem no retry can fix.
                            wire::FaultCode::SessionRejected => Attempt::Reconnect(message),
                            _ => Attempt::Stop(message),
                        };
                    }
                    Some(wire::Frame {
                        payload: Some(wire::frame::Payload::Command(command)),
                        ..
                    }) => {
                        // At-least-once dispatch: the journal decides
                        // between replay, ignore, and execute. The result
                        // goes back through the outbound channel.
                        let journal = journal.clone();
                        let state = state.clone();
                        let inventory = inventory.clone();
                        let outbound = outbound_tx.clone();
                        let operation_id = command.operation_id.clone();
                        tokio::spawn(async move {
                            let outcome = tokio::task::spawn_blocking(move || {
                                crate::commands::execute(&journal, &state, &inventory, &command)
                            })
                            .await
                            .unwrap_or_else(|error| {
                                Err(format!("the command task failed: {error}"))
                            });
                            let result = match outcome {
                                Ok(outcome) => crate::commands::to_wire(&operation_id, &outcome),
                                Err(detail) => wire::CommandResult {
                                    operation_id: operation_id.clone(),
                                    status: wire::ResultStatus::Failed as i32,
                                    exit_code: 0,
                                    output_truncated: false,
                                    duration_millis: 0,
                                    stopped: false,
                                    fault: Some(wire::Fault {
                                        code: wire::FaultCode::MalformedFrame as i32,
                                        message: detail,
                                        retry: wire::FaultRetry::Never as i32,
                                        supported_protocol_versions: None,
                                    }),
                                    payload: Vec::new(),
                                },
                            };
                            let frame = wire::Frame {
                                message_id: uuid::Uuid::now_v7().to_string(),
                                correlation_id: String::new(),
                                sent_at_unix_millis: fleet_core::SystemClock::now_unix_millis(),
                                payload: Some(wire::frame::Payload::CommandResult(result)),
                            };
                            if outbound.send(frame).await.is_err() {
                                eprintln!("fleetd: the session closed before the result could be sent");
                            }
                        });
                    }
                    Some(_) => {
                        return Attempt::Reconnect(
                            "the controller sent an unexpected frame".to_owned(),
                        );
                    }
                    None => {
                        return Attempt::Reconnect("the connection closed".to_owned());
                    }
                }
            }
        }
    }
}

/// The bounded backoff schedule: exponential from the first interval, with
/// ±25% jitter, capped at [`MAX_BACKOFF`].
pub struct Backoff {
    current: Duration,
    jitter: Jitter,
}

impl Backoff {
    /// Creates the schedule from its first interval.
    #[must_use]
    pub fn new(first: Duration) -> Self {
        Self {
            current: first,
            jitter: Jitter::new(),
        }
    }

    /// The next wait: the current interval, jittered, then doubled for the
    /// caller's next call.
    #[must_use]
    pub fn wait(&mut self) -> Duration {
        let wait = self.jitter.scale(self.current);
        self.current = (self.current * 2).min(MAX_BACKOFF);
        wait
    }
}

async fn send_frame(
    sender: &mut futures_util::stream::SplitSink<WsStream, WsMessage>,
    frame: wire::Frame,
) -> Result<(), String> {
    let bytes = encode_frame(&frame).map_err(|fault| fault.message().to_owned())?;
    sender
        .send(WsMessage::Binary(bytes.into()))
        .await
        .map_err(|error| format!("the send failed: {error}"))
}

async fn receive_frame(
    receiver: &mut futures_util::stream::SplitStream<WsStream>,
) -> Option<wire::Frame> {
    loop {
        match receiver.next().await {
            Some(Ok(WsMessage::Binary(bytes))) => match decode_frame(&bytes) {
                Ok(frame) => return Some(frame),
                Err(fault) => {
                    eprintln!("fleetd: an undecodable frame arrived: {}", fault.message());
                    return None;
                }
            },
            Some(Ok(WsMessage::Close(_))) | None => return None,
            Some(Ok(_)) => {}
            Some(Err(error)) => {
                eprintln!("fleetd: transport error: {error}");
                return None;
            }
        }
    }
}

#[cfg(test)]
mod backoff_tests {
    use super::{Backoff, FIRST_BACKOFF, MAX_BACKOFF};
    use std::time::Duration;

    #[test]
    fn the_reconnect_backoff_is_bounded_and_jittered() {
        let mut backoff = Backoff::new(FIRST_BACKOFF);
        let mut previous = Duration::ZERO;
        for _ in 0..20 {
            let wait = backoff.wait();
            assert!(
                wait >= Duration::from_millis(100),
                "{wait:?} must not collapse to zero"
            );
            assert!(
                wait <= MAX_BACKOFF * 5 / 4,
                "{wait:?} must stay inside the jitter band of the capped base"
            );
            if previous >= MAX_BACKOFF / 2 {
                assert!(
                    wait >= MAX_BACKOFF / 2,
                    "the schedule must not shrink once it has grown: {previous:?} -> {wait:?}"
                );
            }
            previous = wait;
        }
    }

    #[test]
    fn the_first_interval_is_inside_the_jitter_band() {
        let mut backoff = Backoff::new(FIRST_BACKOFF);
        let wait = backoff.wait();
        assert!(
            wait >= FIRST_BACKOFF * 3 / 4 && wait <= FIRST_BACKOFF * 5 / 4,
            "the first wait must be inside the ±25% band: {wait:?}"
        );
    }
}
