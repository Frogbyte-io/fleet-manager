//! The node gateway: the controller side of the outbound WebSocket session.
//!
//! A node connects to `GET /api/node/v1/connect` after obtaining a
//! short-lived session by key proof (see `fleet-application::node` and the
//! enrollment contract in `proto/README.md`). The gateway owns four things,
//! and nothing else:
//!
//! 1. **Session admission.** The upgrade request must present a live node
//!    session (`x-fleet-node-session`) and offer the node-protocol
//!    subprotocol. Neither is negotiable; both failures are actionable.
//! 2. **Version negotiation.** The first frame must be `Hello`; the
//!    controller negotiates a common protocol and inventory-schema version
//!    with the FM-007 machinery and answers `Welcome` — or a typed `Fault`
//!    that names which peer is behind.
//! 3. **One session per node.** The registry holds at most one live session
//!    per machine. A second connect supersedes the first: the older loop is
//!    notified with a stored permit, answers `Fault{SESSION_REJECTED}` and
//!    closes, so a reconnecting node always wins without wedging the
//!    registry.
//! 4. **Sparse state.** Heartbeats update the registry's memory only. A
//!    background sweeper transitions `connected` → `stale` after two missed
//!    intervals and persists **only on transition**; a closed connection
//!    persists `offline` once. Connect/disconnect/superseded transitions are
//!    audited; staleness is observable in durable node state, deliberately
//!    not audited, because an offline node flaps faster than an operator can
//!    read the ledger.
//!
//! Commands, inventory deltas, and journal reconciliation are later issues
//! (FM-206/FM-207); this channel carries liveness and negotiation only.
#![warn(missing_docs)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header::SEC_WEBSOCKET_PROTOCOL};
use axum::response::Response;
use fleet_application::audit::AuditIntent;
use fleet_application::node::{GatewayState, NodePort, Nodes, SessionValidity};
use fleet_application::operation::AuditPort;
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use fleet_protocol::wire;
use fleet_protocol::{
    HEARTBEAT_INTERVAL_MILLIS, ProtocolFault, SUPPORTED_PROTOCOL_VERSIONS, VersionRange,
    decode_frame, encode_frame, negotiate_feature_flags, negotiate_protocol_version,
    session_limits,
};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use std::str::FromStr as _;
use uuid::Uuid;

/// The WebSocket subprotocol this build speaks. A client that does not offer
/// it is refused before any protocol frame flows.
pub const NODE_SUBPROTOCOL: &str = "fleet.node.v1";
/// The HTTP header that carries the node session on the upgrade request.
pub const SESSION_HEADER: &str = "x-fleet-node-session";

/// How many heartbeat intervals a session may go without a heartbeat before
/// it is considered stale: two, so one lost frame is not a state change.
pub const STALE_AFTER_HEARTBEATS: i64 = 2;

/// The sweeper's tick. Short enough that a stale session is seen within a
/// few seconds; a tick on a quiet registry is a read of an empty map.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// One live gateway session.
#[derive(Debug)]
pub struct SessionEntry {
    /// The node's boot/session id from `Hello`.
    pub boot_session: String,
    /// The negotiated protocol version.
    pub protocol_version: u32,
    /// The last heartbeat's monotonically increasing sequence.
    pub heartbeat_sequence: AtomicU64,
    /// The journal position the node last reported.
    pub journal_position: AtomicU64,
    /// The last heartbeat's arrival, in Unix epoch milliseconds.
    pub last_seen_millis: AtomicI64,
    /// The gateway state last persisted for this session.
    pub persisted_state: Mutex<GatewayState>,
    /// The supersede signal: holds a permit when a newer session takes over,
    /// so a loop that is mid-read still observes the takeover on return.
    pub superseded: Arc<tokio::sync::Notify>,
}

impl SessionEntry {
    fn new(boot_session: String, protocol_version: u32, now_millis: i64) -> Self {
        Self {
            boot_session,
            protocol_version,
            heartbeat_sequence: AtomicU64::new(0),
            journal_position: AtomicU64::new(0),
            last_seen_millis: AtomicI64::new(now_millis),
            persisted_state: Mutex::new(GatewayState::Offline),
            superseded: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// The registry's view of freshness, computed against a sweeper tick.
    fn observed_state(&self, now_millis: i64, stale_after_millis: i64) -> GatewayState {
        if now_millis - self.last_seen_millis.load(Ordering::Relaxed) > stale_after_millis {
            GatewayState::Stale
        } else {
            GatewayState::Connected
        }
    }
}

/// The in-memory registry of live sessions, at most one per machine.
#[derive(Debug, Default)]
pub struct Registry {
    sessions: Mutex<HashMap<String, Arc<SessionEntry>>>,
}

impl Registry {
    /// Inserts a session, superseding any previous one for the machine.
    /// Returns the superseded entry so its loop can drain it.
    fn insert(&self, machine_id: &str, entry: Arc<SessionEntry>) -> Option<Arc<SessionEntry>> {
        let superseded = {
            let mut sessions = self.sessions.lock().expect("uncontended");
            sessions
                .insert(machine_id.to_owned(), entry)
                .inspect(|old| {
                    old.superseded.notify_one();
                })
        };
        if let Some(old) = &superseded {
            eprintln!(
                "node gateway: superseding session for machine {machine_id} (old boot session {})",
                old.boot_session
            );
        }
        superseded
    }

    /// Removes the session if it is still the registered one; a superseded
    /// loop exits later and must not remove its replacement.
    fn remove_if_current(&self, machine_id: &str, boot_session: &str) {
        let mut sessions = self.sessions.lock().expect("uncontended");
        if sessions
            .get(machine_id)
            .map(|entry| entry.boot_session == boot_session)
            .unwrap_or(false)
        {
            sessions.remove(machine_id);
        }
    }

    fn all(&self) -> Vec<(String, Arc<SessionEntry>)> {
        self.sessions
            .lock()
            .expect("uncontended")
            .iter()
            .map(|(machine_id, entry)| (machine_id.clone(), entry.clone()))
            .collect()
    }
}

/// The gateway service: the registry plus the ports it persists through.
#[derive(Debug)]
pub struct GatewayService {
    nodes: Arc<Nodes>,
    port: Arc<dyn NodePort>,
    audit: Arc<dyn AuditPort>,
    registry: Arc<Registry>,
}

impl GatewayService {
    /// Composes the gateway from the node trust service and its storage.
    #[must_use]
    pub fn new(nodes: Arc<Nodes>, port: Arc<dyn NodePort>, audit: Arc<dyn AuditPort>) -> Self {
        Self {
            nodes,
            port,
            audit,
            registry: Arc::new(Registry::default()),
        }
    }

    /// The WebSocket upgrade handler, mounted at `/api/node/v1/connect`.
    ///
    /// # Panics
    ///
    /// Panics only if a pinned literal error code stops being valid syntax,
    /// which is a constant path the protocol crate's tests pin.
    async fn connect(
        State(self_arc): State<Arc<GatewayService>>,
        ws: WebSocketUpgrade,
        headers: HeaderMap,
    ) -> Result<Response, fleet_api::ApiErrorResponse> {
        let reject = |code: &'static str, message: String, status: StatusCode| {
            let public = PublicError::new(
                ErrorCode::from_str(code).expect("the literal is valid"),
                message,
                RetryClass::Never,
            );
            fleet_api::ApiError::new(&public, correlation()).with_status(status)
        };

        // The subprotocol is the outer transport contract: a client that
        // does not offer it cannot have been built for this protocol.
        let offers_subprotocol = headers
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(',')
                    .any(|candidate| candidate.trim() == NODE_SUBPROTOCOL)
            })
            .unwrap_or(false);
        if !offers_subprotocol {
            return Err(reject(
                "node_protocol_subprotocol",
                format!("the upgrade must offer the WebSocket subprotocol {NODE_SUBPROTOCOL:?}"),
                StatusCode::BAD_REQUEST,
            ));
        }

        // The session is the whole authentication: present it or stop here.
        let Some(session_token) = headers
            .get(SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
        else {
            return Err(reject(
                "node_session_required",
                format!("the upgrade must present a node session in {SESSION_HEADER:?}"),
                StatusCode::UNAUTHORIZED,
            ));
        };
        let machine_id = match self_arc.nodes.validate_session(&session_token).await {
            Ok(SessionValidity::Valid { machine_id, .. }) => machine_id,
            Ok(SessionValidity::Invalid { detail }) => {
                return Err(reject(
                    "node_session_rejected",
                    detail,
                    StatusCode::UNAUTHORIZED,
                ));
            }
            Err(error) => {
                return Err(reject(
                    "node_session_rejected",
                    error.to_string(),
                    StatusCode::UNAUTHORIZED,
                ));
            }
        };

        Ok(ws
            .protocols([NODE_SUBPROTOCOL])
            .on_upgrade(move |socket| async move {
                self_arc.serve_session(socket, machine_id).await;
            }))
    }

    /// One connected node session: negotiate, then serve heartbeats until
    /// the socket closes or a newer session supersedes this one.
    async fn serve_session(self: Arc<Self>, socket: WebSocket, machine_id: String) {
        let (mut sender, mut receiver) = socket.split();
        let now = fleet_core::SystemClock::now_unix_millis();
        let boot_session = Uuid::now_v7().to_string();

        // Handshake: Hello or nothing.
        let Some(wire::Frame {
            payload: Some(wire::frame::Payload::Hello(hello)),
            ..
        }) = receive_frame(&mut receiver, &machine_id).await
        else {
            send_fault(
                &mut sender,
                ProtocolFault::new(wire::FaultCode::MalformedFrame),
            )
            .await;
            return;
        };

        // Version negotiation is the handshake's second gate: a mismatch is
        // answered with the typed fault that names the supported range, so
        // an operator can see exactly which peer is behind.
        let negotiate = |wire_range: Option<&wire::VersionRange>| match wire_range {
            Some(raw) => match VersionRange::from_wire(raw) {
                Ok(range) => negotiate_protocol_version(range, SUPPORTED_PROTOCOL_VERSIONS),
                Err(_) => Err(ProtocolFault::new(wire::FaultCode::MalformedFrame)),
            },
            None => Err(ProtocolFault::new(wire::FaultCode::MalformedFrame)),
        };
        let negotiated = match negotiate(hello.protocol_versions.as_ref()) {
            Ok(version) => version,
            Err(fault) => {
                eprintln!(
                    "node gateway: refusing machine {machine_id}: {}",
                    fault.message()
                );
                send_fault(&mut sender, fault).await;
                return;
            }
        };
        let inventory_schema_version = match negotiate(hello.inventory_schema_versions.as_ref()) {
            Ok(version) => version,
            Err(fault) => {
                eprintln!(
                    "node gateway: refusing machine {machine_id} inventory schema: {}",
                    fault.message()
                );
                send_fault(&mut sender, fault).await;
                return;
            }
        };

        // Admit the session, superseding any earlier one for this machine.
        let entry = Arc::new(SessionEntry::new(
            boot_session.clone(),
            negotiated.value(),
            now,
        ));
        if self.registry.insert(&machine_id, entry.clone()).is_some() {
            self.audit_event(&machine_id, "gateway_superseded");
        }

        let welcome = wire::Frame {
            message_id: Uuid::now_v7().to_string(),
            correlation_id: String::new(),
            sent_at_unix_millis: now,
            payload: Some(wire::frame::Payload::Welcome(wire::Welcome {
                protocol_version: negotiated.value(),
                inventory_schema_version: inventory_schema_version.value(),
                session_id: boot_session.clone(),
                enabled_feature_flags: negotiate_feature_flags::<String, String>(
                    &[],
                    &hello.feature_flags,
                ),
                limits: Some(session_limits()),
                heartbeat_interval_millis: HEARTBEAT_INTERVAL_MILLIS,
            })),
        };
        if !send_frame(&mut sender, welcome).await {
            self.finish_session(&machine_id, &boot_session, &entry)
                .await;
            return;
        }

        // The connect transition is durable and audited, once.
        self.persist_transition(&machine_id, GatewayState::Connected, &entry)
            .await;
        self.audit_event(&machine_id, "gateway_connected");
        eprintln!(
            "node gateway: machine {machine_id} connected (boot session {boot_session}, \
             protocol {}, flags {:?})",
            negotiated, hello.feature_flags
        );

        // The session loop: heartbeats in, supersede or close out.
        loop {
            tokio::select! {
                _ = entry.superseded.notified() => {
                    send_fault(&mut sender, ProtocolFault::new(wire::FaultCode::SessionRejected)).await;
                    self.audit_event(&machine_id, "gateway_superseded");
                    self.finish_session(&machine_id, &boot_session, &entry).await;
                    return;
                }
                frame = receive_frame(&mut receiver, &machine_id) => {
                    match frame {
                        None => {
                            self.audit_event(&machine_id, "gateway_disconnected");
                            self.finish_session(&machine_id, &boot_session, &entry).await;
                            return;
                        }
                        Some(wire::Frame {
                            payload: Some(wire::frame::Payload::Heartbeat(heartbeat)),
                            ..
                        }) => {
                            entry
                                .heartbeat_sequence
                                .store(heartbeat.sequence, Ordering::Relaxed);
                            entry
                                .journal_position
                                .store(heartbeat.journal_position, Ordering::Relaxed);
                            let seen = fleet_core::SystemClock::now_unix_millis();
                            entry.last_seen_millis.store(seen, Ordering::Relaxed);
                            // A recovered heartbeat un-marks staleness; the
                            // persist helper writes only on transition.
                            self.persist_transition(&machine_id, GatewayState::Connected, &entry).await;
                        }
                        Some(_) => {
                            // An unexpected frame cannot be acted on; the
                            // peer is told in the protocol's own vocabulary.
                            send_fault(&mut sender, ProtocolFault::new(wire::FaultCode::UnknownPayload)).await;
                        }
                    }
                }
            }
        }
    }

    /// Persists a gateway-state transition when, and only when, the state
    /// actually changed. Heartbeats call this with `Connected`; the stored
    /// state is already `Connected`, so nothing is written.
    async fn persist_transition(
        &self,
        machine_id: &str,
        state: GatewayState,
        entry: &SessionEntry,
    ) {
        {
            let mut persisted = entry.persisted_state.lock().expect("uncontended");
            if *persisted == state {
                return;
            }
            *persisted = state;
        }
        let last_seen = entry.last_seen_millis.load(Ordering::Relaxed);
        if let Err(error) = self
            .port
            .record_gateway_state(machine_id, state, Some(&entry.boot_session), last_seen)
            .await
        {
            eprintln!("node gateway: cannot persist {state:?} for machine {machine_id}: {error}");
        } else {
            eprintln!("node gateway: machine {machine_id} is now {}", state.id());
        }
    }

    /// Leaves the registry and settles the durable state to offline, once.
    async fn finish_session(&self, machine_id: &str, boot_session: &str, entry: &SessionEntry) {
        self.registry.remove_if_current(machine_id, boot_session);
        entry.last_seen_millis.store(
            fleet_core::SystemClock::now_unix_millis(),
            Ordering::Relaxed,
        );
        self.persist_transition(machine_id, GatewayState::Offline, entry)
            .await;
        eprintln!("node gateway: machine {machine_id} session ended");
    }

    /// Appends one gateway audit event under the node actor.
    fn audit_event(&self, machine_id: &str, event: &'static str) {
        let mut metadata = fleet_application::audit::AuditMetadata::default();
        if metadata.insert("event", event).is_err() {
            return;
        }
        let intent = AuditIntent {
            actor: format!("node:{machine_id}"),
            action: "node.gateway".to_owned(),
            resource: Some(machine_id.to_owned()),
            decision: fleet_application::authz::Decision::allow(),
            correlation_id: None,
            operation_id: None,
            metadata,
        };
        let audit = self.audit.clone();
        tokio::spawn(async move {
            if let Err(error) = audit.record_intent(&intent).await {
                eprintln!("node gateway: audit write failed: {error}");
            }
        });
    }

    /// The staleness sweeper: transitions open-but-quiet sessions to stale
    /// and back, persisting only on transitions.
    pub async fn run_staleness_sweeper(
        self: Arc<Self>,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) {
        self.run_staleness_sweeper_with(
            SWEEP_INTERVAL,
            STALE_AFTER_HEARTBEATS * HEARTBEAT_INTERVAL_MILLIS,
            shutdown,
        )
        .await;
    }

    /// The parameterized sweeper the production runner uses with its
    /// constants and tests use with compressed timing.
    pub async fn run_staleness_sweeper_with(
        self: Arc<Self>,
        tick: Duration,
        stale_after_millis: i64,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) {
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => {
                    eprintln!("node gateway sweeper draining");
                    return;
                }
                _ = interval.tick() => {
                    let now = fleet_core::SystemClock::now_unix_millis();
                    for (machine_id, entry) in self.registry.all() {
                        let observed = entry.observed_state(now, stale_after_millis);
                        if observed == GatewayState::Connected {
                            continue;
                        }
                        self.persist_transition(&machine_id, observed, &entry).await;
                    }
                }
            }
        }
    }

    /// The live session registered for a machine, for observability and
    /// tests. None means no open session.
    #[must_use]
    pub async fn session_of(&self, machine_id: &str) -> Option<Arc<SessionEntry>> {
        self.registry
            .sessions
            .lock()
            .expect("uncontended")
            .get(machine_id)
            .cloned()
    }
}

/// The node-surface router fragment carrying the gateway route. The
/// controller merges this with `fleet_api::node::node_router` at
/// `/api/node/v1` so both share one nest.
pub fn gateway_router(service: Arc<GatewayService>) -> axum::Router {
    axum::Router::new()
        .route("/connect", axum::routing::get(GatewayService::connect))
        .with_state(service)
}

fn correlation() -> CorrelationId {
    CorrelationId::try_from(Uuid::now_v7()).expect("now_v7 identifiers are version 7")
}

/// Reads one binary frame, treating any close, error, or undecodable frame
/// as session end.
async fn receive_frame(
    receiver: &mut SplitStream<WebSocket>,
    machine_id: &str,
) -> Option<wire::Frame> {
    loop {
        match receiver.next().await {
            Some(Ok(WsMessage::Binary(bytes))) => {
                return match decode_frame(&bytes) {
                    Ok(frame) => Some(frame),
                    Err(fault) => {
                        eprintln!(
                            "node gateway: machine {machine_id} sent an undecodable frame: {}",
                            fault.message()
                        );
                        return None;
                    }
                };
            }
            Some(Ok(WsMessage::Close(_))) | None => return None,
            Some(Ok(_)) => continue,
            Some(Err(error)) => {
                eprintln!("node gateway: machine {machine_id} transport error: {error}");
                return None;
            }
        }
    }
}

async fn send_frame(sender: &mut SplitSink<WebSocket, WsMessage>, frame: wire::Frame) -> bool {
    match encode_frame(&frame) {
        Ok(bytes) => sender.send(WsMessage::Binary(bytes.into())).await.is_ok(),
        Err(fault) => {
            eprintln!("node gateway: cannot encode a frame: {}", fault.message());
            false
        }
    }
}

async fn send_fault(sender: &mut SplitSink<WebSocket, WsMessage>, fault: ProtocolFault) {
    let frame = wire::Frame {
        message_id: Uuid::now_v7().to_string(),
        correlation_id: String::new(),
        sent_at_unix_millis: fleet_core::SystemClock::now_unix_millis(),
        payload: Some(wire::frame::Payload::Fault(fault.to_wire())),
    };
    let _ = send_frame(sender, frame).await;
    let _ = sender.close().await;
}
