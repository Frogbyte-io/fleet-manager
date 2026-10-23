//! The interactive machine terminal (#494): a shell on a Fleet machine over
//! its SSH endpoint, in the console or in `fleetctl`.
//!
//! A terminal is two steps, mirroring the Proxmox console's session shape:
//!
//! 1. [`MachineAccess::terminal_create`] authorizes `machines.terminal` on
//!    the machine, resolves the endpoint and its credential the way a
//!    machine exec does (the host key must be confirmed, an explicit auth
//!    needs `machine.update`), audits the request, and mints a short-lived,
//!    **single-use** session token. Only its SHA-256 is kept.
//! 2. The caller presents the token when it attaches
//!    ([`MachineAccess::terminal_attach`]). Authorization is decided again
//!    for the attaching caller, the session leaves the *waiting* set and
//!    enters the *attached* set in one critical section (so the caps always
//!    count it), the start is audited, and only then is the `ssh` session
//!    opened through the [`TerminalPort`]. The token is worthless once used.
//!
//! [`MachineAccess::terminal_run`] then relays between the caller's
//! connection ([`TerminalClient`]) and the guest ([`TerminalChannel`]) under
//! the bounds: an idle limit measured on the caller's input, a maximum
//! duration, a send deadline and a liveness ping toward the caller, and a
//! clean close when the controller shuts down. The end is audited with the
//! principal, machine, endpoint, duration and close reason.
//!
//! Nothing typed or shown is read, logged, or recorded: the audit trail and
//! every error carry identities and reasons, never terminal content. The
//! adapters (the controller's WebSocket route, `fleetctl`) own the framing
//! and nothing else.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fleet_core::SensitiveString;
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Permission, authorize};
use crate::lab::LabUseCaseError;
use crate::machine_access::{AccessTarget, EndpointAuth, MachineAccess};

/// How long an unattached session token stays valid.
pub const SESSION_TOKEN_TTL: Duration = Duration::from_secs(120);

/// The default most sessions (waiting or attached) the controller holds.
pub const DEFAULT_MAX_SESSIONS: usize = 16;

/// The default most sessions one principal may hold.
pub const DEFAULT_MAX_SESSIONS_PER_PRINCIPAL: usize = 4;

/// The default idle bound: no input from the caller for this long closes the
/// session.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_mins(10);

/// The default maximum duration of one session.
pub const DEFAULT_MAX_DURATION: Duration = Duration::from_hours(1);

/// The longest a configured maximum duration may be. A session's key file
/// lives as long as the session, and the provider reclaims key files older
/// than seven hours, so a session must end before that.
pub const MAX_CONFIGURED_DURATION: Duration = Duration::from_hours(6);

/// How long the relay waits to hand output to the caller, or input to the
/// guest, before it gives up on the connection.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the relay pings the caller.
pub const PING_INTERVAL: Duration = Duration::from_secs(20);

/// How long the relay tolerates hearing nothing at all (not even a pong)
/// from the caller before it closes the session as lost.
pub const PEER_TIMEOUT: Duration = Duration::from_secs(60);

/// The widest and tallest terminal a caller may ask for.
pub const MAX_DIMENSION: u16 = 1000;

/// The terminal size a session starts with when the caller names none.
pub const DEFAULT_SIZE: (u16, u16) = (80, 24);

/// The bounds applied to the terminal sessions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalLimits {
    /// Close after this long without input from the caller.
    pub idle: Duration,
    /// Close after this long regardless.
    pub max_duration: Duration,
    /// The most sessions (waiting or attached) at once.
    pub max_sessions: usize,
    /// The most sessions one principal may hold at once.
    pub max_per_principal: usize,
}

impl Default for TerminalLimits {
    fn default() -> Self {
        Self {
            idle: DEFAULT_IDLE_TIMEOUT,
            max_duration: DEFAULT_MAX_DURATION,
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_per_principal: DEFAULT_MAX_SESSIONS_PER_PRINCIPAL,
        }
    }
}

impl TerminalLimits {
    /// Whether the limits are usable: nonzero, and a maximum duration within
    /// [`MAX_CONFIGURED_DURATION`].
    ///
    /// # Errors
    ///
    /// Names the first limit that is out of range.
    pub fn validate(&self) -> Result<(), String> {
        if self.idle.is_zero() {
            return Err("the terminal idle timeout must be positive".to_owned());
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_CONFIGURED_DURATION {
            return Err(format!(
                "the terminal maximum duration must be 1..={} seconds",
                MAX_CONFIGURED_DURATION.as_secs()
            ));
        }
        if self.max_sessions == 0 || self.max_per_principal == 0 {
            return Err("the terminal session caps must be positive".to_owned());
        }
        Ok(())
    }
}

/// Why an attached terminal ended. The identifiers are audit-stable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalCloseReason {
    /// The caller closed its connection.
    Client,
    /// The shell ended (the user exited, or `ssh` failed to connect).
    Exited,
    /// No input from the caller within the idle bound.
    Idle,
    /// The maximum duration elapsed.
    MaxDuration,
    /// The controller is shutting down.
    Shutdown,
    /// The caller stopped answering (a stalled or vanished connection).
    PeerLost,
    /// The relay failed.
    Error,
}

impl TerminalCloseReason {
    /// The stable identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Exited => "exited",
            Self::Idle => "idle",
            Self::MaxDuration => "max_duration",
            Self::Shutdown => "shutdown",
            Self::PeerLost => "peer_lost",
            Self::Error => "error",
        }
    }
}

/// What a guest terminal produced next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalOutput {
    /// Bytes the guest wrote.
    Data(Vec<u8>),
    /// The session ended; the code is absent when a signal ended it.
    Exited(Option<i32>),
}

/// An open terminal on a guest. The controller's SSH provider is translated
/// into this at the composition root; tests implement it in memory.
#[async_trait]
pub trait TerminalChannel: fmt::Debug + Send {
    /// The next output, or the end of the session. Cancel-safe, and once the
    /// session ended every call answers [`TerminalOutput::Exited`].
    async fn next(&mut self) -> TerminalOutput;

    /// Sends input (keystrokes, pasted text) to the guest.
    ///
    /// # Errors
    ///
    /// Fails with a bounded, caller-safe detail.
    async fn write(&mut self, data: &[u8]) -> Result<(), String>;

    /// Resizes the terminal. The size is already validated.
    ///
    /// # Errors
    ///
    /// Fails with a bounded, caller-safe detail.
    fn resize(&mut self, cols: u16, rows: u16) -> Result<(), String>;

    /// Ends the session, best effort.
    async fn close(&mut self);
}

/// What the port needs to open one terminal.
#[derive(Clone, Debug)]
pub struct TerminalOpen {
    /// The machine.
    pub machine_id: String,
    /// The SSH endpoint.
    pub endpoint_id: String,
    /// How the endpoint authenticates; a stored key is resolved just in time.
    pub auth: EndpointAuth,
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
}

/// The port that opens a machine's terminal. The controller implements it
/// over the SSH provider; tests implement it in memory.
#[async_trait]
pub trait TerminalPort: fmt::Debug + Send + Sync {
    /// A fresh, unguessable session token. Shown once, never stored.
    fn new_session_token(&self) -> String;

    /// Opens the shell: resolves the credential just in time, enforces the
    /// host-key trust gate, and starts `ssh` under a PTY.
    ///
    /// # Errors
    ///
    /// Fails with a bounded, caller-safe detail (no key text).
    async fn open(&self, request: &TerminalOpen) -> Result<Box<dyn TerminalChannel>, String>;
}

/// One message from the caller's connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientMessage {
    /// Keystrokes or pasted text for the guest.
    Input(Vec<u8>),
    /// The caller's window changed.
    Resize {
        /// Columns.
        cols: u16,
        /// Rows.
        rows: u16,
    },
    /// Proof the connection is alive (a pong, or any frame that carries no
    /// input).
    Alive,
    /// The caller closed its connection.
    Closed,
}

/// The caller's side of an attached terminal: a WebSocket in the console and
/// in `fleetctl`.
#[async_trait]
pub trait TerminalClient: Send {
    /// The next message. Cancel-safe.
    async fn recv(&mut self) -> ClientMessage;

    /// Hands output to the caller.
    ///
    /// # Errors
    ///
    /// Fails when the connection is gone.
    async fn send_output(&mut self, data: Vec<u8>) -> Result<(), String>;

    /// Pings the caller to prove it is still there.
    ///
    /// # Errors
    ///
    /// Fails when the connection is gone.
    async fn send_ping(&mut self) -> Result<(), String>;

    /// Tells the caller why the session ended and closes the connection.
    async fn close(&mut self, reason: TerminalCloseReason, exit_code: Option<i32>);
}

/// A session waiting for its connection.
struct Pending {
    session_id: String,
    principal_id: String,
    machine_id: String,
    endpoint_id: String,
    auth: EndpointAuth,
    size: (u16, u16),
    expires_at: i64,
}

/// An attached session.
struct Active {
    principal_id: String,
    machine_id: String,
    endpoint_id: String,
}

#[derive(Default)]
struct Ledger {
    pending: HashMap<String, Pending>,
    active: HashMap<String, Active>,
}

/// The session ledger and the bounds: what is waiting, what is attached, and
/// how many more may start. Counting and moving a session between the two
/// sets happen under one lock, so no interleaving of creates and attaches
/// can exceed a cap.
pub struct TerminalSessions {
    port: Arc<dyn TerminalPort>,
    ledger: Mutex<Ledger>,
    limits: TerminalLimits,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl fmt::Debug for TerminalSessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TerminalSessions")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// The lowercase hex SHA-256 of a session token.
fn hash_token(token: &str) -> String {
    use std::fmt::Write as _;
    Sha256::digest(token.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

fn ttl_millis() -> i64 {
    i64::try_from(SESSION_TOKEN_TTL.as_millis()).unwrap_or(i64::MAX)
}

/// Returns an attached session's slot to the ledger when dropped, so a
/// relay that panics or is cancelled cannot leak a slot toward the cap.
struct ActiveSlot {
    sessions: Arc<TerminalSessions>,
    session_id: String,
}

impl Drop for ActiveSlot {
    fn drop(&mut self) {
        self.sessions.ledger().active.remove(&self.session_id);
    }
}

impl TerminalSessions {
    /// Composes the ledger over a port, with the bounds.
    #[must_use]
    pub fn new(port: Arc<dyn TerminalPort>, limits: TerminalLimits) -> Arc<Self> {
        Arc::new(Self {
            port,
            ledger: Mutex::new(Ledger::default()),
            limits,
            shutdown: tokio::sync::watch::channel(false).0,
        })
    }

    /// The ledger. A poisoned lock still holds a consistent ledger (every
    /// critical section is a few map operations), so it is used.
    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The bounds.
    #[must_use]
    pub fn limits(&self) -> TerminalLimits {
        self.limits
    }

    /// Reserves a waiting slot, refusing past the caps. Waiting sessions that
    /// expired are dropped first. Returns the token and its session id.
    fn reserve(
        &self,
        principal_id: &str,
        machine_id: &str,
        endpoint_id: &str,
        auth: &EndpointAuth,
        size: (u16, u16),
        now: i64,
    ) -> Result<(String, String, i64), LabUseCaseError> {
        let token = self.port.new_session_token();
        let hash = hash_token(&token);
        let session_id = format!("terminal-{}", &hash[..16]);
        let expires_at = now.saturating_add(ttl_millis());
        let mut ledger = self.ledger();
        ledger.pending.retain(|_, pending| pending.expires_at > now);
        let mine = ledger
            .pending
            .values()
            .map(|pending| pending.principal_id.as_str())
            .chain(ledger.active.values().map(|active| active.principal_id.as_str()))
            .filter(|owner| *owner == principal_id)
            .count();
        if ledger.pending.len() + ledger.active.len() >= self.limits.max_sessions
            || mine >= self.limits.max_per_principal
        {
            return Err(LabUseCaseError::Busy {
                detail: format!(
                    "too many terminal sessions are open (at most {} on the controller, {} per principal); close one first",
                    self.limits.max_sessions, self.limits.max_per_principal
                ),
            });
        }
        ledger.pending.insert(
            hash,
            Pending {
                session_id: session_id.clone(),
                principal_id: principal_id.to_owned(),
                machine_id: machine_id.to_owned(),
                endpoint_id: endpoint_id.to_owned(),
                auth: auth.clone(),
                size,
                expires_at,
            },
        );
        Ok((token, session_id, expires_at))
    }

    /// Drops a waiting session (its audit failed).
    fn forget(&self, token: &str) {
        self.ledger().pending.remove(&hash_token(token));
    }

    /// Consumes a token: the session leaves the waiting set and joins the
    /// attached set in one critical section, so the caps never see it
    /// missing. A token that is unknown, spent, expired, or owned by another
    /// principal is refused the same way, and the last is left unspent.
    fn claim(
        self: &Arc<Self>,
        principal_id: &str,
        token: &str,
        now: i64,
    ) -> Result<(Pending, ActiveSlot), LabUseCaseError> {
        let unknown = || LabUseCaseError::NotFound {
            what: "terminal session (unknown, already used, or expired)".to_owned(),
        };
        let hash = hash_token(token);
        let mut ledger = self.ledger();
        let Some(waiting) = ledger.pending.get(&hash) else {
            return Err(unknown());
        };
        if waiting.expires_at <= now {
            ledger.pending.remove(&hash);
            return Err(unknown());
        }
        if waiting.principal_id != principal_id {
            return Err(unknown());
        }
        let pending = ledger.pending.remove(&hash).ok_or_else(unknown)?;
        ledger.active.insert(
            pending.session_id.clone(),
            Active {
                principal_id: pending.principal_id.clone(),
                machine_id: pending.machine_id.clone(),
                endpoint_id: pending.endpoint_id.clone(),
            },
        );
        let slot = ActiveSlot {
            sessions: Arc::clone(self),
            session_id: pending.session_id.clone(),
        };
        Ok((pending, slot))
    }

    /// Tells every attached terminal the controller is shutting down; each
    /// relay closes cleanly and records its end.
    pub fn shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    /// How many terminals are attached right now.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.ledger().active.len()
    }

    /// How many sessions are waiting or attached.
    #[must_use]
    pub fn session_count(&self) -> usize {
        let ledger = self.ledger();
        ledger.pending.len() + ledger.active.len()
    }
}

/// A created, unattached session: the only place the token exists.
pub struct NewTerminalSession {
    /// The session's identity, as it appears in audit events (not a
    /// credential).
    pub session_id: String,
    /// The single-use token the caller presents to attach.
    pub token: SensitiveString,
    /// When the token stops being valid (epoch millis).
    pub expires_at: i64,
    /// The machine.
    pub machine_id: String,
    /// The SSH endpoint.
    pub endpoint_id: String,
    /// The bounds the attached terminal runs under.
    pub limits: TerminalLimits,
}

impl fmt::Debug for NewTerminalSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewTerminalSession")
            .field("session_id", &self.session_id)
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("machine_id", &self.machine_id)
            .field("endpoint_id", &self.endpoint_id)
            .finish_non_exhaustive()
    }
}

/// An attached terminal: an open shell and the bounds it runs under. It owns
/// its slot in the ledger and gives it back when dropped.
pub struct AttachedTerminal {
    /// The session's identity.
    pub session_id: String,
    /// The shell.
    pub channel: Box<dyn TerminalChannel>,
    /// The bounds.
    pub limits: TerminalLimits,
    shutdown: tokio::sync::watch::Receiver<bool>,
    _slot: ActiveSlot,
}

impl fmt::Debug for AttachedTerminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachedTerminal")
            .field("session_id", &self.session_id)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// How a terminal session ended.
#[derive(Debug)]
pub struct SessionEnd {
    /// Why.
    pub reason: TerminalCloseReason,
    /// The shell's exit code, when it exited with one.
    pub exit_code: Option<i32>,
    /// How long the session ran.
    pub duration: Duration,
    /// The audit sink's refusal of the end event, when it refused. The
    /// session is released regardless.
    pub audit_error: Option<String>,
}

/// Whether a terminal size is usable.
fn valid_size(cols: u16, rows: u16) -> bool {
    (1..=MAX_DIMENSION).contains(&cols) && (1..=MAX_DIMENSION).contains(&rows)
}

/// A request for a terminal session.
#[derive(Clone, Debug)]
pub struct TerminalRequest<'a> {
    /// The machine, endpoint and explicit auth, if any.
    pub target: AccessTarget<'a>,
    /// The initial columns; absent means [`DEFAULT_SIZE`].
    pub cols: Option<u16>,
    /// The initial rows; absent means [`DEFAULT_SIZE`].
    pub rows: Option<u16>,
}

fn unwired() -> LabUseCaseError {
    LabUseCaseError::Invalid {
        detail: "interactive terminals are not available on this controller".to_owned(),
    }
}

impl MachineAccess {
    fn authorize_terminal(
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
    ) -> Result<(), LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineTerminal,
                resource: Some(machine_id),
            },
        )
        .map(|_| ())
        .map_err(LabUseCaseError::Denied)
    }

    /// The terminal sessions, when the controller composed them.
    #[must_use]
    pub fn terminals(&self) -> Option<&Arc<TerminalSessions>> {
        self.terminals.as_ref()
    }

    fn terminal_sessions(&self) -> Result<&Arc<TerminalSessions>, LabUseCaseError> {
        self.terminals.as_ref().ok_or_else(unwired)
    }

    /// Creates a terminal session: the authorization and target checks, the
    /// audit event, and the single-use token. Nothing reaches the machine
    /// yet.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine or endpoint, an endpoint whose
    /// host key was never confirmed, no usable auth, an invalid size, the
    /// session caps, or an audit failure.
    pub async fn terminal_create(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: &TerminalRequest<'_>,
        now: i64,
    ) -> Result<NewTerminalSession, LabUseCaseError> {
        let machine_id = request.target.machine_id;
        Self::authorize_terminal(authorizer, principal, machine_id)?;
        let sessions = self.terminal_sessions()?;
        let size = (
            request.cols.unwrap_or(DEFAULT_SIZE.0),
            request.rows.unwrap_or(DEFAULT_SIZE.1),
        );
        if !valid_size(size.0, size.1) {
            return Err(LabUseCaseError::Invalid {
                detail: format!("cols and rows must be 1..={MAX_DIMENSION}"),
            });
        }
        let (endpoint_id, auth) = self
            .resolve_target(authorizer, principal, &request.target)
            .await?;
        // Reserve before the audit await so two concurrent creates cannot
        // both pass a cap.
        let (token, session_id, expires_at) =
            sessions.reserve(&principal.id, machine_id, &endpoint_id, &auth, size, now)?;
        let facts = [
            ("terminalSession", session_id.clone()),
            ("endpointId", endpoint_id.clone()),
            ("authKind", auth.kind().to_owned()),
        ];
        if let Err(error) = self
            .audit_event(
                principal,
                Permission::MachineTerminal,
                Some(machine_id),
                "terminal_session_created",
                &facts,
            )
            .await
        {
            sessions.forget(&token);
            return Err(error);
        }
        Ok(NewTerminalSession {
            session_id,
            token: SensitiveString::new(token),
            expires_at,
            machine_id: machine_id.to_owned(),
            endpoint_id,
            limits: sessions.limits(),
        })
    }

    /// Attaches a session: consumes the token (single use), decides
    /// authorization again for the attaching caller, audits the start, and
    /// opens the shell. A failure after the token was presented leaves it
    /// spent and the slot released.
    ///
    /// # Errors
    ///
    /// Fails with [`LabUseCaseError::NotFound`] for an unknown, spent,
    /// expired or foreign token; on denial; on an audit failure; or when the
    /// shell cannot be opened (the end is audited with reason `error`).
    pub async fn terminal_attach(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        token: &str,
        now: i64,
    ) -> Result<AttachedTerminal, LabUseCaseError> {
        let sessions = self.terminal_sessions()?;
        let (pending, slot) = sessions.claim(&principal.id, token, now)?;
        // From here the slot guard releases the session on every early exit.
        Self::authorize_terminal(authorizer, principal, &pending.machine_id)?;
        let facts = [
            ("terminalSession", pending.session_id.clone()),
            ("endpointId", pending.endpoint_id.clone()),
            ("authKind", pending.auth.kind().to_owned()),
        ];
        self.audit_event(
            principal,
            Permission::MachineTerminal,
            Some(&pending.machine_id),
            "terminal_session_started",
            &facts,
        )
        .await?;
        let open = TerminalOpen {
            machine_id: pending.machine_id.clone(),
            endpoint_id: pending.endpoint_id.clone(),
            auth: pending.auth.clone(),
            cols: pending.size.0,
            rows: pending.size.1,
        };
        let channel = match sessions.port.open(&open).await {
            Ok(channel) => channel,
            Err(detail) => {
                let end = [
                    ("terminalSession", pending.session_id.clone()),
                    ("endpointId", pending.endpoint_id.clone()),
                    ("closeReason", TerminalCloseReason::Error.id().to_owned()),
                    ("elapsedMs", "0".to_owned()),
                ];
                let _ = self
                    .audit_event(
                        principal,
                        Permission::MachineTerminal,
                        Some(&pending.machine_id),
                        "terminal_session_ended",
                        &end,
                    )
                    .await;
                return Err(LabUseCaseError::Backend {
                    context: "terminal",
                    detail,
                });
            }
        };
        Ok(AttachedTerminal {
            session_id: pending.session_id,
            channel,
            limits: sessions.limits(),
            shutdown: sessions.shutdown.subscribe(),
            _slot: slot,
        })
    }

    /// Relays an attached terminal until it ends, closes both sides, and
    /// audits the end: principal, machine, endpoint, duration and close
    /// reason, never anything typed or shown.
    ///
    /// # Panics
    ///
    /// Never; a session that is no longer in the ledger is ended anyway.
    pub async fn terminal_run(
        &self,
        attached: AttachedTerminal,
        client: &mut dyn TerminalClient,
    ) -> SessionEnd {
        let AttachedTerminal {
            session_id,
            mut channel,
            limits,
            mut shutdown,
            _slot,
        } = attached;
        let started = Instant::now();
        let (reason, exit_code) =
            run_session(channel.as_mut(), client, limits, &mut shutdown).await;
        channel.close().await;
        client.close(reason, exit_code).await;
        let duration = started.elapsed();
        let (principal, machine_id, endpoint_id) = self
            .terminals
            .as_ref()
            .and_then(|sessions| {
                sessions.ledger().active.get(&session_id).map(|active| {
                    (
                        active.principal_id.clone(),
                        active.machine_id.clone(),
                        active.endpoint_id.clone(),
                    )
                })
            })
            .unwrap_or_default();
        let mut facts = vec![
            ("terminalSession", session_id.clone()),
            ("endpointId", endpoint_id),
            ("closeReason", reason.id().to_owned()),
            (
                "elapsedMs",
                i64::try_from(duration.as_millis())
                    .unwrap_or(i64::MAX)
                    .to_string(),
            ),
        ];
        if let Some(code) = exit_code.filter(|code| *code >= 0) {
            facts.push(("exitCode", code.to_string()));
        }
        let audit_error = self
            .audit_event(
                &ActingPrincipal { id: principal },
                Permission::MachineTerminal,
                Some(&machine_id),
                "terminal_session_ended",
                &facts,
            )
            .await
            .err()
            .map(|error| error.to_string());
        // The slot returns to the ledger when `_slot` drops here.
        SessionEnd {
            reason,
            exit_code,
            duration,
            audit_error,
        }
    }
}

/// The relay loop: guest output to the caller, caller input to the guest,
/// under the bounds. Returns why it ended.
async fn run_session(
    channel: &mut dyn TerminalChannel,
    client: &mut dyn TerminalClient,
    limits: TerminalLimits,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> (TerminalCloseReason, Option<i32>) {
    let started = Instant::now();
    let max_deadline = started + limits.max_duration;
    let mut idle_deadline = started + limits.idle;
    let mut next_ping = started + PING_INTERVAL;
    let mut last_heard = started;
    loop {
        tokio::select! {
            output = channel.next() => match output {
                TerminalOutput::Data(bytes) => {
                    match tokio::time::timeout(SEND_TIMEOUT, client.send_output(bytes)).await {
                        Ok(Ok(())) => {}
                        // A caller that went away or stopped reading.
                        Ok(Err(_)) => return (TerminalCloseReason::Client, None),
                        Err(_) => return (TerminalCloseReason::PeerLost, None),
                    }
                }
                TerminalOutput::Exited(code) => return (TerminalCloseReason::Exited, code),
            },
            message = client.recv() => {
                last_heard = Instant::now();
                match message {
                    ClientMessage::Input(bytes) => {
                        idle_deadline = Instant::now() + limits.idle;
                        match tokio::time::timeout(SEND_TIMEOUT, channel.write(&bytes)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) => return (TerminalCloseReason::Error, None),
                            // The guest stopped reading its terminal.
                            Err(_) => return (TerminalCloseReason::Error, None),
                        }
                    }
                    ClientMessage::Resize { cols, rows } => {
                        // An unusable size is ignored; a failed resize means
                        // the terminal is gone and its exit follows.
                        if valid_size(cols, rows) {
                            let _ = channel.resize(cols, rows);
                        }
                    }
                    ClientMessage::Alive => {}
                    ClientMessage::Closed => return (TerminalCloseReason::Client, None),
                }
            },
            () = tokio::time::sleep_until(idle_deadline) => {
                return (TerminalCloseReason::Idle, None);
            }
            () = tokio::time::sleep_until(max_deadline) => {
                return (TerminalCloseReason::MaxDuration, None);
            }
            () = tokio::time::sleep_until(next_ping) => {
                if last_heard.elapsed() >= PEER_TIMEOUT {
                    return (TerminalCloseReason::PeerLost, None);
                }
                match tokio::time::timeout(SEND_TIMEOUT, client.send_ping()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => return (TerminalCloseReason::Client, None),
                    Err(_) => return (TerminalCloseReason::PeerLost, None),
                }
                next_ping = Instant::now() + PING_INTERVAL;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return (TerminalCloseReason::Shutdown, None);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::mpsc;

    #[derive(Debug, Default)]
    struct FakePort {
        next: AtomicU64,
        fail_open: bool,
    }

    #[async_trait]
    impl TerminalPort for FakePort {
        fn new_session_token(&self) -> String {
            format!("token-{}", self.next.fetch_add(1, Ordering::Relaxed))
        }

        async fn open(&self, _request: &TerminalOpen) -> Result<Box<dyn TerminalChannel>, String> {
            if self.fail_open {
                return Err("no route".to_owned());
            }
            Ok(Box::new(FakeChannel::default()))
        }
    }

    #[derive(Debug, Default)]
    struct FakeChannel {
        output: VecDeque<TerminalOutput>,
        written: Vec<u8>,
        size: Option<(u16, u16)>,
    }

    #[async_trait]
    impl TerminalChannel for FakeChannel {
        async fn next(&mut self) -> TerminalOutput {
            match self.output.pop_front() {
                Some(output) => output,
                None => std::future::pending().await,
            }
        }
        async fn write(&mut self, data: &[u8]) -> Result<(), String> {
            self.written.extend_from_slice(data);
            Ok(())
        }
        fn resize(&mut self, cols: u16, rows: u16) -> Result<(), String> {
            self.size = Some((cols, rows));
            Ok(())
        }
        async fn close(&mut self) {}
    }

    struct FakeClient {
        inbox: mpsc::UnboundedReceiver<ClientMessage>,
        output: Vec<u8>,
        pings: u32,
        closed: Option<TerminalCloseReason>,
        stall_sends: bool,
    }

    #[async_trait]
    impl TerminalClient for FakeClient {
        async fn recv(&mut self) -> ClientMessage {
            match self.inbox.recv().await {
                Some(message) => message,
                None => std::future::pending().await,
            }
        }
        async fn send_output(&mut self, data: Vec<u8>) -> Result<(), String> {
            if self.stall_sends {
                std::future::pending::<()>().await;
            }
            self.output.extend(data);
            Ok(())
        }
        async fn send_ping(&mut self) -> Result<(), String> {
            self.pings += 1;
            Ok(())
        }
        async fn close(&mut self, reason: TerminalCloseReason, _code: Option<i32>) {
            self.closed = Some(reason);
        }
    }

    fn client() -> (FakeClient, mpsc::UnboundedSender<ClientMessage>) {
        let (sender, inbox) = mpsc::unbounded_channel();
        (
            FakeClient {
                inbox,
                output: Vec::new(),
                pings: 0,
                closed: None,
                stall_sends: false,
            },
            sender,
        )
    }

    fn sessions(limits: TerminalLimits) -> Arc<TerminalSessions> {
        TerminalSessions::new(Arc::new(FakePort::default()), limits)
    }

    fn reserve(
        sessions: &TerminalSessions,
        principal: &str,
        now: i64,
    ) -> Result<(String, String, i64), LabUseCaseError> {
        sessions.reserve(principal, "m1", "e1", &EndpointAuth::Agent, (80, 24), now)
    }

    #[test]
    fn a_token_is_single_use() {
        let sessions = sessions(TerminalLimits::default());
        let (token, _, _) = reserve(&sessions, "p", 0).unwrap();
        let (pending, slot) = sessions.claim("p", &token, 1).unwrap();
        assert_eq!(pending.machine_id, "m1");
        assert!(matches!(
            sessions.claim("p", &token, 2),
            Err(LabUseCaseError::NotFound { .. })
        ));
        drop(slot);
        assert_eq!(sessions.session_count(), 0);
    }

    #[test]
    fn a_token_expires() {
        let sessions = sessions(TerminalLimits::default());
        let (token, _, expires_at) = reserve(&sessions, "p", 0).unwrap();
        assert_eq!(expires_at, ttl_millis());
        assert!(sessions.claim("p", &token, expires_at - 1).is_ok());
        let (token, _, expires_at) = reserve(&sessions, "p", 0).unwrap();
        assert!(matches!(
            sessions.claim("p", &token, expires_at),
            Err(LabUseCaseError::NotFound { .. })
        ));
        // The expired session no longer counts toward the caps.
        assert_eq!(sessions.session_count(), 0);
        reserve(&sessions, "p", 0).unwrap();
        assert_eq!(sessions.session_count(), 1);
        // A later create purges what expired meanwhile.
        reserve(&sessions, "p", expires_at + 1).unwrap();
        assert_eq!(sessions.session_count(), 1);
    }

    #[test]
    fn another_principal_cannot_spend_a_token() {
        let sessions = sessions(TerminalLimits::default());
        let (token, _, _) = reserve(&sessions, "p", 0).unwrap();
        assert!(matches!(
            sessions.claim("intruder", &token, 1),
            Err(LabUseCaseError::NotFound { .. })
        ));
        // The owner can still use it.
        assert!(sessions.claim("p", &token, 2).is_ok());
    }

    #[test]
    fn caps_count_waiting_and_attached_sessions_together() {
        let limits = TerminalLimits {
            max_sessions: 3,
            max_per_principal: 2,
            ..TerminalLimits::default()
        };
        let sessions = sessions(limits);
        let (first, _, _) = reserve(&sessions, "a", 0).unwrap();
        let (_second, _, _) = reserve(&sessions, "a", 0).unwrap();
        // Per principal: a third for "a" is refused whatever its state.
        assert!(matches!(
            reserve(&sessions, "a", 0),
            Err(LabUseCaseError::Busy { .. })
        ));
        // Attaching moves a session between the sets without freeing a slot.
        let (_pending, slot) = sessions.claim("a", &first, 1).unwrap();
        assert_eq!(sessions.session_count(), 2);
        assert!(matches!(
            reserve(&sessions, "a", 1),
            Err(LabUseCaseError::Busy { .. })
        ));
        // Per controller.
        reserve(&sessions, "b", 1).unwrap();
        assert!(matches!(
            reserve(&sessions, "c", 1),
            Err(LabUseCaseError::Busy { .. })
        ));
        // Releasing the attached slot frees one.
        drop(slot);
        reserve(&sessions, "c", 1).unwrap();
    }

    #[test]
    fn limits_are_validated() {
        assert!(TerminalLimits::default().validate().is_ok());
        let bad = |change: fn(&mut TerminalLimits)| {
            let mut limits = TerminalLimits::default();
            change(&mut limits);
            limits.validate().is_err()
        };
        assert!(bad(|l| l.idle = Duration::ZERO));
        assert!(bad(|l| l.max_duration = Duration::ZERO));
        assert!(bad(|l| l.max_duration = MAX_CONFIGURED_DURATION + Duration::from_secs(1)));
        assert!(bad(|l| l.max_sessions = 0));
        assert!(bad(|l| l.max_per_principal = 0));
    }

    #[test]
    fn sizes_are_bounded() {
        assert!(valid_size(80, 24));
        assert!(!valid_size(0, 24));
        assert!(!valid_size(80, MAX_DIMENSION + 1));
    }

    #[test]
    fn close_reasons_have_stable_ids() {
        assert_eq!(TerminalCloseReason::MaxDuration.id(), "max_duration");
        assert_eq!(TerminalCloseReason::PeerLost.id(), "peer_lost");
    }

    fn short_limits(idle: u64, max: u64) -> TerminalLimits {
        TerminalLimits {
            idle: Duration::from_secs(idle),
            max_duration: Duration::from_secs(max),
            ..TerminalLimits::default()
        }
    }

    async fn run(
        channel: &mut FakeChannel,
        client: &mut FakeClient,
        limits: TerminalLimits,
    ) -> (TerminalCloseReason, Option<i32>) {
        let (_keep, mut shutdown) = tokio::sync::watch::channel(false);
        run_session(channel, client, limits, &mut shutdown).await
    }

    #[tokio::test(start_paused = true)]
    async fn silence_closes_the_session_as_idle() {
        let (mut client, _sender) = client();
        let mut channel = FakeChannel::default();
        // Alive frames (pongs) do not count as input.
        let (reason, _) = run(&mut channel, &mut client, short_limits(30, 600)).await;
        assert_eq!(reason, TerminalCloseReason::Idle);
    }

    #[tokio::test(start_paused = true)]
    async fn input_defers_the_idle_close() {
        let (mut client, sender) = client();
        let mut channel = FakeChannel::default();
        let feeder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            sender.send(ClientMessage::Input(b"ls\n".to_vec())).unwrap();
            // Keep the sender alive so the client does not look closed.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        let started = Instant::now();
        let (reason, _) = run(&mut channel, &mut client, short_limits(30, 600)).await;
        assert_eq!(reason, TerminalCloseReason::Idle);
        // Input at 20 s moved the idle deadline from 30 s to 50 s.
        assert!(started.elapsed() >= Duration::from_secs(50));
        assert_eq!(channel.written, b"ls\n");
        feeder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_maximum_duration_ends_an_active_session() {
        let (mut client, sender) = client();
        let mut channel = FakeChannel::default();
        let feeder = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if sender.send(ClientMessage::Input(b"x".to_vec())).is_err() {
                    break;
                }
            }
        });
        let (reason, _) = run(&mut channel, &mut client, short_limits(30, 100)).await;
        assert_eq!(reason, TerminalCloseReason::MaxDuration);
        feeder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_resize_reaches_the_guest_and_is_not_input() {
        let (mut client, sender) = client();
        let mut channel = FakeChannel::default();
        sender
            .send(ClientMessage::Resize { cols: 120, rows: 40 })
            .unwrap();
        sender.send(ClientMessage::Resize { cols: 0, rows: 40 }).unwrap();
        let keep = sender.clone();
        let (reason, _) = run(&mut channel, &mut client, short_limits(30, 600)).await;
        // Resize frames do not defer the idle close.
        assert_eq!(reason, TerminalCloseReason::Idle);
        assert_eq!(channel.size, Some((120, 40)));
        drop(keep);
    }

    #[tokio::test(start_paused = true)]
    async fn the_shell_exiting_ends_the_session_with_its_code() {
        let (mut client, _sender) = client();
        let mut channel = FakeChannel::default();
        channel
            .output
            .push_back(TerminalOutput::Data(b"bye\n".to_vec()));
        channel.output.push_back(TerminalOutput::Exited(Some(3)));
        let (reason, code) = run(&mut channel, &mut client, short_limits(30, 600)).await;
        assert_eq!((reason, code), (TerminalCloseReason::Exited, Some(3)));
        assert_eq!(client.output, b"bye\n");
    }

    #[tokio::test(start_paused = true)]
    async fn a_closed_client_ends_the_session() {
        let (mut client, sender) = client();
        let mut channel = FakeChannel::default();
        sender.send(ClientMessage::Closed).unwrap();
        let (reason, _) = run(&mut channel, &mut client, short_limits(30, 600)).await;
        assert_eq!(reason, TerminalCloseReason::Client);
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_stops_reading_is_dropped_by_the_send_timeout() {
        let (mut client, _sender) = client();
        client.stall_sends = true;
        let mut channel = FakeChannel::default();
        channel
            .output
            .push_back(TerminalOutput::Data(b"x".to_vec()));
        let started = Instant::now();
        let (reason, _) = run(&mut channel, &mut client, short_limits(300, 600)).await;
        assert_eq!(reason, TerminalCloseReason::PeerLost);
        assert_eq!(started.elapsed(), SEND_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_is_pinged_then_declared_lost() {
        let (mut client, sender) = client();
        let mut channel = FakeChannel::default();
        let (reason, _) = run(&mut channel, &mut client, short_limits(3000, 6000)).await;
        // Nobody ever answered: pinged every 20 s until 60 s of silence.
        assert_eq!(reason, TerminalCloseReason::PeerLost);
        assert!(client.pings >= 2);
        drop(sender);
    }

    #[tokio::test(start_paused = true)]
    async fn answers_to_pings_keep_a_session_alive() {
        let (mut client, sender) = client();
        let mut channel = FakeChannel::default();
        let feeder = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                if sender.send(ClientMessage::Alive).is_err() {
                    break;
                }
            }
        });
        let (reason, _) = run(&mut channel, &mut client, short_limits(3000, 200)).await;
        assert_eq!(reason, TerminalCloseReason::MaxDuration);
        feeder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_closes_the_session() {
        let (mut client, _sender) = client();
        let mut channel = FakeChannel::default();
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let trigger = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tx.send_replace(true);
        });
        let (reason, _) = run_session(&mut channel, &mut client, short_limits(300, 600), &mut rx).await;
        assert_eq!(reason, TerminalCloseReason::Shutdown);
        trigger.await.unwrap();
    }
}
