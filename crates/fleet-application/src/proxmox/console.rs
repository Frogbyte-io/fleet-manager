//! The Proxmox VM screen: console sessions over the PVE VNC proxy (FM-495).
//!
//! A console session is two steps. [`ProxmoxAccounts::console_create`]
//! authorizes `proxmox.console`, checks the account's trust, secret and (when
//! readable) the token's `VM.Console` privilege, audits the request, and
//! mints a short-lived, **single-use** session token. The browser (or a link
//! handed to a human) presents that token when it attaches
//! ([`ProxmoxAccounts::console_attach`]): authorization is decided again for
//! the attaching caller, the PVE VNC proxy is opened through the pinned
//! transport and authenticated on the controller side, and only then does a
//! channel exist. The browser never holds the PVE token, the VNC ticket, or
//! the VNC password; the Fleet session token is worthless once attached.
//!
//! The relay itself (bytes between the browser socket and the PVE socket,
//! idle and maximum-duration bounds, shutdown) is an adapter concern; this
//! module owns the rules: who may open a screen, for how many, for how long,
//! and what is audited. Nothing the screen shows is ever recorded — the
//! audit trail carries the principal, the account, the node, the VMID, the
//! duration, and the close reason.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fleet_core::SensitiveString;
use sha2::{Digest as _, Sha256};

use super::privileges::{PrivilegeStatus, PrivilegeTier};
use super::{ProxmoxAccount, ProxmoxAccounts, ProxmoxSourceError, ProxmoxUseCaseError};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};

/// How long an unattached session token stays valid.
pub const SESSION_TOKEN_TTL: Duration = Duration::from_secs(120);

/// The most sessions (waiting for their socket, or attached) at once.
pub const MAX_CONSOLE_SESSIONS: usize = 8;

/// The most sessions one principal may hold at once.
pub const MAX_CONSOLE_SESSIONS_PER_PRINCIPAL: usize = 4;

/// How long an attached console may sit without input or output from the
/// browser before the controller closes it.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_mins(10);

/// The longest an attached console may stay open.
pub const DEFAULT_MAX_DURATION: Duration = Duration::from_hours(1);

/// The audit action id recorded for every console event.
pub const CONSOLE_AUDIT_ACTION: &str = "proxmox.console";

/// The bounds applied to one attached console.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleLimits {
    /// Close after this long without browser input.
    pub idle: Duration,
    /// Close after this long regardless.
    pub max_duration: Duration,
}

impl Default for ConsoleLimits {
    fn default() -> Self {
        Self {
            idle: DEFAULT_IDLE_TIMEOUT,
            max_duration: DEFAULT_MAX_DURATION,
        }
    }
}

/// Why an attached console ended. The identifiers are audit-stable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleCloseReason {
    /// The browser closed the socket.
    Client,
    /// The guest or the PVE proxy closed the screen (including a guest
    /// that stopped).
    Guest,
    /// No browser input within the idle bound.
    Idle,
    /// The maximum duration elapsed.
    MaxDuration,
    /// The controller is shutting down.
    Shutdown,
    /// The relay failed.
    Error,
    /// The browser sent a stream the relay could not follow.
    Protocol,
}

impl ConsoleCloseReason {
    /// The stable identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Guest => "guest",
            Self::Idle => "idle",
            Self::MaxDuration => "max_duration",
            Self::Shutdown => "shutdown",
            Self::Error => "error",
            Self::Protocol => "protocol",
        }
    }
}

/// A binary message channel to one authenticated PVE VNC session. The
/// provider's socket is translated into this at the composition root.
#[async_trait]
pub trait ConsoleChannel: fmt::Debug + Send {
    /// The next message from the guest's screen, or `None` once PVE closed
    /// it. Cancel-safe.
    ///
    /// # Errors
    ///
    /// Fails with a bounded, caller-safe detail.
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, String>;

    /// Sends one message toward the guest (keyboard, pointer, requests).
    ///
    /// # Errors
    ///
    /// Fails with a bounded, caller-safe detail.
    async fn send(&mut self, data: Vec<u8>) -> Result<(), String>;

    /// Closes the channel, best effort.
    async fn close(&mut self);
}

/// The port that opens a guest's console through one bound account. The
/// provider implements it over the PVE VNC proxy; tests implement it in
/// memory.
#[async_trait]
pub trait ProxmoxConsolePort: fmt::Debug + Send + Sync {
    /// A fresh, unguessable session token. Shown once, never stored.
    fn new_session_token(&self) -> String;

    /// Opens the guest's VNC proxy, authenticated.
    ///
    /// # Errors
    ///
    /// Fails with [`ProxmoxSourceError`]; a missing `VM.Console` is
    /// [`ProxmoxSourceError::Forbidden`].
    async fn open(
        &self,
        account: &ProxmoxAccount,
        secret: &SensitiveString,
        node: &str,
        vmid: u32,
    ) -> Result<Box<dyn ConsoleChannel>, ProxmoxSourceError>;
}

/// A session waiting for its socket.
struct Pending {
    session_id: String,
    principal: ActingPrincipal,
    account_id: String,
    node: String,
    vmid: u32,
    expires_at: i64,
}

/// A session with an open channel.
struct Active {
    principal: String,
    account_id: String,
    node: String,
    vmid: u32,
    started_at: i64,
}

/// The session ledger: what is waiting and what is attached.
struct Ledger {
    pending: HashMap<String, Pending>,
    active: HashMap<String, Active>,
}

/// The console sessions' shared state, owned by [`ProxmoxAccounts`].
pub(crate) struct ConsoleState {
    port: Arc<dyn ProxmoxConsolePort>,
    ledger: Mutex<Ledger>,
    limits: ConsoleLimits,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl ConsoleState {
    /// The session ledger. A poisoned lock still holds a consistent ledger
    /// (every critical section is a few map operations), so it is used.
    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for ConsoleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsoleState")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn hash_token(token: &str) -> String {
    use std::fmt::Write as _;
    Sha256::digest(token.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// A created, unattached session: the only place the token exists.
pub struct NewConsoleSession {
    /// The session's identity, used in audit events (not a credential).
    pub session_id: String,
    /// The single-use token the browser presents to attach.
    pub token: SensitiveString,
    /// When the token stops being valid (epoch millis).
    pub expires_at: i64,
    /// The account.
    pub account_id: String,
    /// The node.
    pub node: String,
    /// The guest.
    pub vmid: u32,
    /// The bounds the attached console will run under.
    pub limits: ConsoleLimits,
}

impl fmt::Debug for NewConsoleSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewConsoleSession")
            .field("session_id", &self.session_id)
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("account_id", &self.account_id)
            .field("node", &self.node)
            .field("vmid", &self.vmid)
            .finish_non_exhaustive()
    }
}

/// An attached console: an authenticated channel to the guest's screen and
/// the bounds it runs under.
pub struct AttachedConsole {
    /// The session's identity, to pass back to
    /// [`ProxmoxAccounts::console_end`].
    pub session_id: String,
    /// The channel to PVE.
    pub channel: Box<dyn ConsoleChannel>,
    /// The bounds.
    pub limits: ConsoleLimits,
    /// Turns `true` when the controller is shutting down.
    pub shutdown: tokio::sync::watch::Receiver<bool>,
}

impl fmt::Debug for AttachedConsole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachedConsole")
            .field("session_id", &self.session_id)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn valid_node(node: &str) -> bool {
    !node.is_empty()
        && node.len() <= 64
        && node
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
}

impl ProxmoxAccounts {
    /// Attaches the console port. Without it, console sessions are refused
    /// as not composed.
    #[must_use]
    pub fn with_console(mut self, port: Arc<dyn ProxmoxConsolePort>) -> Self {
        self.console = Some(Arc::new(ConsoleState {
            port,
            ledger: Mutex::new(Ledger {
                pending: HashMap::new(),
                active: HashMap::new(),
            }),
            limits: ConsoleLimits::default(),
            shutdown: tokio::sync::watch::channel(false).0,
        }));
        self
    }

    /// Replaces the bounds every attached console runs under. The defaults
    /// ([`DEFAULT_IDLE_TIMEOUT`], [`DEFAULT_MAX_DURATION`]) apply otherwise.
    /// Call after [`Self::with_console`].
    #[must_use]
    pub fn with_console_limits(mut self, limits: ConsoleLimits) -> Self {
        if let Some(state) = self.console.take() {
            // The state was just built by `with_console`, so it is still
            // uniquely owned here.
            if let Ok(mut state) = Arc::try_unwrap(state) {
                state.limits = limits;
                self.console = Some(Arc::new(state));
            }
        }
        self
    }

    fn console_state(&self) -> Result<&Arc<ConsoleState>, ProxmoxUseCaseError> {
        self.console
            .as_ref()
            .ok_or_else(|| ProxmoxUseCaseError::Backend {
                context: "console",
                detail: "the console relay is not composed".to_owned(),
            })
    }

    fn authorize_console(
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
    ) -> Result<Decision, ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxConsole,
                resource: Some(account_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)
    }

    /// Creates a console session for one guest: the authorization, trust,
    /// and privilege checks, the audit event, and the single-use token.
    /// Nothing is sent to PVE with the guest's console yet.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed node or VMID, an unknown or unconfirmed
    /// account, a missing secret, a token that demonstrably lacks
    /// `VM.Console`, the session cap, or an audit failure.
    pub async fn console_create(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        node: &str,
        vmid: u32,
        now: i64,
    ) -> Result<NewConsoleSession, ProxmoxUseCaseError> {
        Self::authorize_console(authorizer, principal, account_id)?;
        let state = self.console_state()?;
        if !valid_node(node) {
            return Err(ProxmoxUseCaseError::Invalid {
                detail: "the node name must be 1..=64 letters, digits, '-', '.', or '_'".to_owned(),
            });
        }
        if !(100..=999_999_999).contains(&vmid) {
            return Err(ProxmoxUseCaseError::Invalid {
                detail: "the VMID must be 100..=999999999".to_owned(),
            });
        }
        let account = self.trusted_account(account_id).await?;
        let secret = SensitiveString::new(self.require_secret(&account).await?);
        self.check_console_privilege(&account, &secret, vmid)
            .await?;

        let session_id;
        let token = state.port.new_session_token();
        {
            let mut ledger = state.ledger();
            ledger.pending.retain(|_, pending| pending.expires_at > now);
            let mine = ledger
                .pending
                .values()
                .map(|pending| pending.principal.id.as_str())
                .chain(
                    ledger
                        .active
                        .values()
                        .map(|active| active.principal.as_str()),
                )
                .filter(|owner| *owner == principal.id)
                .count();
            if ledger.pending.len() + ledger.active.len() >= MAX_CONSOLE_SESSIONS
                || mine >= MAX_CONSOLE_SESSIONS_PER_PRINCIPAL
            {
                return Err(ProxmoxUseCaseError::Conflict {
                    detail: format!(
                        "too many console sessions are open (at most {MAX_CONSOLE_SESSIONS}, {MAX_CONSOLE_SESSIONS_PER_PRINCIPAL} per principal); close one first"
                    ),
                });
            }
            session_id = format!("console-{}", &hash_token(&token)[..16]);
            // Reserve the slot before the audit await so two concurrent
            // creates cannot both pass the cap.
            ledger.pending.insert(
                hash_token(&token),
                Pending {
                    session_id: session_id.clone(),
                    principal: principal.clone(),
                    account_id: account.id.clone(),
                    node: node.to_owned(),
                    vmid,
                    expires_at: now + i64::try_from(SESSION_TOKEN_TTL.as_millis()).unwrap_or(0),
                },
            );
        }
        let facts = [
            ("session", session_id.as_str()),
            ("node", node),
            ("vmid", &vmid.to_string()),
        ];
        if let Err(error) = self
            .console_audit(
                &principal.id,
                &account.id,
                "proxmox_console_session_created",
                &facts,
            )
            .await
        {
            state.ledger().pending.remove(&hash_token(&token));
            return Err(error);
        }
        Ok(NewConsoleSession {
            session_id,
            token: SensitiveString::new(token),
            expires_at: now + i64::try_from(SESSION_TOKEN_TTL.as_millis()).unwrap_or(0),
            account_id: account.id,
            node: node.to_owned(),
            vmid,
            limits: state.limits,
        })
    }

    /// Reads the token's effective permissions and refuses when it holds
    /// `VM.Console` nowhere in scope. An unreadable permissions map is not a
    /// refusal: PVE decides at the proxy, and its answer is mapped to the
    /// same explained error.
    async fn check_console_privilege(
        &self,
        account: &ProxmoxAccount,
        secret: &SensitiveString,
        vmid: u32,
    ) -> Result<(), ProxmoxUseCaseError> {
        let Some(port) = self.permissions.as_ref() else {
            return Ok(());
        };
        let raw = match port
            .token_permissions(account, &SensitiveString::new(secret.expose().to_owned()))
            .await
        {
            Ok(raw) => raw,
            Err(ProxmoxSourceError::Forbidden { .. }) => return Ok(()),
            Err(error) => return Err(ProxmoxUseCaseError::Source(error)),
        };
        let report = super::privileges::evaluate_report(account.id.clone(), raw, 0);
        let missing = report
            .tiers
            .iter()
            .find(|tier| tier.tier == PrivilegeTier::Console)
            .is_some_and(|tier| tier.status == PrivilegeStatus::Missing);
        if missing {
            return Err(ProxmoxUseCaseError::Source(console_forbidden(vmid)));
        }
        Ok(())
    }

    /// Attaches a session: consumes the token (single use), decides
    /// authorization again for the attaching caller, opens the PVE VNC proxy
    /// through the pinned transport, and audits the start. A failure after
    /// the token was presented leaves it spent.
    ///
    /// # Errors
    ///
    /// Fails with [`ProxmoxUseCaseError::NotFound`] for an unknown, spent, or
    /// expired token; on denial; when the account changed; when PVE refuses
    /// (a missing `VM.Console` is the explained refusal); or on an audit
    /// failure.
    pub async fn console_attach(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        token: &str,
        now: i64,
    ) -> Result<AttachedConsole, ProxmoxUseCaseError> {
        let state = self.console_state()?;
        // The token is spent and the slot is held in one critical section:
        // from here until the console ends (or this attach fails), the
        // session counts against the caps, so a create racing an attach
        // cannot slip past them while the PVE proxy is being opened.
        let pending = {
            let mut ledger = state.ledger();
            let pending = ledger.pending.remove(&hash_token(token));
            if let Some(pending) = pending.as_ref().filter(|pending| pending.expires_at > now) {
                ledger.active.insert(
                    pending.session_id.clone(),
                    Active {
                        principal: principal.id.clone(),
                        account_id: pending.account_id.clone(),
                        node: pending.node.clone(),
                        vmid: pending.vmid,
                        started_at: now,
                    },
                );
            }
            pending
        };
        let Some(pending) = pending.filter(|pending| pending.expires_at > now) else {
            return Err(ProxmoxUseCaseError::NotFound {
                what: "console session (unknown, already used, or expired)".to_owned(),
            });
        };
        match self
            .attach_reserved(state, authorizer, principal, &pending, now)
            .await
        {
            Ok(channel) => Ok(AttachedConsole {
                session_id: pending.session_id,
                channel,
                limits: state.limits,
                shutdown: state.shutdown.subscribe(),
            }),
            Err(error) => {
                state.ledger().active.remove(&pending.session_id);
                Err(error)
            }
        }
    }

    /// The attach steps that run while the slot is held; the caller releases
    /// the slot on any error.
    async fn attach_reserved(
        &self,
        state: &ConsoleState,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        pending: &Pending,
        now: i64,
    ) -> Result<Box<dyn ConsoleChannel>, ProxmoxUseCaseError> {
        Self::authorize_console(authorizer, principal, &pending.account_id)?;
        if *state.shutdown.borrow() {
            // No new screen opens once the controller is shutting down; the
            // refusal is audited as an end so the trail shows the attempt.
            let _ = self
                .console_end(&pending.session_id, ConsoleCloseReason::Shutdown, now)
                .await;
            return Err(ProxmoxUseCaseError::Conflict {
                detail: "the controller is shutting down; try again once it is back".to_owned(),
            });
        }
        let account = self.trusted_account(&pending.account_id).await?;
        let secret = SensitiveString::new(self.require_secret(&account).await?);
        let mut channel = state
            .port
            .open(&account, &secret, &pending.node, pending.vmid)
            .await
            .map_err(|error| match error {
                ProxmoxSourceError::Forbidden { .. } => {
                    ProxmoxUseCaseError::Source(console_forbidden(pending.vmid))
                }
                other => ProxmoxUseCaseError::Source(other),
            })?;
        let vmid = pending.vmid.to_string();
        let mut facts = vec![
            ("session", pending.session_id.as_str()),
            ("node", pending.node.as_str()),
            ("vmid", vmid.as_str()),
        ];
        if pending.principal.id != principal.id {
            facts.push(("createdBy", pending.principal.id.as_str()));
        }
        if let Err(error) = self
            .console_audit(
                &principal.id,
                &account.id,
                "proxmox_console_session_started",
                &facts,
            )
            .await
        {
            channel.close().await;
            return Err(error);
        }
        // The duration counts from the moment the screen opened.
        if let Some(active) = state.ledger().active.get_mut(&pending.session_id) {
            active.started_at = now;
        }
        Ok(channel)
    }

    /// Records the end of an attached console: duration and close reason,
    /// never anything the screen showed. Idempotent: an unknown session is
    /// ignored.
    ///
    /// # Errors
    ///
    /// Fails when the audit sink refuses; the session is released anyway.
    pub async fn console_end(
        &self,
        session_id: &str,
        reason: ConsoleCloseReason,
        now: i64,
    ) -> Result<(), ProxmoxUseCaseError> {
        let state = self.console_state()?;
        let active = state.ledger().active.remove(session_id);
        let Some(active) = active else {
            return Ok(());
        };
        let duration = (now - active.started_at).max(0).to_string();
        let vmid = active.vmid.to_string();
        self.console_audit(
            &active.principal,
            &active.account_id,
            "proxmox_console_session_ended",
            &[
                ("session", session_id),
                ("node", active.node.as_str()),
                ("vmid", vmid.as_str()),
                ("durationMs", duration.as_str()),
                ("reason", reason.id()),
            ],
        )
        .await
    }

    /// Tells every attached console the controller is shutting down; each
    /// relay closes cleanly and records its end.
    pub fn console_shutdown(&self) {
        if let Some(state) = &self.console {
            state.shutdown.send_replace(true);
        }
    }

    /// How many consoles are attached right now.
    #[must_use]
    pub fn console_active_count(&self) -> usize {
        self.console
            .as_ref()
            .map_or(0, |state| state.ledger().active.len())
    }

    /// How many sessions are waiting or attached.
    #[must_use]
    pub fn console_session_count(&self) -> usize {
        self.console.as_ref().map_or(0, |state| {
            let ledger = state.ledger();
            ledger.pending.len() + ledger.active.len()
        })
    }

    async fn console_audit(
        &self,
        actor: &str,
        account_id: &str,
        event: &str,
        facts: &[(&str, &str)],
    ) -> Result<(), ProxmoxUseCaseError> {
        let backend = |detail: String| ProxmoxUseCaseError::Backend {
            context: "audit",
            detail,
        };
        let mut metadata = crate::audit::AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| backend(error.to_string()))?;
        for (key, value) in facts {
            metadata
                .insert(key, value)
                .map_err(|error| backend(error.to_string()))?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: actor.to_owned(),
                action: CONSOLE_AUDIT_ACTION.to_owned(),
                resource: Some(account_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(backend)
    }
}

/// The explained refusal for a token without `VM.Console`.
fn console_forbidden(vmid: u32) -> ProxmoxSourceError {
    ProxmoxSourceError::Forbidden {
        detail: format!(
            "the account's API token lacks VM.Console on /vms/{vmid}; grant it (the FleetConsole role from the token guide, or PVEVMUser) and retry"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_hash_to_a_stable_hex_digest() {
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn nodes_are_validated_before_they_reach_a_path() {
        assert!(valid_node("pve-b"));
        assert!(valid_node("pve.example"));
        assert!(!valid_node(""));
        assert!(!valid_node("../etc"));
        assert!(!valid_node("a b"));
        assert!(!valid_node(&"a".repeat(65)));
    }

    #[test]
    fn close_reasons_have_stable_ids() {
        assert_eq!(ConsoleCloseReason::MaxDuration.id(), "max_duration");
        assert_eq!(ConsoleCloseReason::Shutdown.id(), "shutdown");
    }
}
