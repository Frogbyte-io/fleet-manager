//! #494: the interactive machine terminal, end to end against a real sshd.
//!
//! A session created through the use case attaches over a real WebSocket to
//! the controller's relay, which runs `ssh -tt` under a PTY with a Fleet-held
//! key. The tests cover the relay (a real shell, resize, exit), the bounds
//! (idle, maximum duration, shutdown, the caps), the token (single use,
//! foreign Origin, wrong principal, no principal), authorization at both
//! stages, and the audit trail (no typed or shown content, no key).

#![cfg(unix)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware::{self, Next};
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::lab::LabUseCaseError;
use fleet_application::machine::{NewEndpoint, RegisterMachine};
use fleet_application::machine_access::{AccessTarget, EndpointAuth, MachineAccess};
use fleet_application::machine_terminal::{TerminalLimits, TerminalRequest, TerminalSessions};
use fleet_controller::machine_access::{SecretBackedMachineKeys, SshAuthResolver};
use fleet_controller::machine_terminal::{SshTerminalPort, terminal_router};
use fleet_core::EndpointKind;
use fleet_storage_sqlite::{AuditSink, EndpointAuthRepository, MachineRepository, Store};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;

mod common;
use common::{start_sshd, whoami};

fn lan() -> ActingPrincipal {
    ActingPrincipal {
        id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
    }
}

/// Denies the listed permissions; the first `allow_first` decisions on
/// `machines.terminal` are allowed (so create passes and attach can fail).
#[derive(Debug)]
struct Policy {
    deny: Vec<Permission>,
    terminal_allows: std::sync::atomic::AtomicUsize,
}

impl Policy {
    fn allow_all() -> Arc<Self> {
        Arc::new(Self {
            deny: vec![],
            terminal_allows: std::sync::atomic::AtomicUsize::new(usize::MAX),
        })
    }

    fn deny(permission: Permission) -> Arc<Self> {
        Arc::new(Self {
            deny: vec![permission],
            terminal_allows: std::sync::atomic::AtomicUsize::new(usize::MAX),
        })
    }

    /// `machines.terminal` is allowed `count` times, then denied.
    fn terminal_allowed_times(count: usize) -> Arc<Self> {
        Arc::new(Self {
            deny: vec![],
            terminal_allows: std::sync::atomic::AtomicUsize::new(count),
        })
    }
}

impl Authorizer for Policy {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if self.deny.contains(&request.action) {
            return Decision::deny(ReasonId::UnknownPrincipal);
        }
        if request.action == Permission::MachineTerminal {
            use std::sync::atomic::Ordering;
            let left = self.terminal_allows.load(Ordering::SeqCst);
            if left == 0 {
                return Decision::deny(ReasonId::UnknownPrincipal);
            }
            if left != usize::MAX {
                self.terminal_allows.store(left - 1, Ordering::SeqCst);
            }
        }
        Decision::allow()
    }
}

struct World {
    dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    sshd: common::TestSshd,
    access: Arc<MachineAccess>,
    sessions: Arc<TerminalSessions>,
    machine_id: String,
    endpoint_id: String,
    key_ref: String,
}

impl World {
    async fn new(limits: TerminalLimits) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        std::mem::forget(store);
        let sshd = start_sshd();
        let key_file = dir.path().join("master.key");
        std::fs::write(
            &key_file,
            "1 0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let secrets = Arc::new(fleet_secrets::SecretStore::open(pool.clone(), &key_file).unwrap());
        let keys = Arc::new(
            SecretBackedMachineKeys::new(secrets).protecting(vec![dir.path().join("ssh")]),
        );
        let resolver = Arc::new(SshAuthResolver::new(keys.clone()));
        let machines: Arc<dyn fleet_application::machine::MachinePort> =
            Arc::new(MachineRepository::new(pool.clone()));
        let port =
            SshTerminalPort::new(machines.clone(), resolver, dir.path().join("ssh")).unwrap();
        let sessions = TerminalSessions::new(Arc::new(port), limits);
        let access = Arc::new(
            MachineAccess::new(
                machines.clone(),
                Arc::new(EndpointAuthRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_keys(keys)
            .with_terminals(sessions.clone()),
        );
        let machine = machines
            .register(&RegisterMachine {
                name: "terminal-box".to_owned(),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: EndpointKind::Ssh,
                    reference: format!("{}@127.0.0.1:{}", whoami(), sshd.port),
                }],
                tags: vec![],
                groups: vec![],
            })
            .await
            .unwrap();
        let endpoint_id = machine.endpoints[0].id.clone();
        let provider = fleet_provider_ssh::SshProvider::new(dir.path().join("ssh")).unwrap();
        let observation = provider
            .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
            .unwrap();
        provider.pin(&observation).unwrap();
        machines
            .confirm_fingerprint(&endpoint_id, &observation.fingerprint, 0)
            .await
            .unwrap();
        let key_text = std::fs::read_to_string(sshd.keys_dir.path().join("user_ed25519")).unwrap();
        let key_ref = access
            .store_key(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                &key_text,
                Some(&machine.id),
            )
            .await
            .unwrap();
        let world = Self {
            dir,
            pool,
            sshd,
            access,
            sessions,
            machine_id: machine.id,
            endpoint_id,
            key_ref,
        };
        world.use_stored_key_by_default().await;
        world
    }

    async fn use_stored_key_by_default(&self) {
        self.access
            .set_default_auth(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                &self.machine_id,
                &self.endpoint_id,
                Some(&EndpointAuth::Secret {
                    credential: self.key_ref.clone(),
                }),
            )
            .await
            .unwrap();
    }

    /// Serves the relay on a loopback port. `principal` is what the stand-in
    /// for the controller's caller resolution attaches to every request.
    async fn serve(
        &self,
        authorizer: Arc<dyn Authorizer>,
        principal: Option<ActingPrincipal>,
    ) -> SocketAddr {
        let mut router: Router = terminal_router(self.access.clone(), authorizer);
        if let Some(principal) = principal {
            router = router.layer(middleware::from_fn(
                move |mut request: axum::extract::Request, next: Next| {
                    let principal = principal.clone();
                    async move {
                        request.extensions_mut().insert(principal);
                        next.run(request).await
                    }
                },
            ));
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        address
    }

    async fn create(&self) -> String {
        self.create_for(&*Policy::allow_all(), &lan())
            .await
            .unwrap()
    }

    async fn create_for(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<String, LabUseCaseError> {
        self.access
            .terminal_create(
                authorizer,
                principal,
                &TerminalRequest {
                    target: AccessTarget {
                        machine_id: &self.machine_id,
                        ..AccessTarget::default()
                    },
                    cols: Some(100),
                    rows: Some(30),
                },
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .map(|session| session.token.expose().to_owned())
    }

    async fn audit_text(&self) -> String {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT group_concat(actor || ' ' || action || ' ' || coalesce(resource, '') || ' ' || metadata_json, char(10)) FROM audit_events",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap()
        .unwrap_or_default()
    }

    /// Waits until the ledger is empty (the session ended and was audited).
    async fn settled(&self) {
        for _ in 0..100 {
            if self.sessions.session_count() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the session never ended");
    }

    fn key_files(&self) -> usize {
        std::fs::read_dir(self.dir.path().join("ssh").join("keys"))
            .map(|entries| entries.count())
            .unwrap_or(0)
    }
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn attach(
    address: SocketAddr,
    token: &str,
    origin: Option<&str>,
) -> Result<Socket, tokio_tungstenite::tungstenite::Error> {
    let mut request = format!("ws://{address}/api/v1/terminal/socket")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_str(&format!("fleet-terminal, fleet-terminal-token.{token}")).unwrap(),
    );
    if let Some(origin) = origin {
        request
            .headers_mut()
            .insert("Origin", HeaderValue::from_str(origin).unwrap());
    }
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(socket, _)| socket)
}

/// What the socket did next.
enum Seen {
    Text(String),
    Output(Vec<u8>),
    Closed(u16, String),
}

async fn next(socket: &mut Socket, wait: Duration) -> Option<Seen> {
    loop {
        let message = tokio::time::timeout(wait, socket.next()).await.ok()?;
        return match message {
            Some(Ok(Message::Binary(bytes))) => Some(Seen::Output(bytes.to_vec())),
            Some(Ok(Message::Text(text))) => Some(Seen::Text(text.to_string())),
            Some(Ok(Message::Close(Some(frame)))) => {
                Some(Seen::Closed(frame.code.into(), frame.reason.to_string()))
            }
            Some(Ok(Message::Close(None))) | None | Some(Err(_)) => {
                Some(Seen::Closed(1006, String::new()))
            }
            Some(Ok(_)) => continue,
        };
    }
}

/// Reads until the accumulated output contains `needle`.
async fn read_until(socket: &mut Socket, needle: &str) -> String {
    let mut text = String::new();
    loop {
        match next(socket, Duration::from_secs(20)).await {
            Some(Seen::Output(bytes)) => {
                text.push_str(&String::from_utf8_lossy(&bytes));
                if text.contains(needle) {
                    return text;
                }
            }
            Some(Seen::Text(_)) => {}
            Some(Seen::Closed(code, reason)) => {
                panic!("closed ({code}: {reason}) before {needle:?}; saw {text:?}")
            }
            None => panic!("timed out before {needle:?}; saw {text:?}"),
        }
    }
}

async fn expect_ready(socket: &mut Socket) {
    match next(socket, Duration::from_secs(20)).await {
        Some(Seen::Text(text)) => assert_eq!(text, r#"{"type":"ready"}"#),
        Some(Seen::Closed(code, reason)) => panic!("closed ({code}: {reason}) before ready"),
        _ => panic!("no ready message"),
    }
}

/// The close code and reason the controller ended the socket with.
async fn closed(socket: &mut Socket) -> (u16, String) {
    loop {
        match next(socket, Duration::from_secs(20)).await {
            Some(Seen::Closed(code, reason)) => return (code, reason),
            Some(_) => {}
            None => panic!("the socket never closed"),
        }
    }
}

fn limits(idle: u64, max: u64) -> TerminalLimits {
    TerminalLimits {
        idle: Duration::from_secs(idle),
        max_duration: Duration::from_secs(max),
        ..TerminalLimits::default()
    }
}

#[tokio::test]
async fn a_real_shell_relays_input_output_resize_and_exit() {
    let world = World::new(TerminalLimits::default()).await;
    let address = world.serve(Policy::allow_all(), Some(lan())).await;
    let token = world.create().await;
    let mut socket = attach(address, &token, None).await.unwrap();
    expect_ready(&mut socket).await;

    // The shell is interactive: it sits on a terminal of the size asked for.
    socket
        .send(Message::Binary(b"echo marker-$((20+22))\n".to_vec().into()))
        .await
        .unwrap();
    let echoed = read_until(&mut socket, "marker-42").await;
    assert!(echoed.contains("marker-42"));
    socket
        .send(Message::Binary(b"stty size\n".to_vec().into()))
        .await
        .unwrap();
    read_until(&mut socket, "30 100").await;

    // A resize reaches the guest (ssh sends a window-change).
    socket
        .send(Message::Text(
            r#"{"type":"resize","cols":132,"rows":43}"#.into(),
        ))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    socket
        .send(Message::Binary(b"stty size\n".to_vec().into()))
        .await
        .unwrap();
    read_until(&mut socket, "43 132").await;

    socket
        .send(Message::Binary(b"exit 7\n".to_vec().into()))
        .await
        .unwrap();
    let (code, reason) = closed(&mut socket).await;
    assert_eq!(code, 1000);
    assert!(reason.contains("exit status 7"), "{reason}");
    world.settled().await;
    assert_eq!(world.key_files(), 0, "the key file outlived the session");

    // Audit: who, which machine and endpoint, how long, why it ended; never
    // what was typed or shown, and never the key.
    let audit = world.audit_text().await;
    for event in [
        "terminal_session_created",
        "terminal_session_started",
        "terminal_session_ended",
    ] {
        assert!(audit.contains(event), "{event} missing: {audit}");
    }
    assert!(audit.contains("machines.terminal"), "{audit}");
    assert!(audit.contains(&world.machine_id), "{audit}");
    assert!(audit.contains(&world.endpoint_id), "{audit}");
    assert!(audit.contains(r#""closeReason":"exited""#), "{audit}");
    assert!(audit.contains(r#""exitCode":"7""#), "{audit}");
    assert!(audit.contains("elapsedMs"), "{audit}");
    assert!(audit.contains(fleet_auth::LAN_PRINCIPAL_ID), "{audit}");
    assert!(!audit.contains("marker-42"), "typed text reached the audit");
    assert!(!audit.contains("stty"), "typed text reached the audit");
    assert!(!audit.contains("BEGIN OPENSSH"), "{audit}");
    assert!(
        !audit.contains(&token),
        "the session token reached the audit"
    );
}

#[tokio::test]
async fn a_token_works_once() {
    let world = World::new(TerminalLimits::default()).await;
    let address = world.serve(Policy::allow_all(), Some(lan())).await;
    let token = world.create().await;
    let mut first = attach(address, &token, None).await.unwrap();
    expect_ready(&mut first).await;
    let mut replay = attach(address, &token, None).await.unwrap();
    assert_eq!(closed(&mut replay).await.0, 4404);
    // The legitimate session is unaffected.
    first
        .send(Message::Binary(b"echo still-here\n".to_vec().into()))
        .await
        .unwrap();
    read_until(&mut first, "still-here").await;
    first.close(None).await.unwrap();
    world.settled().await;
}

#[tokio::test]
async fn a_foreign_origin_and_a_missing_token_are_refused_before_the_upgrade() {
    let world = World::new(TerminalLimits::default()).await;
    let address = world.serve(Policy::allow_all(), Some(lan())).await;
    let token = world.create().await;
    let refused = attach(address, &token, Some("https://evil.example.test")).await;
    match refused {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 403);
        }
        other => panic!("a foreign origin must be refused, got {other:?}"),
    }
    // The refused attempt did not spend the token.
    let mut socket = attach(address, &token, Some(&format!("http://{address}")))
        .await
        .unwrap();
    expect_ready(&mut socket).await;
    socket.close(None).await.unwrap();
    world.settled().await;

    // No token subprotocol at all.
    let mut request = format!("ws://{address}/api/v1/terminal/socket")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static("fleet-terminal"),
    );
    match tokio_tungstenite::connect_async(request).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 400);
        }
        other => panic!("a missing token must be refused, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unauthenticated_caller_and_another_principal_cannot_attach() {
    let world = World::new(TerminalLimits::default()).await;
    let token = world.create().await;

    // No caller resolved at all.
    let anonymous = world.serve(Policy::allow_all(), None).await;
    let mut socket = attach(anonymous, &token, None).await.unwrap();
    assert_eq!(closed(&mut socket).await.0, 4401);

    // Another principal gets the same answer as an unknown token, and the
    // owner's token is not spent by it.
    let intruder = world
        .serve(
            Policy::allow_all(),
            Some(ActingPrincipal {
                id: "someone-else".to_owned(),
            }),
        )
        .await;
    let mut socket = attach(intruder, &token, None).await.unwrap();
    assert_eq!(closed(&mut socket).await.0, 4404);
    let owner = world.serve(Policy::allow_all(), Some(lan())).await;
    let mut socket = attach(owner, &token, None).await.unwrap();
    expect_ready(&mut socket).await;
    socket.close(None).await.unwrap();
    world.settled().await;
}

#[tokio::test]
async fn machines_terminal_is_required_when_creating_and_again_when_attaching() {
    let world = World::new(TerminalLimits::default()).await;

    // Creating without the permission is refused, and nothing is reserved.
    let denied = world
        .create_for(&*Policy::deny(Permission::MachineTerminal), &lan())
        .await;
    assert!(
        matches!(denied, Err(LabUseCaseError::Denied(_))),
        "{denied:?}"
    );
    assert_eq!(world.sessions.session_count(), 0);
    // `machines.exec` is not a substitute: allowing everything but the
    // terminal permission still refuses.

    // Revoked between create and attach: the socket is refused, the token is
    // spent, and the slot is released.
    let token = world
        .create_for(&*Policy::allow_all(), &lan())
        .await
        .unwrap();
    let address = world
        .serve(Policy::terminal_allowed_times(0), Some(lan()))
        .await;
    let mut socket = attach(address, &token, None).await.unwrap();
    assert_eq!(closed(&mut socket).await.0, 4403);
    assert_eq!(world.sessions.session_count(), 0);
    let audit = world.audit_text().await;
    assert!(!audit.contains("terminal_session_started"), "{audit}");
}

#[tokio::test]
async fn an_explicit_auth_needs_machine_update_like_exec() {
    let world = World::new(TerminalLimits::default()).await;
    let result = world
        .access
        .terminal_create(
            &*Policy::deny(Permission::MachineUpdate),
            &lan(),
            &TerminalRequest {
                target: AccessTarget {
                    machine_id: &world.machine_id,
                    auth: Some(&EndpointAuth::Agent),
                    ..AccessTarget::default()
                },
                cols: None,
                rows: None,
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await;
    assert!(
        matches!(result, Err(LabUseCaseError::Denied(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn silence_closes_an_idle_terminal_but_typing_keeps_it_open() {
    let world = World::new(limits(2, 60)).await;
    let address = world.serve(Policy::allow_all(), Some(lan())).await;
    let token = world.create().await;
    let mut socket = attach(address, &token, None).await.unwrap();
    expect_ready(&mut socket).await;
    // Typing at 1.2 s intervals for 3 s outlives the 2 s idle bound.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        socket
            .send(Message::Binary(b" ".to_vec().into()))
            .await
            .unwrap();
    }
    // Then silence: the controller closes it.
    let (code, _) = closed(&mut socket).await;
    assert_eq!(code, 4408);
    world.settled().await;
    let audit = world.audit_text().await;
    assert!(audit.contains(r#""closeReason":"idle""#), "{audit}");
}

#[tokio::test]
async fn the_maximum_duration_ends_even_an_active_terminal() {
    let world = World::new(limits(30, 3)).await;
    let address = world.serve(Policy::allow_all(), Some(lan())).await;
    let token = world.create().await;
    let mut socket = attach(address, &token, None).await.unwrap();
    expect_ready(&mut socket).await;
    let (mut sink, mut stream) = socket.split();
    let typist = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(400)).await;
            if sink
                .send(Message::Binary(b" ".to_vec().into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let started = std::time::Instant::now();
    let code = loop {
        match tokio::time::timeout(Duration::from_secs(20), stream.next()).await {
            Ok(Some(Ok(Message::Close(Some(frame))))) => break u16::from(frame.code),
            Ok(Some(Ok(_))) => {}
            other => panic!("the socket ended without a close frame: {other:?}"),
        }
    };
    typist.abort();
    // Typing every 400 ms never let it go idle (30 s), yet it ended at 3 s.
    assert_eq!(code, 4410);
    assert!(started.elapsed() < Duration::from_secs(10));
    world.settled().await;
    let audit = world.audit_text().await;
    assert!(audit.contains(r#""closeReason":"max_duration""#), "{audit}");
}

#[tokio::test]
async fn shutdown_closes_attached_terminals_and_audits_the_end() {
    let world = World::new(TerminalLimits::default()).await;
    let address = world.serve(Policy::allow_all(), Some(lan())).await;
    let token = world.create().await;
    let mut socket = attach(address, &token, None).await.unwrap();
    expect_ready(&mut socket).await;
    world.sessions.shutdown();
    let (code, _) = closed(&mut socket).await;
    assert_eq!(code, 1001);
    world.settled().await;
    let audit = world.audit_text().await;
    assert!(audit.contains(r#""closeReason":"shutdown""#), "{audit}");
}

#[tokio::test]
async fn the_caps_count_waiting_and_attaching_sessions() {
    let world = World::new(TerminalLimits {
        max_sessions: 2,
        max_per_principal: 2,
        ..TerminalLimits::default()
    })
    .await;
    let address = world.serve(Policy::allow_all(), Some(lan())).await;
    let first = world.create().await;
    let _second = world.create().await;
    // Two waiting sessions fill the controller.
    let third = world.create_for(&*Policy::allow_all(), &lan()).await;
    assert!(
        matches!(third, Err(LabUseCaseError::Busy { .. })),
        "{third:?}"
    );
    // Attaching one does not free its slot...
    let mut socket = attach(address, &first, None).await.unwrap();
    expect_ready(&mut socket).await;
    let still = world.create_for(&*Policy::allow_all(), &lan()).await;
    assert!(
        matches!(still, Err(LabUseCaseError::Busy { .. })),
        "{still:?}"
    );
    // ...ending it does.
    socket.close(None).await.unwrap();
    for _ in 0..100 {
        if world.sessions.active_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    world
        .create_for(&*Policy::allow_all(), &lan())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_machine_that_refuses_the_key_ends_with_an_audited_error() {
    let world = World::new(TerminalLimits::default()).await;
    // Revoke the stored key: the next session cannot resolve it.
    let address = world.serve(Policy::allow_all(), Some(lan())).await;
    let token = world.create().await;
    sqlx::query("DELETE FROM secret_records")
        .execute(&world.pool)
        .await
        .unwrap();
    let mut socket = attach(address, &token, None).await.unwrap();
    let (code, reason) = closed(&mut socket).await;
    assert_eq!(code, 4502, "{reason}");
    assert!(
        reason.contains("revoked") || reason.contains("no longer"),
        "{reason}"
    );
    world.settled().await;
    let audit = world.audit_text().await;
    assert!(audit.contains(r#""closeReason":"error""#), "{audit}");
    let _ = &world.sshd;
}
