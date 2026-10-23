//! `fleetctl machines terminal <machine-id>` (#494): an interactive shell on
//! a Fleet machine in the local terminal.
//!
//! The command is an adapter over the same session API as the console. It
//! asks the controller for a terminal session (`POST
//! /machines/{id}/terminal-sessions`, which authorizes `machines.terminal`
//! and audits), then attaches the local TTY to the controller's WebSocket
//! with the single-use token in a subprotocol. The controller holds the
//! machine's key and runs `ssh -tt`; nothing here ever receives a key, and
//! nothing typed or shown is recorded anywhere by this command.
//!
//! The local terminal is put in raw mode for the session and restored on
//! every way out: the shell ending, the connection closing, an error, and
//! `SIGINT`/`SIGTERM`/`SIGHUP` (in raw mode Ctrl-C is an ordinary byte for
//! the guest, so those signals come from outside). The window size is sent
//! at the start and on every `SIGWINCH`.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};
use tungstenite::protocol::Message;

use crate::machine_access::Target;
use crate::{CliError, Invocation, Output};

/// How long a read on the socket waits before the loop looks at local input
/// and signals again.
const POLL: Duration = Duration::from_millis(40);

/// The largest chunk of local input sent in one message.
const INPUT_CHUNK: usize = 16 * 1024;

/// The WebSocket subprotocol and token prefix of the terminal relay.
const SUBPROTOCOL: &str = "fleet-terminal";
const TOKEN_PREFIX: &str = "fleet-terminal-token.";

/// How a terminal session ended, as the CLI reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ended {
    /// The WebSocket close code, or 1006 when the connection dropped.
    pub code: u16,
    /// The controller's reason, or a description of the drop.
    pub reason: String,
}

impl Ended {
    /// The process exit status: the shell's own exit status when the
    /// controller reported one, 0 for an ordinary close, 1 otherwise.
    pub(crate) fn exit_status(&self) -> u8 {
        if let Some(status) = self
            .reason
            .split("exit status ")
            .nth(1)
            .and_then(|rest| rest.trim_end_matches(')').parse::<u16>().ok())
        {
            return u8::try_from(status.min(255)).unwrap_or(255);
        }
        u8::from(!matches!(self.code, 1000 | 1001))
    }

    /// A one-line explanation for the person at the keyboard.
    pub(crate) fn describe(&self) -> String {
        let why = match self.code {
            4401 => "authentication is required".to_owned(),
            4403 => "you may not open a terminal on this machine (machines.terminal is required)"
                .to_owned(),
            4404 => "the terminal session is unknown, already used, or expired".to_owned(),
            4408 => "closed after inactivity".to_owned(),
            4410 => "the maximum session duration was reached".to_owned(),
            1001 => "the controller is shutting down".to_owned(),
            _ if self.reason.is_empty() => format!("closed ({})", self.code),
            _ => self.reason.clone(),
        };
        format!("terminal closed: {why}")
    }
}

/// The WebSocket URL for a controller base URL and a socket path.
pub(crate) fn websocket_url(base: &str, path: &str) -> Result<String, CliError> {
    let rest = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return Err(CliError {
            message: format!("the controller URL must start with http:// or https://, not {base:?}"),
        });
    };
    Ok(format!("{}{path}", rest.trim_end_matches('/')))
}

/// What the loop needs from the local side.
pub(crate) struct LocalSide<'a> {
    /// Bytes the person typed.
    pub input: mpsc::Receiver<Vec<u8>>,
    /// Where the guest's output goes.
    pub output: &'a mut dyn Write,
    /// A new window size, when the window changed since the last call.
    pub resized: &'a mut dyn FnMut() -> Option<(u16, u16)>,
    /// Whether a signal asked the command to stop.
    pub stop: &'a dyn Fn() -> bool,
}

/// Sets a read timeout on the socket's transport so the loop can interleave
/// local input with remote output.
pub(crate) fn set_poll_timeout(
    socket: &tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
) {
    use tungstenite::stream::MaybeTlsStream;
    let _ = match socket.get_ref() {
        MaybeTlsStream::Plain(stream) => stream.set_read_timeout(Some(POLL)),
        MaybeTlsStream::Rustls(stream) => stream.get_ref().set_read_timeout(Some(POLL)),
        _ => Ok(()),
    };
}

/// Relays between the local terminal and the controller's socket until the
/// session ends. The socket's transport must have a read timeout (see
/// [`set_poll_timeout`]) so a quiet remote does not block local input.
pub(crate) fn pump<S: Read + Write>(
    socket: &mut tungstenite::WebSocket<S>,
    local: &mut LocalSide<'_>,
) -> Ended {
    use tungstenite::Error;
    loop {
        if (local.stop)() {
            let _ = socket.close(None);
            let _ = socket.flush();
            return Ended {
                code: 1000,
                reason: "interrupted".to_owned(),
            };
        }
        if let Some((cols, rows)) = (local.resized)() {
            let message = json!({ "type": "resize", "cols": cols, "rows": rows }).to_string();
            if let Err(error) = socket.send(Message::Text(message.into())) {
                if !would_block(&error) {
                    return dropped(&error);
                }
            }
        }
        while let Ok(bytes) = local.input.try_recv() {
            for chunk in bytes.chunks(INPUT_CHUNK) {
                match socket.send(Message::Binary(chunk.to_vec().into())) {
                    Ok(()) => {}
                    Err(error) if would_block(&error) => {}
                    Err(error) => return dropped(&error),
                }
            }
        }
        match socket.read() {
            Ok(Message::Binary(bytes)) => {
                if local.output.write_all(&bytes).is_err() || local.output.flush().is_err() {
                    let _ = socket.close(None);
                    return Ended {
                        code: 1000,
                        reason: "the local terminal went away".to_owned(),
                    };
                }
            }
            Ok(Message::Close(frame)) => {
                let (code, reason) = frame.map_or((1005, String::new()), |frame| {
                    (u16::from(frame.code), frame.reason.to_string())
                });
                return Ended { code, reason };
            }
            Ok(_) => {}
            Err(error) if would_block(&error) => {}
            Err(Error::ConnectionClosed | Error::AlreadyClosed) => {
                return Ended {
                    code: 1000,
                    reason: "closed".to_owned(),
                };
            }
            Err(error) => return dropped(&error),
        }
    }
}

fn would_block(error: &tungstenite::Error) -> bool {
    matches!(error, tungstenite::Error::Io(io)
        if matches!(io.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut))
}

fn dropped(error: &tungstenite::Error) -> Ended {
    Ended {
        code: 1006,
        reason: format!("the connection to the controller dropped ({error})"),
    }
}

/// The request body of a terminal session.
pub(crate) fn session_body(target: &Target, cols: u16, rows: u16) -> Result<Value, CliError> {
    let mut body = json!({ "cols": cols, "rows": rows });
    if let Some(endpoint) = &target.endpoint {
        body["endpointId"] = json!(endpoint);
    }
    if let Some(auth) = target.auth.to_json()? {
        body["auth"] = auth;
    }
    Ok(body)
}

/// Runs `machines terminal`.
#[cfg(unix)]
pub(crate) fn run(invocation: &Invocation, target: &Target) -> Result<(String, u8), CliError> {
    use rustix::stdio::{stdin, stdout};
    use rustix::termios::{
        OptionalActions, isatty, tcgetattr, tcgetwinsize, tcsetattr,
    };
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGWINCH};

    if !isatty(stdin()) || !isatty(stdout()) {
        return Err(CliError {
            message: "machines terminal needs an interactive terminal on standard input and output; use `machines exec` for scripts".to_owned(),
        });
    }
    let size = tcgetwinsize(stdout())
        .ok()
        .filter(|size| size.ws_col > 0 && size.ws_row > 0)
        .map_or((80, 24), |size| (size.ws_col, size.ws_row));

    // Ask the controller for the session before touching the terminal, so a
    // refusal prints like any other error.
    let client = crate::http_client()?;
    let body = session_body(target, size.0, size.1)?;
    let created = crate::send(
        &client,
        invocation,
        reqwest::Method::POST,
        &format!("/api/v1/machines/{}/terminal-sessions", target.machine),
        &[],
        Some(&body),
        uuid::Uuid::now_v7().to_string(),
    )?;
    let data = &created["data"];
    let token = data["token"].as_str().ok_or_else(|| CliError {
        message: "the controller's answer carried no session token".to_owned(),
    })?;
    let socket_path = data["socketPath"].as_str().ok_or_else(|| CliError {
        message: "the controller's answer named no socket".to_owned(),
    })?;

    let url = websocket_url(&invocation.url, socket_path)?;
    let mut request = tungstenite::client::IntoClientRequest::into_client_request(url.as_str())
        .map_err(|error| CliError {
            message: format!("cannot build the terminal connection: {error}"),
        })?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        format!("{SUBPROTOCOL}, {TOKEN_PREFIX}{token}")
            .parse()
            .map_err(|_| CliError {
                message: "the session token is not a valid header value".to_owned(),
            })?,
    );
    if let Some(value) = crate::bearer_token()? {
        request
            .headers_mut()
            .insert(reqwest::header::AUTHORIZATION.as_str(), value);
    }
    let (mut socket, _) = tungstenite::connect(request).map_err(|error| CliError {
        message: format!("the controller refused the terminal connection: {error}"),
    })?;
    set_poll_timeout(&socket);

    // Signals: the flags are polled by the loop.
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let winch = std::sync::Arc::new(AtomicBool::new(true));
    for signal in [SIGINT, SIGTERM, SIGHUP] {
        signal_hook::flag::register(signal, stop.clone()).map_err(|error| CliError {
            message: format!("cannot watch for signals: {error}"),
        })?;
    }
    signal_hook::flag::register(SIGWINCH, winch.clone()).map_err(|error| CliError {
        message: format!("cannot watch for window changes: {error}"),
    })?;

    // Raw mode, restored on every way out of this function.
    let original = tcgetattr(stdin()).map_err(|error| CliError {
        message: format!("cannot read the terminal settings: {error}"),
    })?;
    let mut raw = original.clone();
    raw.make_raw();
    tcsetattr(stdin(), OptionalActions::Flush, &raw).map_err(|error| CliError {
        message: format!("cannot enter raw mode: {error}"),
    })?;
    struct Restore(rustix::termios::Termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = tcsetattr(stdin(), OptionalActions::Flush, &self.0);
        }
    }
    let restore = Restore(original);

    let (sender, input) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        let mut standard_input = std::io::stdin();
        while let Ok(count) = standard_input.read(&mut buffer) {
            if count == 0 || sender.send(buffer[..count].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut standard_output = std::io::stdout();
    let mut resized = || {
        winch.swap(false, Ordering::SeqCst).then(|| {
            tcgetwinsize(stdout())
                .ok()
                .filter(|size| size.ws_col > 0 && size.ws_row > 0)
                .map_or((80, 24), |size| (size.ws_col, size.ws_row))
        })
    };
    let stopped = || stop.load(Ordering::SeqCst);
    let ended = pump(
        &mut socket,
        &mut LocalSide {
            input,
            output: &mut standard_output,
            resized: &mut resized,
            stop: &stopped,
        },
    );
    // Back to the user's terminal settings before anything is printed.
    drop(restore);
    let status = ended.exit_status();
    let message = ended.describe();
    let text = match invocation.output {
        Output::Json => json!({
            "closed": true,
            "code": ended.code,
            "reason": ended.reason,
            "exitStatus": status,
        })
        .to_string(),
        Output::Text => format!("\r\n{message}"),
    };
    Ok((text, status))
}

/// Interactive terminals need a Unix terminal.
#[cfg(not(unix))]
pub(crate) fn run(_invocation: &Invocation, _target: &Target) -> Result<(String, u8), CliError> {
    Err(CliError {
        message: "machines terminal is available on Unix terminals only".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine_access::AuthArgs;

    #[test]
    fn urls_map_to_websocket_schemes() {
        assert_eq!(
            websocket_url("http://127.0.0.1:8080", "/api/v1/terminal/socket").unwrap(),
            "ws://127.0.0.1:8080/api/v1/terminal/socket"
        );
        assert_eq!(
            websocket_url("https://fleet.example.test/", "/api/v1/terminal/socket").unwrap(),
            "wss://fleet.example.test/api/v1/terminal/socket"
        );
        assert!(websocket_url("ftp://x", "/p").is_err());
    }

    #[test]
    fn the_exit_status_follows_the_shell_or_the_close() {
        let ended = |code, reason: &str| Ended {
            code,
            reason: reason.to_owned(),
        };
        assert_eq!(ended(1000, "the shell ended (exit status 7)").exit_status(), 7);
        assert_eq!(ended(1000, "the shell ended (exit status 300)").exit_status(), 255);
        assert_eq!(ended(1000, "closed").exit_status(), 0);
        assert_eq!(ended(1001, "the controller is shutting down").exit_status(), 0);
        assert_eq!(ended(4403, "denied").exit_status(), 1);
        assert_eq!(ended(4408, "the terminal was idle").exit_status(), 1);
        assert_eq!(ended(1006, "dropped").exit_status(), 1);
    }

    #[test]
    fn refusals_are_explained_in_words() {
        let describe = |code| {
            Ended {
                code,
                reason: String::new(),
            }
            .describe()
        };
        assert!(describe(4403).contains("machines.terminal"));
        assert!(describe(4404).contains("expired"));
        assert!(describe(4408).contains("inactivity"));
        assert!(describe(4410).contains("maximum"));
    }

    #[test]
    fn the_session_body_carries_the_size_and_only_what_was_asked_for() {
        let target = Target {
            machine: "m1".to_owned(),
            ..Target::default()
        };
        assert_eq!(
            session_body(&target, 120, 40).unwrap(),
            json!({ "cols": 120, "rows": 40 })
        );
        let target = Target {
            machine: "m1".to_owned(),
            endpoint: Some("e1".to_owned()),
            auth: AuthArgs {
                kind: Some("secret".to_owned()),
                credential: Some("ref-1".to_owned()),
                identity: None,
            },
            os: None,
        };
        assert_eq!(
            session_body(&target, 80, 24).unwrap(),
            json!({
                "cols": 80,
                "rows": 24,
                "endpointId": "e1",
                "auth": { "type": "secret", "credential": "ref-1" },
            })
        );
    }

    /// A server on a loopback port, run by `script` on its accepted socket.
    fn serve(
        script: impl FnOnce(&mut tungstenite::WebSocket<std::net::TcpStream>) + Send + 'static,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept(stream).unwrap();
            script(&mut socket);
        });
        (url, handle)
    }

    fn connect(
        url: &str,
    ) -> tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>> {
        let (socket, _) = tungstenite::connect(url).unwrap();
        set_poll_timeout(&socket);
        socket
    }

    fn close_frame(code: u16, reason: &str) -> Message {
        Message::Close(Some(tungstenite::protocol::CloseFrame {
            code: code.into(),
            reason: reason.to_owned().into(),
        }))
    }

    #[test]
    fn output_is_written_locally_and_the_shells_exit_status_is_the_result() {
        let (url, server) = serve(|socket| {
            socket
                .send(Message::Text(r#"{"type":"ready"}"#.into()))
                .unwrap();
            socket
                .send(Message::Binary(b"hello\r\n".to_vec().into()))
                .unwrap();
            socket
                .send(close_frame(1000, "the shell ended (exit status 3)"))
                .unwrap();
            let _ = socket.flush();
            while socket.read().is_ok() {}
        });
        let mut socket = connect(&url);
        let (_keep, input) = mpsc::channel();
        let mut output = Vec::new();
        let ended = pump(
            &mut socket,
            &mut LocalSide {
                input,
                output: &mut output,
                resized: &mut || None,
                stop: &|| false,
            },
        );
        assert_eq!(output, b"hello\r\n");
        assert_eq!(ended.exit_status(), 3);
        server.join().unwrap();
    }

    #[test]
    fn typed_bytes_and_window_changes_reach_the_controller() {
        let (url, server) = serve(|socket| {
            let mut seen_input = false;
            let mut seen_resize = false;
            while !(seen_input && seen_resize) {
                match socket.read().unwrap() {
                    Message::Binary(bytes) => {
                        assert_eq!(&bytes[..], b"ls\n");
                        seen_input = true;
                    }
                    Message::Text(text) => {
                        let value: Value = serde_json::from_str(text.as_str()).unwrap();
                        assert_eq!(value, json!({ "type": "resize", "cols": 100, "rows": 30 }));
                        seen_resize = true;
                    }
                    _ => {}
                }
            }
            socket.send(close_frame(1000, "closed")).unwrap();
            let _ = socket.flush();
            while socket.read().is_ok() {}
        });
        let mut socket = connect(&url);
        let (sender, input) = mpsc::channel();
        sender.send(b"ls\n".to_vec()).unwrap();
        let mut pending = Some((100, 30));
        let mut output = Vec::new();
        let ended = pump(
            &mut socket,
            &mut LocalSide {
                input,
                output: &mut output,
                resized: &mut || pending.take(),
                stop: &|| false,
            },
        );
        assert_eq!(ended.exit_status(), 0);
        server.join().unwrap();
    }

    #[test]
    fn a_signal_stops_the_session_with_a_close() {
        let (url, server) = serve(|socket| {
            // The client closes; the server sees the close frame.
            loop {
                match socket.read() {
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        let mut socket = connect(&url);
        let (_keep, input) = mpsc::channel();
        let mut output = Vec::new();
        let ended = pump(
            &mut socket,
            &mut LocalSide {
                input,
                output: &mut output,
                resized: &mut || None,
                stop: &|| true,
            },
        );
        assert_eq!(ended.reason, "interrupted");
        server.join().unwrap();
    }

    #[test]
    fn a_vanished_controller_is_reported_and_is_an_error_exit() {
        let (url, server) = serve(|socket| {
            let _ = socket.get_ref().shutdown(std::net::Shutdown::Both);
        });
        let mut socket = connect(&url);
        let (_keep, input) = mpsc::channel();
        let mut output = Vec::new();
        let ended = pump(
            &mut socket,
            &mut LocalSide {
                input,
                output: &mut output,
                resized: &mut || None,
                stop: &|| false,
            },
        );
        assert_ne!(ended.exit_status(), 0, "{ended:?}");
        server.join().unwrap();
    }

    #[test]
    fn the_command_parses_its_target_flags_and_refuses_the_rest() {
        let args = |words: &[&str]| words.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        let parsed = crate::parse(&args(&[
            "machines",
            "terminal",
            "m1",
            "--endpoint",
            "e1",
            "--auth",
            "secret",
            "--credential",
            "ref-1",
        ]))
        .unwrap();
        match parsed.command {
            crate::Command::MachineAccess(
                crate::machine_access::MachineAccessAction::Terminal { target },
            ) => {
                assert_eq!(target.machine, "m1");
                assert_eq!(target.endpoint.as_deref(), Some("e1"));
                assert_eq!(target.auth.kind.as_deref(), Some("secret"));
            }
            other => panic!("{other:?}"),
        }
        assert!(crate::parse(&args(&["machines", "terminal"])).is_err());
        assert!(crate::parse(&args(&["machines", "terminal", "m1", "--os", "windows"])).is_err());
        assert!(crate::parse(&args(&["machines", "terminal", "m1", "--auth", "secret"])).is_err());
        assert!(crate::parse(&args(&["machines", "terminal", "m1", "--bogus", "x"])).is_err());
    }
}
