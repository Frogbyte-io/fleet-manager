//! An interactive shell over SSH under a pseudo-terminal (#494).
//!
//! The session is the system `ssh -tt` against the same isolated
//! configuration and `known_hosts` as every other Fleet session, so the
//! host-key trust gate applies unchanged. It runs under a real PTY owned by
//! this process (the `pty-process` crate contains the `unsafe` the workspace
//! otherwise forbids): `ssh` sees a terminal on its standard input, enters
//! raw mode on it, and reports the window size to the guest. A resize sets
//! the PTY's window size; the kernel delivers `SIGWINCH` to `ssh`, which
//! sends the guest a `window-change` request.
//!
//! Linux starts the login shell. Recorded Windows endpoints start an explicit
//! interactive PowerShell child and preserve its exit status through the
//! configured default shell (Windows PowerShell 5.1). A stored key is delivered
//! the way every other session delivers it: a mode-0600 file that lives as long as the
//! [`Terminal`] and is removed when it drops.
//!
//! Nothing read from or written to the terminal is logged or retained here.

use std::io;

use fleet_core::GuestOs;

use pty_process::{Command, OwnedReadPty, OwnedWritePty, Size};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::key::KeyFile;
use crate::{SshAuth, SshConnectionSpec, SshProvider, SshProviderError};

/// The widest and tallest terminal a caller may ask for.
pub const MAX_TERMINAL_DIMENSION: u16 = 1000;

/// The terminal type announced to the guest.
const TERM: &str = "xterm-256color";

/// A terminal's size in character cells.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalSize {
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
}

impl TerminalSize {
    /// The size, or `None` when a dimension is zero or beyond
    /// [`MAX_TERMINAL_DIMENSION`].
    #[must_use]
    pub fn new(cols: u16, rows: u16) -> Option<Self> {
        let valid = |value: u16| (1..=MAX_TERMINAL_DIMENSION).contains(&value);
        (valid(cols) && valid(rows)).then_some(Self { cols, rows })
    }

    fn pty(self) -> Size {
        Size::new(self.rows, self.cols)
    }
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

// A PTY plus an exec request avoids the shell-request exit-status path in
// Windows OpenSSH. Use the current default shell's installation, never PATH.
// The outer PowerShell must explicitly preserve the child's native status:
// https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
pub(crate) const WINDOWS_TERMINAL_COMMAND: &str =
    "& (Join-Path $PSHOME 'powershell.exe') -NoLogo -NoProfile; exit $LASTEXITCODE";

fn terminal_command(os: GuestOs) -> Option<&'static str> {
    match os {
        GuestOs::Windows => Some(WINDOWS_TERMINAL_COMMAND),
        GuestOs::Linux => None,
    }
}

/// What the terminal produced next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalEvent {
    /// Bytes the guest wrote to the terminal.
    Output(Vec<u8>),
    /// The `ssh` process ended. The code is `None` when a signal ended it.
    Exited(Option<i32>),
}

/// A running `ssh -tt` session.
#[derive(Debug)]
pub struct Terminal {
    child: tokio::process::Child,
    reader: OwnedReadPty,
    buffer: Vec<u8>,
    writer: OwnedWritePty,
    #[allow(clippy::option_option)]
    exited: Option<Option<i32>>,
    // Dropped with the session: removes a stored key's file.
    _key: Option<KeyFile>,
}

impl SshProvider {
    /// Starts an interactive shell on the endpoint.
    ///
    /// # Errors
    ///
    /// Fails when the key file, the PTY or `ssh` cannot be set up. A
    /// connection or authentication failure is not an error here: `ssh`
    /// reports it on the terminal and exits, and the caller sees the exit.
    pub fn open_terminal(
        &self,
        endpoint: &SshConnectionSpec,
        size: TerminalSize,
    ) -> Result<Terminal, SshProviderError> {
        let config_path = self.write_config(&endpoint.auth)?;
        let key_file = match &endpoint.auth {
            SshAuth::StoredKey { key } => Some(self.materialize_key(key)?),
            _ => None,
        };
        let tool = |detail: String| SshProviderError::Tool {
            tool: "ssh",
            detail,
        };
        let (pty, pts) = pty_process::open().map_err(|error| tool(error.to_string()))?;
        pty.resize(size.pty())
            .map_err(|error| tool(error.to_string()))?;

        let mut args: Vec<std::ffi::OsString> = vec![
            "-tt".into(),
            // No `~` escape sequences: every keystroke belongs to the guest.
            "-e".into(),
            "none".into(),
            "-F".into(),
            config_path.into(),
            "-o".into(),
            "ConnectTimeout=15".into(),
            // A dead path ends the session instead of hanging it.
            "-o".into(),
            "ServerAliveInterval=15".into(),
            "-o".into(),
            "ServerAliveCountMax=3".into(),
            // A terminal is a shell and nothing else: no forwarding, no
            // multiplexing, no local commands.
            "-o".into(),
            "ClearAllForwardings=yes".into(),
            "-o".into(),
            "ForwardAgent=no".into(),
            "-o".into(),
            "ForwardX11=no".into(),
            "-o".into(),
            "ControlPath=none".into(),
            "-o".into(),
            "PermitLocalCommand=no".into(),
            "-p".into(),
            endpoint.port.to_string().into(),
        ];
        match &endpoint.auth {
            SshAuth::IdentityFile { path } => {
                self.check_identity_file(path)?;
                args.push("-i".into());
                args.push(path.into());
            }
            SshAuth::StoredKey { .. } => {
                if let Some(file) = &key_file {
                    args.push("-i".into());
                    args.push(file.path().into());
                }
            }
            SshAuth::Agent => {}
        }
        args.push("--".into());
        args.push(format!("{}@{}", endpoint.user, endpoint.host).into());
        if let Some(command) = terminal_command(endpoint.guest_os) {
            args.push(command.into());
        }

        let child = Command::new("ssh")
            .args(args)
            .env("TERM", TERM)
            .kill_on_drop(true)
            .spawn(pts)
            .map_err(|error| tool(format!("cannot start: {error}")))?;
        let (reader, writer) = pty.into_split();
        Ok(Terminal {
            child,
            reader,
            buffer: vec![0_u8; 16 * 1024],
            writer,
            exited: None,
            _key: key_file,
        })
    }
}

impl Terminal {
    /// The next thing the terminal did: output, or the end of the session.
    /// Cancel-safe: dropping the future loses nothing, and once the session
    /// ended every call answers [`TerminalEvent::Exited`].
    pub async fn next_event(&mut self) -> TerminalEvent {
        if let Some(code) = self.exited {
            return TerminalEvent::Exited(code);
        }
        match self.reader.read(&mut self.buffer).await {
            Ok(count) if count > 0 => TerminalEvent::Output(self.buffer[..count].to_vec()),
            // End of file, or the EIO Linux reports once the slave closed:
            // the session is over; its exit status says how.
            Ok(_) | Err(_) => {
                let code = self
                    .child
                    .wait()
                    .await
                    .ok()
                    .and_then(|status| status.code());
                self.exited = Some(code);
                TerminalEvent::Exited(code)
            }
        }
    }

    /// Writes input (keystrokes, pasted text) to the guest's terminal.
    ///
    /// # Errors
    ///
    /// Fails when the terminal is gone.
    pub async fn write_input(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data).await?;
        self.writer.flush().await
    }

    /// Resizes the terminal; the guest learns of it through `ssh`.
    ///
    /// # Errors
    ///
    /// Fails when the terminal is gone.
    pub fn resize(&self, size: TerminalSize) -> io::Result<()> {
        self.writer.resize(size.pty()).map_err(io::Error::other)
    }

    /// Ends the session now: kills `ssh` and reaps it.
    pub async fn kill(&mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_windows_gets_a_fixed_interactive_command() {
        assert_eq!(terminal_command(GuestOs::Linux), None);
        assert_eq!(
            terminal_command(GuestOs::Windows),
            Some(WINDOWS_TERMINAL_COMMAND)
        );
        assert!(WINDOWS_TERMINAL_COMMAND.ends_with("exit $LASTEXITCODE"));
        assert!(!WINDOWS_TERMINAL_COMMAND.contains("NonInteractive"));
    }

    #[test]
    fn sizes_are_bounded() {
        assert!(TerminalSize::new(80, 24).is_some());
        assert!(TerminalSize::new(0, 24).is_none());
        assert!(TerminalSize::new(80, 0).is_none());
        assert!(TerminalSize::new(MAX_TERMINAL_DIMENSION + 1, 24).is_none());
        assert_eq!(TerminalSize::default().cols, 80);
    }
}
