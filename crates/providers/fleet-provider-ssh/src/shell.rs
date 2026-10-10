//! The guest shell: how a fixed script and its inert metadata reach a guest.
//!
//! One transport rule holds for every guest OS: **caller data never reaches a
//! remote shell as shell text.** What differs is how the fixed text and the
//! data are framed. [`GuestShell::Posix`] sends `bash -s -- <blob>` as the
//! command and the prologue plus script on stdin. The framing for each OS is
//! owned here, so the executors (`exec`, `fetch`, `put`, `detached`) never
//! build a command line themselves.

use std::io::Write as _;
use std::time::Duration;

use fleet_core::GuestOs;

use crate::exec::{ScriptMetadata, encode_metadata, remote_prologue};
use crate::{SshConnectionSpec, SshProvider, SshProviderError};

/// The remote shell a guest is driven through.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestShell {
    /// Bash on a Linux guest.
    Posix,
}

impl GuestShell {
    /// The shell for a guest OS.
    ///
    /// # Errors
    ///
    /// Fails for a guest OS this build has no shell for.
    pub fn for_os(os: GuestOs) -> Result<Self, SshProviderError> {
        match os {
            GuestOs::Linux => Ok(Self::Posix),
            GuestOs::Windows => Err(SshProviderError::Setup {
                detail: "Windows guests are not supported by this build".to_owned(),
            }),
        }
    }

    /// The one command string handed to the remote login shell: fixed text,
    /// plus for Bash the shell-inert metadata blob.
    pub(crate) fn command_line(self, metadata: &ScriptMetadata) -> String {
        match self {
            Self::Posix => format!("bash -s -- {}", encode_metadata(metadata)),
        }
    }

    /// The bytes written to the session's stdin before any payload: the
    /// prologue and the script.
    pub(crate) fn session_input(self, script: &str, _metadata: &ScriptMetadata) -> Vec<u8> {
        match self {
            Self::Posix => format!("{}{script}", remote_prologue()).into_bytes(),
        }
    }
}

/// Starts an `ssh` session running `script` with `metadata` through the
/// endpoint's guest shell. The script has been written to the session's
/// stdin, which stays open: a caller that streams a payload after the script
/// keeps writing to it, and everyone else drops it.
pub(crate) fn spawn_script_session(
    provider: &SshProvider,
    endpoint: &SshConnectionSpec,
    metadata: &ScriptMetadata,
    script: &str,
    deadline: Duration,
) -> Result<std::process::Child, SshProviderError> {
    let shell = GuestShell::for_os(endpoint.guest_os)?;
    let config_path = provider.write_config(&endpoint.auth)?;

    let mut command = std::process::Command::new("ssh");
    command
        .arg("-F")
        .arg(&config_path)
        .arg("-o")
        .arg(format!("ConnectTimeout={}", deadline.as_secs().max(1)))
        .arg("-T")
        .arg("-p")
        .arg(endpoint.port.to_string());
    if let crate::SshAuth::IdentityFile { path } = &endpoint.auth {
        command.arg("-i").arg(path);
    }
    crate::add_ssh_destination(&mut command, endpoint);
    command
        .arg(shell.command_line(metadata))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().map_err(|error| SshProviderError::Tool {
        tool: "ssh",
        detail: format!("cannot start: {error}"),
    })?;
    let stdin = child.stdin.as_mut().ok_or_else(|| SshProviderError::Tool {
        tool: "ssh",
        detail: "the ssh process has no stdin".to_owned(),
    })?;
    if let Err(error) = stdin.write_all(&shell.session_input(script, metadata)) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: format!("cannot send the script: {error}"),
        });
    }
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_posix_framing_is_the_bash_framing() {
        let metadata = ScriptMetadata {
            working_directory: "/tmp".to_owned(),
            environment: vec![("A".to_owned(), "b c".to_owned())],
            arguments: vec!["x".to_owned()],
        };
        let shell = GuestShell::for_os(GuestOs::Linux).unwrap();
        assert_eq!(
            shell.command_line(&metadata),
            format!("bash -s -- {}", encode_metadata(&metadata))
        );
        assert_eq!(
            shell.session_input("echo hi\n", &metadata),
            format!("{}echo hi\n", remote_prologue()).into_bytes()
        );
    }
}
