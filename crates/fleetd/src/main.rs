//! The `fleetd` binary: argument parsing over the library's composition.
//! All behavior lives in the library so integration tests exercise the real
//! client.

use fleetd::{Command, EnrollArgs, RunArgs};

const HELP: &str = "Usage:
  fleetd enroll --controller <url> (--token <token> | --token-stdin) [--state-dir <path>]
  fleetd run --controller <url> [--state-dir <path>] [--local-group <gid>]
  fleetd [--help|--version]

--token-stdin reads the enrollment token from standard input. Automated
installs must use it: a token on argv is readable from the process list,
and the whole point of a single-use token is that it leaves no reusable
trace.";

fn parse_args() -> Result<Command, String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(HELP.to_owned());
    };
    let mut controller = None;
    let mut token = None;
    let mut token_stdin = false;
    let mut state_dir = None;
    let mut local_group = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--controller" => {
                controller = Some(
                    args.next()
                        .ok_or_else(|| "the --controller flag requires a URL".to_owned())?,
                );
            }
            "--token" => {
                token = Some(
                    args.next()
                        .ok_or_else(|| "the --token flag requires a value".to_owned())?,
                );
            }
            "--token-stdin" => {
                token_stdin = true;
            }
            "--state-dir" => {
                state_dir = Some(
                    args.next()
                        .ok_or_else(|| "the --state-dir flag requires a path".to_owned())?,
                );
            }
            "--local-group" => {
                let value = args
                    .next()
                    .ok_or_else(|| "the --local-group flag requires a gid".to_owned())?;
                local_group =
                    Some(value.parse().map_err(|_| {
                        format!("--local-group must be a gid number, not {value:?}")
                    })?);
            }
            other => return Err(format!("unknown argument {other:?}\n{HELP}")),
        }
    }
    match command.as_str() {
        "enroll" => Ok(Command::Enroll(EnrollArgs {
            controller: controller.ok_or("enroll requires --controller <url>")?,
            token,
            token_stdin,
            state_dir,
        })),
        "run" => Ok(Command::Run(RunArgs {
            controller: controller.ok_or("run requires --controller <url>")?,
            state_dir,
            local_group,
        })),
        other => Err(format!("unknown command {other:?}\n{HELP}")),
    }
}

fn main() -> std::process::ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("fleetd {}", env!("CARGO_PKG_VERSION"));
            return std::process::ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!("{HELP}");
            return std::process::ExitCode::SUCCESS;
        }
        _ => {}
    }
    fleetd::main_exit(parse_args())
}
