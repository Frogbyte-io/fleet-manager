//! Repeatable repository verification tasks.

use std::fmt::{self, Display, Formatter};
use std::io;
use std::process::{Command, ExitStatus};

/// One command in the repository verification sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationStep {
    /// Human-readable name printed before the command runs.
    pub label: &'static str,
    program: &'static str,
    args: &'static [&'static str],
}

impl VerificationStep {
    fn command_text(self) -> String {
        format!("{} {}", self.program, self.args.join(" "))
    }
}

const STEPS: &[VerificationStep] = &[
    VerificationStep {
        label: "Rust formatting",
        program: "cargo",
        args: &["fmt", "--all", "--check"],
    },
    VerificationStep {
        label: "Rust clippy",
        program: "cargo",
        args: &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    },
    VerificationStep {
        label: "Rust tests",
        program: "cargo",
        args: &["test", "--workspace", "--all-features", "--locked"],
    },
    VerificationStep {
        label: "Generated desired-resource schema",
        program: "cargo",
        args: &[
            "run",
            "--locked",
            "-p",
            "fleet-schema",
            "--",
            "generate",
            "--check",
        ],
    },
    VerificationStep {
        label: "Generated OpenAPI document",
        program: "cargo",
        args: &[
            "run",
            "--locked",
            "-p",
            "fleet-api",
            "--bin",
            "fleet-openapi",
            "--",
            "generate",
            "--check",
        ],
    },
    VerificationStep {
        label: "Web frozen install",
        program: "corepack",
        args: &["pnpm", "install", "--frozen-lockfile"],
    },
    VerificationStep {
        label: "Generated API client",
        program: "corepack",
        args: &["pnpm", "-r", "--if-present", "run", "check:generated"],
    },
    VerificationStep {
        label: "Web lint",
        program: "corepack",
        args: &["pnpm", "-r", "--if-present", "run", "lint"],
    },
    VerificationStep {
        label: "Web type-check",
        program: "corepack",
        args: &["pnpm", "-r", "--if-present", "run", "typecheck"],
    },
    VerificationStep {
        label: "Web build",
        program: "corepack",
        args: &["pnpm", "-r", "--if-present", "run", "build"],
    },
];

/// Returns the ordered commands run by [`verify_with`].
#[must_use]
pub const fn verification_steps() -> &'static [VerificationStep] {
    STEPS
}

/// Executes commands for the verifier.
pub trait CommandRunner {
    /// Runs one program and returns its exit status.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the child process cannot be
    /// started or observed.
    fn run(&mut self, program: &str, args: &[&str]) -> io::Result<ExitStatus>;
}

/// Runs verification commands as child processes with inherited output.
#[derive(Default)]
pub struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> io::Result<ExitStatus> {
        Command::new(program).args(args).status()
    }
}

/// A repository verification step that could not be completed.
#[derive(Debug)]
pub enum VerificationError {
    /// The command started but returned a non-zero status.
    CommandFailed {
        /// Human-readable step name.
        label: &'static str,
        /// Exact command that failed.
        command: String,
    },
    /// The command could not be started or observed.
    CommandIo {
        /// Human-readable step name.
        label: &'static str,
        /// Exact command that could not run.
        command: String,
        /// Operating-system process error.
        source: io::Error,
    },
}

impl Display for VerificationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandFailed { label, command } => {
                write!(formatter, "{label} failed: {command}")
            }
            Self::CommandIo {
                label,
                command,
                source,
            } => write!(formatter, "{label} could not run: {command}: {source}"),
        }
    }
}

impl std::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CommandFailed { .. } => None,
            Self::CommandIo { source, .. } => Some(source),
        }
    }
}

/// Runs every repository verification step, stopping at the first failure.
///
/// # Errors
///
/// Returns [`VerificationError`] when a command cannot start or exits with a
/// non-zero status.
pub fn verify_with(runner: &mut impl CommandRunner) -> Result<(), VerificationError> {
    for step in verification_steps() {
        let command = step.command_text();
        println!("\n==> {}\n    {command}", step.label);
        let status =
            runner
                .run(step.program, step.args)
                .map_err(|source| VerificationError::CommandIo {
                    label: step.label,
                    command: command.clone(),
                    source,
                })?;
        if !status.success() {
            return Err(VerificationError::CommandFailed {
                label: step.label,
                command,
            });
        }
    }
    Ok(())
}
