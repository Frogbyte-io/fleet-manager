//! FM-703: table-driven contract tests over the recorded Packer
//! machine-readable fixtures (`tests/fixtures/1.16.1`, see the fixture
//! set's README for the exact capture commands and provenance).
//!
//! ADR-0005: external CLI integrations are contract-tested against the
//! documented machine-readable stream as the CLI actually emits it. If a
//! fixture shows the parser is wrong, stop and file a bug issue instead
//! of changing parser logic here.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fleet_provider_packer::{
    BuildStream, CliOutcome, PackerClient, PackerCommand, PackerTransport,
};

const FIXTURES: &str = "tests/fixtures/1.16.1";

/// One scenario: the recorded transcript and what the public parser API
/// must answer for it.
struct Scenario {
    /// The fixture file, relative to the fixture directory.
    file: &'static str,
    /// The parsed-stream assertions.
    expect: fn(&BuildStream),
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURES)
        .join(name)
}

fn transcript(name: &str) -> String {
    let path = fixture_path(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()))
}

/// Replays a recorded `CliOutcome` through the client — the same shape
/// the real transport returns.
#[derive(Debug)]
struct RecordedTransport {
    outcome: CliOutcome,
}

#[async_trait::async_trait]
impl PackerTransport for RecordedTransport {
    async fn run(
        &self,
        _command: &PackerCommand,
        _deadline: Duration,
    ) -> Result<CliOutcome, String> {
        Ok(self.outcome.clone())
    }
}

/// The version-gate answer for the recorded `packer -machine-readable
/// version` stream.
#[tokio::test]
async fn version_gate_opens_for_the_recorded_1_16_1_stream() {
    let stdout = transcript("version.txt");
    let transport = Arc::new(RecordedTransport {
        outcome: CliOutcome {
            stdout,
            stderr: String::new(),
            exit_code: Some(0),
            killed_by_deadline: false,
        },
    });
    let client = PackerClient::new(transport);
    let version = client
        .version(PathBuf::from("work"))
        .await
        .expect("the recorded version stream must open the gate");
    assert_eq!(version.version, "1.16.1");
}

/// Every scenario's stream answers as the parser contract requires.
#[test]
fn recorded_streams_answer_the_parser_contract() {
    let scenarios = [
        Scenario {
            file: "version.txt",
            expect: |stream| {
                // `version`/`version-prelease`/`version-commit` events are
                // not `ui` messages; the human line rides `ui,say`.
                assert!(stream.messages.is_empty());
                assert_eq!(stream.says, ["Packer v1.16.1"]);
                assert!(stream.errors.is_empty());
                assert!(stream.artifacts.is_empty());
            },
        },
        Scenario {
            file: "plugins-installed.txt",
            expect: |stream| {
                // The installed-plugin answer is one `ui,message` carrying
                // the plugin path; the pinned plugin's binary name and
                // version ride it.
                assert_eq!(stream.messages.len(), 1);
                let message = &stream.messages[0];
                assert!(
                    message.contains("packer-plugin-proxmox_v1.2.4_x5.0_linux_amd64"),
                    "the recorded plugin path must carry the pinned plugin: {message}"
                );
                assert!(stream.says.is_empty());
                assert!(stream.errors.is_empty());
            },
        },
        Scenario {
            file: "validate-valid.txt",
            expect: |stream| {
                // A valid recipe is exactly one `ui,say` line and no
                // errors: the parser contract for "validate succeeded".
                assert_eq!(stream.says, ["The configuration is valid."]);
                assert!(stream.errors.is_empty());
                assert!(stream.messages.is_empty());
            },
        },
        Scenario {
            file: "validate-invalid.txt",
            expect: |stream| {
                // Both wrong-typed attributes ride ONE `ui,error` event:
                // the CLI emits the diagnostic blob as a single
                // comma-escaped stream segment — this is what the
                // recorded transcript pins.
                assert_eq!(stream.errors.len(), 1);
                let joined = stream.errors.join("\n");
                assert!(
                    joined.contains("Inappropriate value for attribute \"clone_vm_id\""),
                    "the first recorded diagnostic must ride the error: {joined}"
                );
                assert!(
                    joined.contains("Inappropriate value for attribute \"cores\""),
                    "the second recorded diagnostic must ride the error: {joined}"
                );
                // `\n` escapes unescape into real newlines inside the
                // single `ui,error` event.
                assert_eq!(stream.says, Vec::<String>::new());
            },
        },
        Scenario {
            file: "build-interrupted.txt",
            expect: |stream| {
                let joined = stream.errors.join("\n");
                assert!(
                    joined.contains("Cancelling build after receiving terminated"),
                    "the interrupt marker must classify as an error: {joined}"
                );
                assert!(
                    joined.contains("Could not retrieve VM"),
                    "the build's failure detail must classify as an error: {joined}"
                );
                // The graceful cancel closes the stream with `ui,say`.
                assert!(
                    stream
                        .says
                        .iter()
                        .any(|say| say.contains("Cleanly cancelled builds after being interrupted")),
                    "the recorded cancel path must close the stream: {:?}",
                    stream.says
                );
                // The `\n`-prefixed step announcement unescapes into a
                // leading newline on one `ui,say`.
                assert!(
                    stream.messages.is_empty(),
                    "build cancels carry no `ui,message` events: {:?}",
                    stream.messages
                );
            },
        },
    ];

    for scenario in scenarios {
        let stdout = transcript(scenario.file);
        let stream = BuildStream::parse(&stdout);
        (scenario.expect)(&stream);
    }
}

/// Every line of every fixture is a machine-readable event: the parser
/// never has to skip one (Go log noise rides stderr, which is empty for
/// all recorded commands).
#[test]
fn every_fixture_line_is_a_machine_readable_event() {
    let scenarios = [
        "version.txt",
        "plugins-installed.txt",
        "validate-valid.txt",
        "validate-invalid.txt",
        "build-interrupted.txt",
    ];
    let mut lines_checked = 0usize;
    for scenario in scenarios {
        let path = fixture_path(scenario);
        let stdout = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()));
        for (index, line) in stdout.lines().enumerate() {
            assert!(
                super_parse(line),
                "{}:{} is not a machine-readable event: {line:?}",
                path.display(),
                index + 1
            );
            lines_checked += 1;
        }
    }
    assert!(
        lines_checked >= 8,
        "the fixture set should keep covering at least the recorded \
         scenarios, parsed {lines_checked} lines"
    );
}

/// The parser entry point under test, without importing it twice.
fn super_parse(line: &str) -> bool {
    fleet_provider_packer::parse_machine_readable_line(line).is_some()
}

/// The redaction contract of the fixture set: no private ranges, no
/// secrets, no real hostnames. `192.0.2.x` (TEST-NET-1, RFC 5737) and the
/// fixture constants are the only host-shaped values allowed.
#[test]
fn fixtures_carry_no_private_hosts_secrets_or_lab_values() {
    let scenarios = [
        "version.txt",
        "plugins-installed.txt",
        "validate-valid.txt",
        "validate-invalid.txt",
        "build-interrupted.txt",
    ];
    let forbidden = [
        "10.",
        "172.",
        "192.168.",
        "127.0.0.1",
        "0.0.0.0",
        "fe80",
        "fd",
        "::1",
        "token_id",
        "PVEAPIToken",
        "BEGIN (OPENSSH|RSA|EC) PRIVATE",
        "CHANGEME",
    ];
    for scenario in scenarios {
        let path = fixture_path(scenario);
        let stdout = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()));
        for needle in forbidden {
            assert!(
                !stdout.contains(needle),
                "{scenario} must stay redacted: found {needle:?}"
            );
        }
        for line in stdout.lines() {
            let event = fleet_provider_packer::parse_machine_readable_line(line)
                .unwrap_or_else(|| panic!("{scenario} line is not an event: {line:?}"));
            let found: Vec<&str> = event
                .data
                .split(&[',', ' ', '\"'][..])
                .filter(|token| looks_like_embedded_address(token))
                .collect();
            for address in found {
                assert!(
                    address.starts_with("192.0.2."),
                    "{scenario} carries a non-TEST-NET address {address:?} in {line:?}"
                );
            }
        }
    }
}

/// A `-`-separated token whose segments are all decimal numbers.
fn looks_like_embedded_address(token: &str) -> bool {
    let mut segments = 0usize;
    for part in token.split('-') {
        if part.len() <= 3 && part.chars().all(|c| c.is_ascii_digit()) {
            if !part.is_empty() {
                segments += 1;
            }
        } else {
            return false;
        }
    }
    segments >= 3
}
