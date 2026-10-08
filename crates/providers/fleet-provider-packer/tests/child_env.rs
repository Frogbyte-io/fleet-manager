//! #335: a Packer child sees only the allowlisted environment, whatever the
//! controller process was started with.
//!
//! Each test re-runs this test binary filtered to itself, with sentinel
//! variables set, so the sentinels exist in a real process environment
//! without racing other tests over `std::env::set_var`. A fake `packer`
//! copies `/proc/$$/environ` (the environment it was executed with, before
//! the shell adds anything) into a file per invocation.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fleet_provider_packer::{PackerClient, PackerCommand, PackerTransport as _, ProcessTransport};

/// Set in the re-run child; names the directory it reports into.
const CHILD: &str = "FLEET_TEST_335_CHILD";

/// Ambient variables that must never reach Packer.
const SENTINELS: &[(&str, &str)] = &[
    ("FLEET_SENTINEL_335", "leaked"),
    ("AWS_SECRET_ACCESS_KEY", "sentinel-aws"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "/sentinel/gcp.json"),
    ("VAULT_TOKEN", "sentinel-vault"),
    ("GIT_ASKPASS", "/sentinel/askpass"),
    ("HTTPS_PROXY", "http://sentinel:pw@proxy.invalid:3128"),
    ("http_proxy", "http://sentinel:pw@proxy.invalid:3128"),
    ("NO_PROXY", "sentinel.invalid"),
    ("PKR_VAR_sentinel", "sentinel-pkr-var"),
    ("PACKER_LOG", "sentinel-1"),
    ("PACKER_LOG_PATH", "/sentinel/packer.log"),
    ("PACKER_GITHUB_API_TOKEN", "sentinel-gh"),
    ("GODEBUG", "x509sha1=1"),
    ("SSL_CERT_FILE", "/sentinel/roots.pem"),
    ("PROXMOX_USERNAME", "sentinel@pve!ambient"),
    ("PROXMOX_TOKEN", "sentinel-ambient-token"),
    ("PROXMOX_URL", "https://sentinel.invalid:8006/api2/json"),
    ("SSH_AUTH_SOCK", "/sentinel/agent.sock"),
];

/// Allowlisted variables the child sets, to prove they pass through.
const PASSED_THROUGH: &[(&str, &str)] = &[
    ("PACKER_PLUGIN_PATH", "/fleet-test/plugins"),
    ("LC_MESSAGES", "C"),
];

/// The ambient names that may reach Packer, written out independently of
/// the provider's own list.
const ALLOWED: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "PACKER_PLUGIN_PATH",
    "PACKER_CONFIG_DIR",
    "PACKER_CONFIG",
    "PACKER_CACHE_DIR",
];

/// Runs `test` again in a child process with the sentinels set, and
/// answers whether this is the parent (which is then done: the child
/// passed). The child answers `false` and runs the body.
fn rerun_with_sentinels(test: &str) -> bool {
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let report = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, report.path())
        .envs(SENTINELS.iter().copied())
        .envs(PASSED_THROUGH.iter().copied())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "the re-run failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // A filter that matched nothing would also succeed: the body proves
    // it ran.
    assert!(
        report.path().join("ran").exists(),
        "the re-run never ran {test}"
    );
    true
}

/// The fake CLI: dumps its exec-time environment to `env-<args>` and
/// answers the version probe.
fn fake_packer(dir: &Path) -> PathBuf {
    let path = dir.join("packer");
    let script = format!(
        "#!/bin/sh\n\
         name=$(printf '%s' \"$*\" | tr -c 'a-z' '_')\n\
         tr '\\0' '\\n' < /proc/$$/environ > '{dir}/env-'\"$name\"\n\
         case \"$*\" in *version*) echo '1,,version,1.16.1' ;; esac\n",
        dir = dir.display()
    );
    std::fs::write(&path, script).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

fn dumped(dir: &Path, name: &str) -> BTreeMap<String, String> {
    let bytes = std::fs::read(dir.join(format!("env-{name}")))
        .unwrap_or_else(|error| panic!("no dump for {name}: {error}"));
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// The exact environment a child handed `handed` must see in this process.
fn expected(handed: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = std::env::vars_os()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .filter(|(key, _)| {
            ALLOWED.contains(&key.as_str()) || (key.starts_with("LC_") && key.len() > 3)
        })
        .collect();
    for (key, value) in [
        ("CHECKPOINT_DISABLE", "1"),
        ("PACKER_NO_COLOR", "1"),
        ("SSH_AUTH_SOCK", ""),
    ]
    .iter()
    .chain(handed)
    {
        env.insert((*key).to_owned(), (*value).to_owned());
    }
    env
}

fn assert_clean(name: &str, env: &BTreeMap<String, String>, want: &BTreeMap<String, String>) {
    for (key, value) in SENTINELS {
        assert!(
            !env.values().any(|seen| seen == value),
            "{name}: the value of {key} leaked: {env:?}"
        );
    }
    assert_eq!(env, want, "{name}");
    for (key, value) in PASSED_THROUGH {
        assert_eq!(env.get(*key).map(String::as_str), Some(*value), "{name}");
    }
}

/// The child's own setup really carries the sentinels.
fn assert_sentinels_present() {
    for (key, value) in SENTINELS {
        assert_eq!(std::env::var(key).as_deref(), Ok(*value), "{key}");
    }
}

#[tokio::test]
async fn the_version_probe_and_both_run_paths_see_only_the_allowlist() {
    if rerun_with_sentinels("the_version_probe_and_both_run_paths_see_only_the_allowlist") {
        return;
    }
    assert_sentinels_present();
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(ProcessTransport::with_binary(fake_packer(dir.path())));

    // The version gate: `SecretEnv::default()`.
    let version = PackerClient::new(transport.clone())
        .version(dir.path().to_path_buf())
        .await
        .unwrap();
    assert_eq!(version.version, "1.16.1");

    // A command handed the account's variables, through both run paths.
    let handed = [
        ("PROXMOX_USERNAME", "fleet@pve!build"),
        ("PROXMOX_TOKEN", "handed-token"),
        ("SSL_CERT_FILE", "/work/tls/pinned.pem"),
        ("SSL_CERT_DIR", "/work/tls/roots.d"),
    ];
    let command = |arg: &str| PackerCommand {
        args: vec![arg.to_owned()],
        work_dir: dir.path().to_path_buf(),
        env: fleet_provider_packer::SecretEnv::new(
            handed
                .iter()
                .map(|(key, value)| ((*key).to_owned(), fleet_core::SensitiveString::new(*value)))
                .collect(),
        ),
    };
    let plain = transport
        .run(&command("validate"), Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(plain.exit_code, Some(0), "{plain:?}");
    let (_stop, stop_rx) = tokio::sync::watch::channel(false);
    let stoppable = transport
        .run_stoppable(&command("build"), Duration::from_secs(30), stop_rx)
        .await
        .unwrap();
    assert_eq!(stoppable.outcome.exit_code, Some(0), "{stoppable:?}");

    assert_clean(
        "version",
        &dumped(dir.path(), "_machine_readable_version"),
        &expected(&[]),
    );
    assert_clean("run", &dumped(dir.path(), "validate"), &expected(&handed));
    assert_clean(
        "run_stoppable",
        &dumped(dir.path(), "build"),
        &expected(&handed),
    );
    std::fs::write(Path::new(&std::env::var_os(CHILD).unwrap()).join("ran"), "").unwrap();
}
