//! #335: every Packer child of an image build (the `version` and
//! `plugins installed` probes, `validate`, and `build`) sees only the
//! allowlisted environment plus what Fleet hands it, whatever the
//! controller process was started with.
//!
//! Each test re-runs this test binary filtered to itself, with sentinel
//! variables set, so they live in a real process environment without
//! racing other tests over `std::env::set_var`. The build goes through the
//! real executor and `ProcessTransport`; a fake `packer` copies
//! `/proc/$$/environ` (its exec-time environment, before the shell adds
//! anything) into a file per subcommand. It never contacts a Proxmox host:
//! a local TLS listener presents the account's certificate for Fleet's own
//! pin check.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision};
use fleet_application::images::{Images, NewRecipe, RecipePort as _};
use fleet_application::operation::{NewOperation, Operations};
use fleet_core::{RecipeContent, RecipeSource};
use fleet_storage_sqlite::{AuditSink, OperationRepository, RecipeRepository, Store};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Digest as _;

/// Set in the re-run child; names the directory it reports into.
const CHILD: &str = "FLEET_TEST_335_CHILD";

/// The account's stored token, handed only to the `build` child.
const ACCOUNT_TOKEN: &str = "00000000-fixture-account-token";

/// Ambient variables that must never reach Packer (with credentials
/// wired, the ambient `PROXMOX_*` included).
const SENTINELS: &[(&str, &str)] = &[
    ("FLEET_SENTINEL_335", "sentinel-leaked"),
    ("AWS_SECRET_ACCESS_KEY", "sentinel-aws"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "/sentinel/gcp.json"),
    ("VAULT_TOKEN", "sentinel-vault"),
    ("CONSUL_HTTP_TOKEN", "sentinel-consul"),
    ("GIT_ASKPASS", "/sentinel/askpass"),
    ("HTTPS_PROXY", "http://sentinel:pw@proxy.invalid:3128"),
    ("https_proxy", "http://sentinel:pw@proxy.invalid:3128"),
    // The controller's own PVE client honors the proxy variables; its pin
    // check must still reach the local listener.
    ("NO_PROXY", "sentinel.invalid,127.0.0.1"),
    ("PKR_VAR_sentinel", "sentinel-pkr-var"),
    ("PACKER_LOG", "sentinel-log"),
    ("PACKER_GITHUB_API_TOKEN", "sentinel-gh"),
    ("GODEBUG", "x509sha1=1"),
    ("SSL_CERT_FILE", "/sentinel/roots.pem"),
    ("SSL_CERT_DIR", "/sentinel/roots.d"),
    ("SSH_AUTH_SOCK", "/sentinel/agent.sock"),
];

/// The controller's own Proxmox credential: dropped once accounts are
/// wired, its only credential when they are not.
const AMBIENT_PROXMOX: &[(&str, &str)] = &[
    ("PROXMOX_USERNAME", "sentinel@pve!ambient"),
    ("PROXMOX_TOKEN", "sentinel-ambient-token"),
    ("PROXMOX_URL", "https://sentinel.invalid:8006/api2/json"),
];

/// Allowlisted variables the child sets, to prove they pass through.
const PASSED_THROUGH: &[(&str, &str)] = &[("PACKER_PLUGIN_PATH", "/fleet-test/plugins")];

/// The ambient names that may reach Packer, written out independently of
/// the provider's own list.
const ALLOWED: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "XDG_CONFIG_HOME",
    "PACKER_PLUGIN_PATH",
    "PACKER_CONFIG_DIR",
    "PACKER_CONFIG",
    "PACKER_CACHE_DIR",
];

const SUBCOMMANDS: &[&str] = &["version", "installed", "validate", "build"];

#[derive(Debug)]
struct Allow;
impl Authorizer for Allow {
    fn decide(&self, _: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[derive(Debug)]
struct Token;
#[async_trait::async_trait]
impl fleet_application::proxmox::ProxmoxCredentialStore for Token {
    async fn load(
        &self,
        _: &str,
    ) -> Result<Option<String>, fleet_application::proxmox::CredentialStoreError> {
        Ok(Some(ACCOUNT_TOKEN.to_owned()))
    }
    async fn store(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(), fleet_application::proxmox::CredentialStoreError> {
        Ok(())
    }
    async fn clear(&self, _: &str) -> Result<(), fleet_application::proxmox::CredentialStoreError> {
        Ok(())
    }
}

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
        .envs(AMBIENT_PROXMOX.iter().copied())
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

fn mark_ran() {
    std::fs::write(Path::new(&std::env::var_os(CHILD).unwrap()).join("ran"), "").unwrap();
}

/// The fake CLI: dumps its exec-time environment to `env-<subcommand>`,
/// answers both probes inside the pins, accepts the recipe, and fails the
/// build (nothing here can build an image).
fn fake_packer(dir: &Path) -> PathBuf {
    let path = dir.join("packer");
    let script = format!(
        "#!/bin/sh\n\
         name=unknown\n\
         for arg in \"$@\"; do case \"$arg\" in version|installed|validate|build) name=$arg ;; esac; done\n\
         tr '\\0' '\\n' < /proc/$$/environ > '{dir}/env-'\"$name\"\n\
         case \"$name\" in\n\
           version) echo '1,,version,1.16.1' ;;\n\
           installed) echo '/fleet-test/plugins/github.com/hashicorp/proxmox/packer-plugin-proxmox_v1.2.4_x5.0_linux_amd64' ;;\n\
           build) echo '1,,ui,error,fake build'; exit 1 ;;\n\
         esac\n",
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
    std::fs::read_to_string(dir.join(format!("env-{name}")))
        .unwrap_or_else(|error| panic!("no Packer child ran {name}: {error}"))
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// The allowlisted part of this process's environment plus Fleet's fixed
/// variables: what a child handed nothing sees.
fn baseline() -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = std::env::vars()
        .filter(|(key, _)| {
            ALLOWED.contains(&key.as_str()) || (key.starts_with("LC_") && key.len() > 3)
        })
        .collect();
    for (key, value) in [
        ("CHECKPOINT_DISABLE", "1"),
        ("PACKER_NO_COLOR", "1"),
        ("SSH_AUTH_SOCK", ""),
    ] {
        env.insert(key.to_owned(), value.to_owned());
    }
    env
}

fn with(mut env: BTreeMap<String, String>, vars: &[(&str, &str)]) -> BTreeMap<String, String> {
    for (key, value) in vars {
        env.insert((*key).to_owned(), (*value).to_owned());
    }
    env
}

fn assert_no_sentinel(name: &str, env: &BTreeMap<String, String>) {
    for (key, value) in SENTINELS {
        assert!(
            !env.values().any(|seen| seen == value),
            "{name}: the value of {key} reached Packer: {env:?}"
        );
    }
    for (key, value) in PASSED_THROUGH {
        assert_eq!(env.get(*key).map(String::as_str), Some(*value), "{name}");
    }
}

/// The child's own setup really carries every sentinel.
fn assert_sentinels_present() {
    for (key, value) in SENTINELS.iter().chain(AMBIENT_PROXMOX) {
        assert_eq!(std::env::var(key).as_deref(), Ok(*value), "{key}");
    }
}

/// A pveproxy-shaped leaf for 127.0.0.1.
fn leaf() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned(), "localhost".to_owned()])
            .unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.self_signed(&key).unwrap();
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

/// Presents `leaf` on every connection, for Fleet's credential-free pin
/// check; the fake Packer never connects.
async fn serve(leaf: &(CertificateDer<'static>, PrivateKeyDer<'static>)) -> u16 {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf.0.clone()], leaf.1.clone_key())
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    port
}

/// Runs one build through the executor over the fake CLI, with account
/// credentials wired or not; answers the build's outcome and reason.
async fn build(fake_dir: &Path, wired: bool) -> (String, Option<String>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pinned = leaf();
    let port = serve(&pinned).await;
    let digest: [u8; 32] = sha2::Sha256::digest(pinned.0.as_ref()).into();
    let pin: String = digest.iter().map(|byte| format!("{byte:02X}")).collect();
    sqlx::query("INSERT INTO proxmox_accounts (id, name, host, port, token_id, fingerprint, created_at) VALUES ('account-1', 'fixture', '127.0.0.1', ?1, 'fixture@pve!builder', ?2, 1)")
        .bind(i64::from(port))
        .bind(pin)
        .execute(store.pool())
        .await
        .unwrap();
    let repository = Arc::new(RecipeRepository::new(store.pool().clone()));
    let audit = Arc::new(AuditSink::new(store.pool().clone()));
    let images = Images::new(repository.clone(), audit.clone());
    let principal = ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    };
    let content = serde_json::json!({"builders": [{
        "type": "proxmox-clone",
        "proxmox_url": format!("https://127.0.0.1:{port}/api2/json"),
        "node": "pve",
        "clone_vm_id": 9000,
        "vm_id": 949,
        "vm_name": "fleet-child-env",
        "template_name": "fleet-child-env",
        "communicator": "none",
        "task_timeout": "30s"
    }]})
    .to_string();
    let recipe = images
        .create(
            &Allow,
            &principal,
            NewRecipe {
                content: RecipeContent {
                    name: "child-env".to_owned(),
                    description: String::new(),
                    node: "pve".to_owned(),
                    storage_pool: Some("local-lvm".to_owned()),
                    source: RecipeSource::Clone,
                    content,
                },
            },
            1,
        )
        .await
        .unwrap();
    let version = images
        .publish(&Allow, &principal, &recipe.id, 2)
        .await
        .unwrap();
    let operations = Operations::new(
        Arc::new(OperationRepository::new(store.pool().clone())),
        audit,
    );
    operations
        .create(
            &Allow,
            &principal.id,
            &NewOperation {
                kind: "image.build".to_owned(),
                payload_json: Some(
                    serde_json::json!({"versionId": version.id, "timeoutSeconds": 120, "accountId": "account-1"})
                        .to_string(),
                ),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                review_token: None,
            },
        )
        .await
        .unwrap();
    let mut report = fleet_application::worker::TickReport::default();
    let operation = operations
        .claim_only(
            "child-env",
            fleet_core::SystemClock::now_unix_millis(),
            &mut report,
        )
        .await
        .unwrap()
        .unwrap();
    let mut executor = fleet_controller::images_exec::ImagesExecutor::new(
        repository.clone(),
        Arc::new(fleet_provider_packer::ProcessTransport::with_binary(
            fake_packer(fake_dir),
        )),
        None,
        dir.path().join("work"),
    );
    if wired {
        executor = executor.with_account_credentials(
            Arc::new(fleet_storage_sqlite::ProxmoxAccountRepository::new(
                store.pool().clone(),
            )),
            Arc::new(Token),
            Arc::new(fleet_provider_proxmox::ReqwestPveTransport::new()),
        );
    }
    assert!(
        operations
            .execute_claimed(&executor, operation.clone())
            .await
    );
    let record = repository.get_build(&operation.id).await.unwrap();
    (record.outcome, record.reason)
}

#[tokio::test]
async fn with_accounts_wired_each_packer_child_sees_only_the_allowlist_and_its_own_credential() {
    let test =
        "with_accounts_wired_each_packer_child_sees_only_the_allowlist_and_its_own_credential";
    if rerun_with_sentinels(test) {
        return;
    }
    assert_sentinels_present();
    let fake = tempfile::tempdir().unwrap();
    let (outcome, reason) = build(fake.path(), true).await;
    // The fake reached `build` and failed it there: every child ran.
    assert_eq!(outcome, "failed");
    assert_eq!(reason.as_deref(), Some("build_failed"));

    for probe in ["version", "installed"] {
        let env = dumped(fake.path(), probe);
        assert_no_sentinel(probe, &env);
        assert_eq!(env, baseline(), "{probe}");
    }
    let validate = dumped(fake.path(), "validate");
    let build = dumped(fake.path(), "build");
    assert_no_sentinel("validate", &validate);
    assert_no_sentinel("build", &build);
    // The pinned roots are Fleet's, in the build's work directory.
    let cert_file = build.get("SSL_CERT_FILE").cloned().unwrap();
    let cert_dir = build.get("SSL_CERT_DIR").cloned().unwrap();
    assert!(cert_file.ends_with("/tls/pinned.pem"), "{cert_file}");
    assert!(cert_dir.ends_with("/tls/roots.d"), "{cert_dir}");
    let tls = [
        ("SSL_CERT_FILE", cert_file.as_str()),
        ("SSL_CERT_DIR", cert_dir.as_str()),
    ];
    assert_eq!(
        validate,
        with(
            with(baseline(), &tls),
            &[
                ("PROXMOX_USERNAME", "fleet@pve!validate"),
                ("PROXMOX_TOKEN", "00000000-0000-0000-0000-000000000000"),
            ]
        )
    );
    assert_eq!(
        build,
        with(
            with(baseline(), &tls),
            &[
                ("PROXMOX_USERNAME", "fixture@pve!builder"),
                ("PROXMOX_TOKEN", ACCOUNT_TOKEN),
            ]
        )
    );
    mark_ran();
}

#[tokio::test]
async fn without_accounts_wired_packer_gets_only_the_allowlist_and_the_ambient_proxmox_credential()
{
    let test =
        "without_accounts_wired_packer_gets_only_the_allowlist_and_the_ambient_proxmox_credential";
    if rerun_with_sentinels(test) {
        return;
    }
    assert_sentinels_present();
    let fake = tempfile::tempdir().unwrap();
    let (outcome, reason) = build(fake.path(), false).await;
    assert_eq!(outcome, "failed");
    assert_eq!(reason.as_deref(), Some("build_failed"));
    // The legacy mode's only credential is the controller's own
    // `PROXMOX_*`; nothing else of the controller's environment passes.
    for name in SUBCOMMANDS {
        let env = dumped(fake.path(), name);
        assert_no_sentinel(name, &env);
        assert_eq!(env, with(baseline(), AMBIENT_PROXMOX), "{name}");
    }
    mark_ran();
}
