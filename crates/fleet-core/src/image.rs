//! The image-recipe primitives (FM-700): the recipe content model, its
//! draft/version lifecycle, and the digest binding a build to the exact
//! bytes it was defined by.

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// The maximum recipe content Fleet accepts. A Packer template is bounded
/// configuration; anything larger is refused rather than materialized.
pub const MAX_RECIPE_CONTENT_BYTES: usize = 256 * 1024;

/// The source a recipe builds from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeSource {
    /// Build from an ISO (the classic install flow).
    #[default]
    Iso,
    /// Build by cloning an existing guest.
    Clone,
}

impl RecipeSource {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Iso => "iso",
            Self::Clone => "clone",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized source id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "iso" => Ok(Self::Iso),
            "clone" => Ok(Self::Clone),
            other => Err(format!("unrecognized recipe source {other:?}")),
        }
    }
}

/// One image recipe: the Fleet metadata plus the raw legacy-JSON Packer
/// template, stored verbatim. Fleet does not re-validate Packer's own
/// builder/provisioner *fields* — `packer validate` is the authority, and
/// unknown fields inside a builder or provisioner pass through untouched —
/// but the content is not opaque: [`recipe_build_refusal`] fails it closed
/// when its top-level structure escapes the provisioner allowlist (a
/// `post-processors` or `error-cleanup-provisioner` block, or any unknown
/// top-level key) or it reads the controller environment, files, or a
/// secret store through a template function, because a recipe runs with
/// the build's Proxmox token in Packer's environment (#313). The content
/// must be a JSON object; a non-JSON (e.g. HCL) template is refused, since
/// builds write it to Packer as legacy `.json`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeContent {
    /// The operator-facing recipe name.
    pub name: String,
    /// The operator-facing description.
    pub description: String,
    /// The PVE node the recipe builds on.
    pub node: String,
    /// The PVE storage pool the build writes to. `None` when the builder
    /// block omits it (consistent with `node`'s absence rule).
    pub storage_pool: Option<String>,
    /// What the recipe builds from.
    pub source: RecipeSource,
    /// The raw Packer template content (`.pkr.json`/`.pkr.hcl`), stored
    /// verbatim. Unknown fields are Fleet's problem never to touch.
    pub content: String,
}

impl RecipeContent {
    /// The SHA-256 digest of the recipe's bytes: the identity a build
    /// references, so a build of a since-edited recipe is reproducible.
    ///
    /// # Errors
    ///
    /// Fails when the content exceeds the bound.
    pub fn content_digest(&self) -> Result<String, String> {
        self.digest(false)
    }

    /// The digest of a version published from this content. A version that
    /// opts into `insecure_skip_tls_verify` (#284) is a different build
    /// input, so the opt-in joins the digest; without it the digest is
    /// exactly [`Self::content_digest`], so every version published before
    /// the opt-in existed keeps its identity.
    ///
    /// # Errors
    ///
    /// Fails when the content exceeds the bound.
    pub fn version_digest(&self, allow_insecure_tls: bool) -> Result<String, String> {
        self.digest(allow_insecure_tls)
    }

    fn digest(&self, allow_insecure_tls: bool) -> Result<String, String> {
        if self.content.len() > MAX_RECIPE_CONTENT_BYTES {
            return Err(format!(
                "the recipe content is {} bytes, over the {MAX_RECIPE_CONTENT_BYTES}-byte bound",
                self.content.len()
            ));
        }
        // The digest covers every build-affecting field: the Packer bytes
        // AND the Fleet metadata (node, pool, source), so a metadata-only
        // edit produces a new version instead of silently reusing one.
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.content.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.node.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.storage_pool.as_deref().unwrap_or_default().as_bytes());
        hasher.update(b"\n");
        hasher.update(self.source.id().as_bytes());
        if allow_insecure_tls {
            hasher.update(b"\nallow-insecure-tls");
        }
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(digest.iter().fold(String::with_capacity(64), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        }))
    }

    /// Validates the Fleet-owned metadata. Packer's own fields are the
    /// CLI's authority, not Fleet's.
    ///
    /// # Errors
    ///
    /// Fails on a malformed field.
    pub fn validate(&self) -> Result<(), String> {
        let count = self.name.chars().count();
        if count == 0 || count > 128 {
            return Err("the name must be 1..=128 characters".to_owned());
        }
        if self.description.chars().count() > 512 {
            return Err("the description must be at most 512 characters".to_owned());
        }
        for (label, value) in [
            ("node", &self.node),
            (
                "storage_pool",
                &self.storage_pool.clone().unwrap_or_default(),
            ),
        ] {
            let len = value.chars().count();
            if len == 0 || len > 128 {
                return Err(format!("the {label} must be 1..=128 characters"));
            }
        }
        if self.content.is_empty() {
            return Err("the recipe content must not be empty".to_owned());
        }
        // Fail-closed recipe structure (#313): a recipe is an untrusted,
        // privileged input and runs with the build's Proxmox token in
        // Packer's environment. Refuse the structures that escape the
        // provisioner allowlist and the template functions that read that
        // environment, at publish time, before the version is frozen.
        if let Some(reason) = recipe_build_refusal(&self.content) {
            return Err(recipe_refusal_message(reason).to_owned());
        }
        self.content_digest()?;
        Ok(())
    }
}

/// Whether a recipe's builders ask Packer's Proxmox plugin to skip TLS
/// verification (#284). Any `insecure_skip_tls_verify` value other than a
/// literal `false` counts, including a template variable: Fleet cannot know
/// what it resolves to. Keys match case-insensitively, as Packer's
/// `mapstructure` decoding does. Content that is not a JSON template is
/// judged by whether the key appears in it at all.
#[must_use]
pub fn requests_insecure_tls(content: &str) -> bool {
    const KEY: &str = "insecure_skip_tls_verify";
    let Ok(template) = serde_json::from_str::<serde_json::Value>(content) else {
        return content.to_ascii_lowercase().contains(KEY);
    };
    // Every case-insensitive `builders` key counts: which one a decoder
    // keeps is not Fleet's to guess.
    template.as_object().is_some_and(|object| {
        object
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("builders"))
            .filter_map(|(_, builders)| builders.as_array())
            .flatten()
            .filter_map(serde_json::Value::as_object)
            .any(|builder| {
                builder.iter().any(|(key, value)| {
                    key.eq_ignore_ascii_case(KEY) && *value != serde_json::Value::Bool(false)
                })
            })
    })
}

/// The legacy-JSON top-level keys a Fleet recipe may carry, in their exact
/// canonical spelling. Fail-closed, like the provisioner allowlist: any
/// other top-level key is refused (#313). That covers `post-processors` (a
/// `shell-local` post-processor runs on the controller with the build's
/// environment), `error-cleanup-provisioner` (a provisioner outside the
/// `has_external_assets` allowlist), Packer's `_`-prefixed root comments,
/// and every case variant: Packer matches root keys case-insensitively, so
/// `Provisioners` would be honored while exact-case checks elsewhere skip it.
const ALLOWED_TOP_LEVEL_KEYS: &[&str] = &[
    "builders",
    "provisioners",
    "variables",
    "sensitive-variables",
    "description",
    "min_packer_version",
];

/// Legacy-JSON template-engine functions that read the controller
/// environment, local files, or a remote secret store, and so can lift the
/// build's `PROXMOX_TOKEN` (or any other secret) into recipe-controlled
/// output (#313). Matched case-insensitively: Go's lookup is exact, so
/// this is only stricter.
///
/// `env` reads the child environment; `consul_key`, `vault`,
/// `aws_secretsmanager`, and `aws_secretsmanager_raw` reach remote secret
/// stores from the controller (and the AWS calls read `~/.aws`). Taken from
/// the `FuncGens` table in `packer-plugin-sdk`'s
/// `template/interpolate/funcs.go`. Packer enables them only in a
/// user-variable default, but a value lifted there flows anywhere through
/// `{{user}}`, so Fleet refuses the names anywhere. The other functions
/// (`user`, `timestamp`, `isotime`, `uuid`, string helpers, `build_name`,
/// `build_type`, `pwd`, `template_dir`, `packer_version`, ...) stay allowed.
const FORBIDDEN_TEMPLATE_FUNCS: &[&str] = &[
    "env",
    "consul_key",
    "vault",
    "aws_secretsmanager",
    "aws_secretsmanager_raw",
];

/// Builder keys that read files on the controller and ship them to the
/// guest or to PVE: `http_directory` serves a controller directory to the
/// guest over HTTP, `cd_files` packs controller files into an ISO that is
/// uploaded and attached. Matched case-insensitively, at any depth inside a
/// builder (so `additional_iso_files[]` counts too).
const CONTROLLER_FILE_KEYS: &[&str] =
    &["http_directory", "cd_files", "floppy_files", "floppy_dirs"];

/// Key prefixes that belong to Packer's communicator (#333): the `SSH`,
/// `WinRM`, and `SSHTemporaryKeyPair` structs of `packer-plugin-sdk`'s
/// `communicator/config.go` (v0.6.10, the version packer-plugin-proxmox
/// 1.2.4 pins). The Proxmox plugin has no key of its own with these
/// prefixes. Inside a builder, at any depth and in any ASCII case, a key
/// with one of them must be in [`ALLOWED_COMMUNICATOR_KEYS`]: an option
/// Fleet has not classified, including one a later SDK adds, is refused.
const COMMUNICATOR_KEY_PREFIXES: &[&str] = &["ssh_", "winrm_", "temporary_key_pair_"];

/// The communicator options that act only on the builder's own guest, with
/// the credential Packer generates or the recipe states. Everything else
/// under [`COMMUNICATOR_KEY_PREFIXES`] is refused, notably:
///
/// - controller files: `ssh_private_key_file`, `ssh_certificate_file`,
///   `ssh_bastion_private_key_file`, `ssh_bastion_certificate_file` (the
///   SDK expands `~` and reads them, even in `packer validate`);
/// - the controller's SSH agent: `ssh_agent_auth`, `ssh_bastion_agent_auth`;
/// - another host or route: `ssh_host`, `winrm_host`, every `ssh_bastion_*`
///   and `ssh_proxy_*` key, and `ssh_local_tunnels`/`ssh_remote_tunnels`
///   (a remote tunnel has the controller dial any address for the guest);
/// - undocumented SDK internals: `ssh_keypair_name`,
///   `temporary_key_pair_name`, `ssh_public_key`, `ssh_private_key`.
///
/// `ssh_disable_agent_forwarding` is allowed only as a literal `true`: the
/// SDK forwards `SSH_AUTH_SOCK` to the guest unless it is set, and the
/// build children get an empty `SSH_AUTH_SOCK` regardless.
const ALLOWED_COMMUNICATOR_KEYS: &[&str] = &[
    "ssh_port",
    "ssh_username",
    "ssh_password",
    "ssh_ciphers",
    "ssh_key_exchange_algorithms",
    "ssh_clear_authorized_keys",
    "ssh_pty",
    "ssh_timeout",
    "ssh_wait_timeout",
    "ssh_handshake_attempts",
    "ssh_file_transfer_method",
    "ssh_keep_alive_interval",
    "ssh_read_write_timeout",
    "ssh_disable_agent_forwarding",
    "temporary_key_pair_type",
    "temporary_key_pair_bits",
    "winrm_username",
    "winrm_password",
    "winrm_port",
    "winrm_timeout",
    "winrm_use_ssl",
    "winrm_insecure",
    "winrm_use_ntlm",
    "winrm_no_proxy",
];

/// The only ports the communicator may dial, per option (#337): the SDK's
/// own defaults (`prepareSSH` sets 22; `prepareWinRM` sets 5985, or 5986
/// with `winrm_use_ssl`). The Proxmox builder connects to whatever address
/// the build guest's QEMU agent reports, re-read on every connection
/// attempt, so the recipe chooses the host; pinning the port keeps that
/// connection to an SSH or `WinRM` service. A port must be a literal JSON
/// integer from this list: a string, template, `0`, or any other number is
/// refused, at any depth and in any ASCII case.
const ALLOWED_COMMUNICATOR_PORTS: &[(&str, &[u64])] =
    &[("ssh_port", &[22]), ("winrm_port", &[5985, 5986])];

/// Every stable reason [`recipe_build_refusal`] can return.
pub const RECIPE_REFUSAL_REASONS: &[&str] = &[
    "recipe_content_not_json_object",
    "recipe_duplicate_key",
    "recipe_non_ascii_key",
    "recipe_forbidden_top_level_key",
    "recipe_forbidden_template_function",
    "recipe_template_malformed",
    "recipe_templated_key",
    "recipe_packer_internal_key",
    "recipe_controller_file_input",
    "recipe_http_server_option",
    "recipe_communicator_forbidden_option",
    "recipe_communicator_port",
];

/// A stable, secret-free reason a recipe's structure is refused before any
/// credential is resolved, or `None` when the structure is acceptable.
///
/// Enforced at publish time (through [`RecipeContent::validate`], the only
/// path content enters a recipe) and again before every build, so a version
/// stored before this gate existed is refused with a stable code rather
/// than built. The check reads only the recipe bytes.
///
/// Fail-closed, in order:
/// - the content must be one JSON object (`recipe_content_not_json_object`);
/// - no object, at any depth, may repeat a key, exactly or up to ASCII case
///   (`recipe_duplicate_key`): `serde_json` keeps the last duplicate, while
///   Packer's case-insensitive decoder may keep another one;
/// - no key, at any depth, may contain non-ASCII characters
///   (`recipe_non_ascii_key`): Go's `EqualFold` folds e.g. `ſ` (U+017F) to
///   `s`, so `proviſioners` is a `provisioners` block to Packer;
/// - only the exact keys in [`ALLOWED_TOP_LEVEL_KEYS`] may appear at the top
///   level (`recipe_forbidden_top_level_key`);
/// - no decoded string — key or value, at any depth — may call a function in
///   [`FORBIDDEN_TEMPLATE_FUNCS`] (`recipe_forbidden_template_function`) or
///   carry a template action Fleet cannot lex the way Go's `text/template`
///   does (`recipe_template_malformed`). The scan runs after JSON decoding,
///   so `"{{env ..."` is caught;
/// - no builder may read controller files or fetch from the controller
///   (`recipe_controller_file_input`): see [`CONTROLLER_FILE_KEYS`]; an
///   `iso_url`/`iso_urls` needs `iso_download_pve: true` in the same block
///   and a literal `http(s)://` URL (so PVE downloads it, not go-getter on
///   the controller); an `iso_checksum` must be a literal hash or `none`
///   (a `file:` checksum is fetched on the controller, even by `validate`);
///   every `cd_content` key must be a relative path of plain segments
///   (`[A-Za-z0-9._-]+`, not `.` or `..`): Packer writes each entry under a
///   controller temp directory with `filepath.Join`;
/// - no key, at any depth, may contain a template action
///   (`recipe_templated_key`): Packer's interpolation renders map keys as
///   well as values, so `{{lower "SSH_HOST"}}` would become `ssh_host`
///   after every key check here;
/// - no builder may set a `packer_*` key (`recipe_packer_internal_key`):
///   those are Packer core's build settings, not the recipe's;
/// - the builder's HTTP server must listen on TCP (`http_network_protocol`
///   absent, `tcp`, or `tcp4`) at a literal IP, if `http_bind_address` is
///   set (`recipe_http_server_option`): a `unix` socket is a file at a
///   recipe-chosen controller path;
/// - no builder may set a communicator option that reads controller files,
///   uses the controller's SSH agent, or connects anywhere but the build
///   guest (`recipe_communicator_forbidden_option`): see
///   [`ALLOWED_COMMUNICATOR_KEYS`]. `communicator` must be absent or a
///   literal `none`, `ssh`, or `winrm`, and `winrm` needs a literal
///   `winrm_no_proxy: true` (otherwise the `WinRM` client goes through the controller's
///   HTTP proxy). Packer's temporary key, the default when no credential is
///   given, stays allowed;
/// - `ssh_port` and `winrm_port`, if set, must be literal integers from
///   [`ALLOWED_COMMUNICATOR_PORTS`] (`recipe_communicator_port`): the guest
///   chooses the address the communicator dials, so the port is the part
///   Fleet can pin.
#[must_use]
pub fn recipe_build_refusal(content: &str) -> Option<&'static str> {
    if let Err(reason) = audit_keys(content) {
        return Some(reason);
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return Some("recipe_content_not_json_object");
    };
    let serde_json::Value::Object(object) = &value else {
        return Some("recipe_content_not_json_object");
    };
    if object
        .keys()
        .any(|key| !ALLOWED_TOP_LEVEL_KEYS.contains(&key.as_str()))
    {
        return Some("recipe_forbidden_top_level_key");
    }
    match value_template_scan(&value) {
        TemplateScan::Clean => {}
        TemplateScan::Forbidden => return Some("recipe_forbidden_template_function"),
        TemplateScan::Malformed => return Some("recipe_template_malformed"),
    }
    let builders = object
        .get("builders")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if has_templated_key(&value) {
        return Some("recipe_templated_key");
    }
    if builders.iter().any(sets_packer_internal_key) {
        return Some("recipe_packer_internal_key");
    }
    if builders.iter().any(reads_controller_inputs) {
        return Some("recipe_controller_file_input");
    }
    if builders.iter().any(uses_forbidden_http_server_option) {
        return Some("recipe_http_server_option");
    }
    if builders
        .iter()
        .any(|builder| uses_forbidden_communicator_option(builder) || unsafe_communicator(builder))
    {
        return Some("recipe_communicator_forbidden_option");
    }
    if builders.iter().any(uses_forbidden_communicator_port) {
        return Some("recipe_communicator_port");
    }
    None
}

/// The operator-facing explanation of a [`recipe_build_refusal`] reason.
#[must_use]
pub fn recipe_refusal_message(reason: &str) -> &'static str {
    match reason {
        "recipe_duplicate_key" => {
            "the recipe repeats a key in one object (exactly or in another letter case); \
             Packer could act on a different copy than Fleet checks"
        }
        "recipe_non_ascii_key" => {
            "the recipe has a key with non-ASCII characters; Packer folds some of them \
             onto ASCII keys, so Fleet refuses them"
        }
        "recipe_forbidden_top_level_key" => {
            "the recipe has a top-level key Fleet does not allow; only builders, \
             provisioners, variables, sensitive-variables, description, and \
             min_packer_version are permitted, spelled exactly so (post-processors, \
             error-cleanup-provisioner, and `_` comments are refused)"
        }
        "recipe_forbidden_template_function" => {
            "the recipe uses a template function that reads the controller environment, \
             files, or a secret store (env, vault, consul_key, aws_secretsmanager, \
             aws_secretsmanager_raw), which could read the build's Proxmox token"
        }
        "recipe_template_malformed" => {
            "the recipe has a template action Fleet cannot check (an unclosed `{{`, \
             comment, or quoted string)"
        }
        "recipe_controller_file_input" => {
            "the recipe reads files on the controller (http_directory, cd_files), \
             fetches an ISO on the controller (iso_url without iso_download_pve, or a \
             non-http(s) URL), uses an iso_checksum that is not a literal md5, sha1, \
             sha256, or sha512 digest or none, or has a cd_content path that is not \
             relative plain segments ([A-Za-z0-9._-], no `.` or `..`)"
        }
        "recipe_packer_internal_key" => {
            "the recipe sets a packer_* key in a builder; those are Packer's own build \
             settings"
        }
        "recipe_http_server_option" => {
            "the recipe's HTTP server must listen on TCP: http_network_protocol may only \
             be tcp or tcp4, and http_bind_address must be a literal IP address"
        }
        "recipe_templated_key" => {
            "the recipe has a key containing a template action (`{{`); Packer renders \
             keys too, so Fleet could not tell which option the key becomes"
        }
        "recipe_communicator_forbidden_option" => {
            "the recipe sets a communicator option that reads files on the controller \
             (ssh_private_key_file, ssh_certificate_file, ...), uses the controller's SSH \
             agent (ssh_agent_auth, ...), or connects somewhere other than the build guest \
             (ssh_host, winrm_host, ssh_bastion_*, ssh_proxy_*, ssh tunnels), or a \
             communicator other than a literal none, ssh, or winrm (winrm needs \
             winrm_no_proxy: true); leave the credential out so Packer uses a temporary \
             key, and set ssh_disable_agent_forwarding only to true"
        }
        "recipe_communicator_port" => {
            "the recipe sets a communicator port other than the defaults: ssh_port may \
             only be the literal number 22, and winrm_port only 5985 or 5986 (leave them \
             out to use the defaults); the build guest chooses the address the controller \
             connects to, so Fleet fixes the port"
        }
        _ => "the recipe content must be a JSON object",
    }
}

/// Walks the raw JSON once, refusing duplicate (exact or ASCII-case) and
/// non-ASCII keys at any depth. Content that is not JSON at all is
/// reported as not being a JSON object.
fn audit_keys(content: &str) -> Result<(), &'static str> {
    const DUPLICATE: &str = "fleet-recipe-duplicate-key";
    const NON_ASCII: &str = "fleet-recipe-non-ascii-key";

    struct Audit;
    impl<'de> serde::de::Visitor<'de> for Audit {
        type Value = Audit;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("JSON")
        }
        fn visit_bool<E>(self, _: bool) -> Result<Audit, E> {
            Ok(Audit)
        }
        fn visit_i64<E>(self, _: i64) -> Result<Audit, E> {
            Ok(Audit)
        }
        fn visit_u64<E>(self, _: u64) -> Result<Audit, E> {
            Ok(Audit)
        }
        fn visit_f64<E>(self, _: f64) -> Result<Audit, E> {
            Ok(Audit)
        }
        fn visit_str<E>(self, _: &str) -> Result<Audit, E> {
            Ok(Audit)
        }
        fn visit_unit<E>(self) -> Result<Audit, E> {
            Ok(Audit)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Audit, A::Error> {
            while seq.next_element::<Audit>()?.is_some() {}
            Ok(Audit)
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Audit, A::Error> {
            use serde::de::Error as _;
            let mut seen = std::collections::HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !key.is_ascii() {
                    return Err(A::Error::custom(NON_ASCII));
                }
                if !seen.insert(key.to_ascii_lowercase()) {
                    return Err(A::Error::custom(DUPLICATE));
                }
                map.next_value::<Audit>()?;
            }
            Ok(Audit)
        }
    }
    impl<'de> Deserialize<'de> for Audit {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(Audit)
        }
    }

    let mut deserializer = serde_json::Deserializer::from_str(content);
    let audited = Audit::deserialize(&mut deserializer).and_then(|_| deserializer.end());
    match audited {
        Ok(()) => Ok(()),
        Err(error) if error.to_string().contains(DUPLICATE) => Err("recipe_duplicate_key"),
        Err(error) if error.to_string().contains(NON_ASCII) => Err("recipe_non_ascii_key"),
        Err(_) => Err("recipe_content_not_json_object"),
    }
}

/// Whether one builder block — at any depth, so `boot_iso` and
/// `additional_iso_files[]` count — reads controller files or makes the
/// controller fetch something.
fn reads_controller_inputs(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(items) => items.iter().any(reads_controller_inputs),
        serde_json::Value::Object(object) => {
            let field = |name: &str| {
                object
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value)
            };
            if object.keys().any(|key| {
                CONTROLLER_FILE_KEYS
                    .iter()
                    .any(|name| key.eq_ignore_ascii_case(name))
            }) {
                return true;
            }
            let urls: Vec<&serde_json::Value> = ["iso_url", "iso_urls"]
                .iter()
                .filter_map(|name| field(name))
                .flat_map(|value| match value {
                    serde_json::Value::Array(items) => items.iter().collect(),
                    other => vec![other],
                })
                .collect();
            if !urls.is_empty() {
                let pve_downloads =
                    field("iso_download_pve") == Some(&serde_json::Value::Bool(true));
                let literal_http = urls.iter().all(|url| {
                    url.as_str().is_some_and(|url| {
                        (url.starts_with("https://") || url.starts_with("http://"))
                            && !url.contains("{{")
                    })
                });
                if !pve_downloads || !literal_http {
                    return true;
                }
            }
            if field("iso_checksum")
                .is_some_and(|checksum| !checksum.as_str().is_some_and(literal_checksum))
            {
                return true;
            }
            // `step_create_cdrom` writes each entry to
            // `filepath.Join(<temp dir>, key)` on the controller, even when
            // no ISO tool is found afterwards.
            if let Some(content) = field("cd_content") {
                let Some(entries) = content.as_object() else {
                    return true;
                };
                if !entries.keys().all(|path| plain_relative_path(path)) {
                    return true;
                }
            }
            object.values().any(reads_controller_inputs)
        }
        _ => false,
    }
}

/// Whether any object key, at any depth, contains a template action.
fn has_templated_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(items) => items.iter().any(has_templated_key),
        serde_json::Value::Object(object) => object
            .iter()
            .any(|(key, child)| key.contains("{{") || has_templated_key(child)),
        _ => false,
    }
}

/// Whether one builder block, at any depth, sets a communicator option
/// outside [`ALLOWED_COMMUNICATOR_KEYS`], or `ssh_disable_agent_forwarding`
/// to anything but a literal `true`. Keys match in any ASCII case, as
/// `mapstructure` matches them.
fn uses_forbidden_communicator_option(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(items) => items.iter().any(uses_forbidden_communicator_option),
        serde_json::Value::Object(object) => object.iter().any(|(key, child)| {
            let key = key.to_ascii_lowercase();
            let communicator = COMMUNICATOR_KEY_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix));
            if communicator && !ALLOWED_COMMUNICATOR_KEYS.contains(&key.as_str()) {
                return true;
            }
            if key == "ssh_disable_agent_forwarding" && *child != serde_json::Value::Bool(true) {
                return true;
            }
            uses_forbidden_communicator_option(child)
        }),
        _ => false,
    }
}

/// Whether a builder, at any depth and in any ASCII case, sets `ssh_port` or
/// `winrm_port` to anything but a literal integer in
/// [`ALLOWED_COMMUNICATOR_PORTS`].
fn uses_forbidden_communicator_port(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(items) => items.iter().any(uses_forbidden_communicator_port),
        serde_json::Value::Object(object) => object.iter().any(|(key, child)| {
            let forbidden = ALLOWED_COMMUNICATOR_PORTS
                .iter()
                .find(|(name, _)| key.eq_ignore_ascii_case(name))
                .is_some_and(|(_, ports)| child.as_u64().is_none_or(|port| !ports.contains(&port)));
            forbidden || uses_forbidden_communicator_port(child)
        }),
        _ => false,
    }
}

/// `none`, a bare hex digest of an md5/sha1/sha256/sha512 length, or
/// `<md5|sha1|sha256|sha512>:<hex digest of that length>`: the forms that
/// Packer checks locally without fetching anything (`file:` and any other
/// go-getter checksum type are refused).
fn literal_checksum(value: &str) -> bool {
    if value == "none" {
        return true;
    }
    let (expected, digest): (&[usize], &str) = match value.split_once(':') {
        None => (&[32, 40, 64, 128], value),
        Some((algorithm, digest)) => match algorithm.to_ascii_lowercase().as_str() {
            "md5" => (&[32], digest),
            "sha1" => (&[40], digest),
            "sha256" => (&[64], digest),
            "sha512" => (&[128], digest),
            _ => return false,
        },
    };
    expected.contains(&digest.len()) && digest.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A relative path of plain segments: each one `[A-Za-z0-9._-]+` and not
/// `.` or `..`, separated by single `/`. So no absolute path, no `\`, no
/// empty segment, and nothing that climbs out of the directory it is
/// joined to.
fn plain_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

/// Whether a builder, at any depth, sets a `packer_*` key (any case).
fn sets_packer_internal_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(items) => items.iter().any(sets_packer_internal_key),
        serde_json::Value::Object(object) => object.iter().any(|(key, child)| {
            key.to_ascii_lowercase().starts_with("packer_") || sets_packer_internal_key(child)
        }),
        _ => false,
    }
}

/// Whether a builder, at any depth, has its HTTP server listen anywhere but
/// a TCP port: `http_network_protocol` must be a literal `tcp` or `tcp4`
/// (`unix`/`unixpacket` create a socket file at the recipe's path; `tcp6`
/// is refused for simplicity), and `http_bind_address` a literal IP.
fn uses_forbidden_http_server_option(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(items) => items.iter().any(uses_forbidden_http_server_option),
        serde_json::Value::Object(object) => object.iter().any(|(key, child)| {
            if key.eq_ignore_ascii_case("http_network_protocol")
                && !matches!(child.as_str(), Some("tcp" | "tcp4"))
            {
                return true;
            }
            if key.eq_ignore_ascii_case("http_bind_address")
                && child
                    .as_str()
                    .is_none_or(|address| address.parse::<std::net::IpAddr>().is_err())
            {
                return true;
            }
            uses_forbidden_http_server_option(child)
        }),
        _ => false,
    }
}

/// Whether a builder's `communicator` is anything but absent or a literal
/// `none`, `ssh`, or `winrm`, or is `winrm` without a literal
/// `winrm_no_proxy: true`: without it, the SDK's `WinRM` client goes through
/// the controller's `HTTP(S)_PROXY`.
fn unsafe_communicator(builder: &serde_json::Value) -> bool {
    let Some(object) = builder.as_object() else {
        return false;
    };
    let field = |name: &str| {
        object
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    };
    match field("communicator").map(serde_json::Value::as_str) {
        None | Some(Some("none" | "ssh")) => false,
        Some(Some("winrm")) => field("winrm_no_proxy") != Some(&serde_json::Value::Bool(true)),
        Some(_) => true,
    }
}

/// What scanning the template actions in a string found.
#[derive(Debug, PartialEq, Eq)]
enum TemplateScan {
    Clean,
    Forbidden,
    Malformed,
}

/// Scans every decoded string in the JSON value — object key, object value,
/// or array element, recursively. The worst finding wins.
fn value_template_scan(value: &serde_json::Value) -> TemplateScan {
    let mut worst = TemplateScan::Clean;
    let mut note = |scan: TemplateScan| {
        if scan != TemplateScan::Clean && worst != TemplateScan::Forbidden {
            worst = scan;
        }
    };
    match value {
        serde_json::Value::String(text) => note(template_scan(text)),
        serde_json::Value::Array(items) => items
            .iter()
            .for_each(|item| note(value_template_scan(item))),
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                note(template_scan(key));
                note(value_template_scan(child));
            }
        }
        _ => {}
    }
    worst
}

/// Scans one decoded string for template actions the way Go's
/// `text/template` lexer reads them, with the default `{{`/`}}`
/// delimiters Packer uses:
///
/// - text outside actions is inert; an action starts at `{{`, optionally
///   followed by a `-` trim marker and whitespace;
/// - `{{/* ... */}}` is a comment (also with trim markers); one that never
///   closes, or is not followed by `}}`, is malformed;
/// - inside an action, `"..."` (backslash escapes, no newline), `'...'`
///   (a rune literal, backslash escapes, no newline), and `` `...` `` (raw,
///   newlines allowed) are literals; an unterminated one is malformed, so no
///   quote can swallow the rest of an action;
/// - an action that reaches the end of the string without `}}` is
///   malformed;
/// - every other run of ASCII letters, digits, and `_` is a word, and a word
///   equal to a forbidden function name is a forbidden call. Go identifiers
///   may also hold non-ASCII letters, so splitting on ASCII is stricter than
///   Go: a Go identifier `env` is always bounded by non-ASCII-word chars.
fn template_scan(text: &str) -> TemplateScan {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let at = |i: usize, s: &str| {
        s.chars()
            .enumerate()
            .all(|(k, c)| chars.get(i + k) == Some(&c))
    };
    let mut i = 0;
    while i < len {
        if !at(i, "{{") {
            i += 1;
            continue;
        }
        i += 2;
        if chars.get(i) == Some(&'-') && chars.get(i + 1).is_some_and(char::is_ascii_whitespace) {
            i += 2;
            while chars.get(i).is_some_and(char::is_ascii_whitespace) {
                i += 1;
            }
        }
        if at(i, "/*") {
            let Some(end) = (i + 2..len).find(|&j| at(j, "*/")) else {
                return TemplateScan::Malformed;
            };
            i = end + 2;
            if chars.get(i).is_some_and(char::is_ascii_whitespace) && chars.get(i + 1) == Some(&'-')
            {
                i += 2;
            }
            if !at(i, "}}") {
                return TemplateScan::Malformed;
            }
            i += 2;
            continue;
        }
        let mut word = String::new();
        let forbidden = |word: &str| {
            FORBIDDEN_TEMPLATE_FUNCS
                .iter()
                .any(|func| word.eq_ignore_ascii_case(func))
        };
        loop {
            let Some(&c) = chars.get(i) else {
                return TemplateScan::Malformed;
            };
            if c.is_ascii_alphanumeric() || c == '_' {
                word.push(c);
                i += 1;
                continue;
            }
            if forbidden(&word) {
                return TemplateScan::Forbidden;
            }
            word.clear();
            if at(i, "}}") {
                i += 2;
                break;
            }
            match c {
                '"' | '\'' => {
                    i += 1;
                    loop {
                        match chars.get(i) {
                            None | Some('\n') => return TemplateScan::Malformed,
                            Some('\\') => {
                                if matches!(chars.get(i + 1), None | Some('\n')) {
                                    return TemplateScan::Malformed;
                                }
                                i += 2;
                            }
                            Some(&q) if q == c => {
                                i += 1;
                                break;
                            }
                            Some(_) => i += 1,
                        }
                    }
                }
                '`' => {
                    let Some(end) = (i + 1..len).find(|&j| chars[j] == '`') else {
                        return TemplateScan::Malformed;
                    };
                    i = end + 1;
                }
                _ => i += 1,
            }
        }
    }
    TemplateScan::Clean
}

/// A published recipe version: immutable, identified by its digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeVersion {
    /// The version's identity: the recipe it came from plus the content
    /// digest, so the same content published twice is the same version.
    pub id: String,
    /// The recipe the version came from.
    pub recipe_id: String,
    /// The recipe name at publication time.
    pub name: String,
    /// The frozen content digest.
    pub content_digest: String,
    /// The frozen description.
    pub description: String,
    /// The frozen content.
    pub content: String,
    /// The source at publication time.
    pub source: RecipeSource,
    /// The node at publication time.
    pub node: String,
    /// The storage pool at publication time.
    pub storage_pool: String,
    /// When the version was published (epoch millis).
    pub published_at: i64,
    /// When the version was promoted (epoch millis), when any. At most
    /// one version per recipe is promoted; the latest promotion demotes
    /// the previous one explicitly.
    pub promoted_at: Option<i64>,
    /// Who promoted the version.
    pub promoted_by: Option<String>,
    /// The build record the version's latest promotion pinned: Lab clones
    /// this build's template, and a later rebuild never changes it (issue
    /// #281). Kept after a demotion so earlier leases keep their source.
    /// `None` when the version was never promoted, or was promoted before
    /// the pin existed and not since.
    pub promoted_build_id: Option<String>,
    /// Whether the version may build with `insecure_skip_tls_verify` (#284).
    /// Set only by an explicit, audited opt-in at publication and part of
    /// the version digest. Without it, a build of a recipe that skips TLS
    /// verification is refused (`insecure_tls_not_allowed`); every other
    /// build pins the account's confirmed certificate for Packer.
    #[serde(default)]
    pub allow_insecure_tls: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe(content: &str) -> RecipeContent {
        RecipeContent {
            name: "ubuntu-base".to_owned(),
            description: "the base image".to_owned(),
            node: "pve".to_owned(),
            storage_pool: Some("local-lvm".to_owned()),
            source: RecipeSource::Iso,
            content: content.to_owned(),
        }
    }

    #[test]
    fn digests_are_stable_and_content_sensitive() {
        let a = recipe("{\"builders\":[]}");
        let b = recipe("{\"builders\":[]}");
        let c = recipe("{\"builders\":[{}]}");
        assert_eq!(a.content_digest().unwrap(), b.content_digest().unwrap());
        assert_ne!(a.content_digest().unwrap(), c.content_digest().unwrap());
    }

    #[test]
    fn the_insecure_tls_opt_in_is_part_of_the_version_digest_only_when_set() {
        let a = recipe("{\"builders\":[]}");
        assert_eq!(
            a.version_digest(false).unwrap(),
            a.content_digest().unwrap()
        );
        assert_ne!(a.version_digest(true).unwrap(), a.content_digest().unwrap());
    }

    #[test]
    fn insecure_tls_requests_are_recognized_in_every_spelling() {
        for content in [
            r#"{"builders":[{"type":"proxmox-clone","insecure_skip_tls_verify":true}]}"#,
            r#"{"builders":[{"type":"proxmox-clone","insecure_skip_tls_verify":"true"}]}"#,
            r#"{"builders":[{"type":"proxmox-clone","insecure_skip_tls_verify":"{{user `skip`}}"}]}"#,
            r#"{"builders":[{"type":"proxmox-clone"},{"INSECURE_SKIP_TLS_VERIFY":1}]}"#,
            r#"{"Builders":[{"Insecure_Skip_Tls_Verify":true}]}"#,
            r#"{"Builders":[{"type":"proxmox-clone"}],"builders":[{"insecure_skip_tls_verify":true}]}"#,
            r#"{"builders":[{"type":"proxmox-clone"}],"BUILDERS":[{"insecure_skip_tls_verify":true}]}"#,
            "source \"proxmox-clone\" \"x\" { insecure_skip_tls_verify = true }",
        ] {
            assert!(requests_insecure_tls(content), "{content}");
        }
        for content in [
            r#"{"builders":[{"type":"proxmox-clone"}]}"#,
            r#"{"builders":[{"type":"proxmox-clone","insecure_skip_tls_verify":false}]}"#,
            r#"{"variables":{"insecure_skip_tls_verify":"true"},"builders":[{}]}"#,
            "not json",
        ] {
            assert!(!requests_insecure_tls(content), "{content}");
        }
    }

    #[test]
    fn the_env_template_function_is_refused_in_every_spelling() {
        // Direct, spaced, trim-marker, and pipeline forms, in a variable
        // default, through `{{user}}` indirection, and in nested strings.
        for content in [
            r#"{"variables":{"t":"{{env `PROXMOX_TOKEN`}}"}}"#,
            r#"{"variables":{"t":"{{ env `PROXMOX_TOKEN` }}"}}"#,
            r#"{"variables":{"t":"{{-env `PROXMOX_TOKEN`}}"}}"#,
            r#"{"variables":{"t":"{{- env `PROXMOX_TOKEN` -}}"}}"#,
            r#"{"variables":{"t":"{{ `PROXMOX_TOKEN` | env }}"}}"#,
            r#"{"variables":{"t":"{{ENV `PROXMOX_TOKEN`}}"}}"#,
            r#"{"builders":[{"type":"proxmox-clone","vm_name":"{{env `PROXMOX_TOKEN`}}"}]}"#,
            r#"{"provisioners":[{"type":"shell","inline":["echo {{env `PROXMOX_TOKEN`}}"]}]}"#,
            r#"{"provisioners":[{"type":"shell","environment_vars":["T={{env `PROXMOX_TOKEN`}}"],"inline":["true"]}]}"#,
            // JSON `\u` escapes decode to `{{env `PROXMOX_TOKEN`}}` before
            // Packer's engine sees the string: scanning decoded strings
            // (not raw bytes) catches it.
            r#"{"variables":{"t":"{{env `PROXMOX_TOKEN`}}"}}"#,
            // A forbidden call hidden in an object key, not a value.
            r#"{"variables":{"{{env `PROXMOX_TOKEN`}}":"x"}}"#,
        ] {
            assert_eq!(
                recipe_build_refusal(content),
                Some("recipe_forbidden_template_function"),
                "{content}"
            );
        }
    }

    #[test]
    fn other_secret_reading_template_functions_are_refused() {
        for content in [
            r#"{"variables":{"t":"{{vault `/secret/x` `k`}}"}}"#,
            r#"{"variables":{"t":"{{ consul_key `k` }}"}}"#,
            r#"{"variables":{"t":"{{aws_secretsmanager `name`}}"}}"#,
            r#"{"variables":{"t":"{{aws_secretsmanager_raw `name`}}"}}"#,
        ] {
            assert_eq!(
                recipe_build_refusal(content),
                Some("recipe_forbidden_template_function"),
                "{content}"
            );
        }
    }

    #[test]
    fn forbidden_top_level_keys_and_non_objects_are_refused() {
        assert_eq!(
            recipe_build_refusal(
                r#"{"builders":[],"post-processors":[{"type":"shell-local","inline":["true"]}]}"#
            ),
            Some("recipe_forbidden_top_level_key"),
        );
        assert_eq!(
            recipe_build_refusal(
                r#"{"builders":[],"error-cleanup-provisioner":{"type":"shell-local","inline":["true"]}}"#
            ),
            Some("recipe_forbidden_top_level_key"),
        );
        assert_eq!(
            recipe_build_refusal(r#"{"builders":[],"POST-PROCESSORS":[]}"#),
            Some("recipe_forbidden_top_level_key"),
        );
        assert_eq!(
            recipe_build_refusal(r#"{"builders":[],"secret_exfil":true}"#),
            Some("recipe_forbidden_top_level_key"),
        );
        for non_object in ["not json", "[]", "\"a string\"", "42"] {
            assert_eq!(
                recipe_build_refusal(non_object),
                Some("recipe_content_not_json_object"),
                "{non_object}"
            );
        }
    }

    #[test]
    fn benign_recipes_and_user_variables_named_like_functions_pass() {
        for content in [
            "{}",
            r#"{"builders":[{"type":"proxmox-clone","vm_name":"{{user `name`}}"}]}"#,
            r#"{"variables":{"env":"prod"},"builders":[{"type":"proxmox-clone","notes":"{{user `env`}}"}]}"#,
            r#"{"builders":[],"provisioners":[{"type":"shell","inline":["env"]}]}"#,
            r#"{"description":"d","min_packer_version":"1.15.0","sensitive-variables":["t"],"variables":{"t":""},"builders":[]}"#,
            r#"{"builders":[{"type":"proxmox-clone","template_name":"img-{{timestamp}}","vm_id":901}]}"#,
        ] {
            assert_eq!(recipe_build_refusal(content), None, "{content}");
        }
    }

    #[test]
    fn duplicate_keys_are_refused_at_any_depth_and_in_any_case() {
        // serde keeps the last duplicate; Packer's case-insensitive decoder
        // may honor another copy, so any repeat is ambiguous.
        for content in [
            r#"{"builders":[],"builders":[]}"#,
            r#"{"builders":[],"provisioners":[],"Provisioners":[]}"#,
            r#"{"builders":[{"type":"proxmox-clone","vm_name":"a","VM_NAME":"b"}]}"#,
            r#"{"builders":[],"variables":{"t":"a","t":"b"}}"#,
            r#"{"builders":[],"provisioners":[{"type":"shell","inline":["true"],"Type":"shell"}]}"#,
        ] {
            assert_eq!(
                recipe_build_refusal(content),
                Some("recipe_duplicate_key"),
                "{content}"
            );
        }
    }

    #[test]
    fn top_level_keys_must_use_their_canonical_spelling() {
        // Packer 1.16.1 honors `Provisioners` as a provisioners block, while
        // the executor's provisioner allowlist reads only `provisioners`.
        for content in [
            r#"{"builders":[],"Provisioners":[{"type":"shell-local","inline":["true"]}]}"#,
            r#"{"BUILDERS":[]}"#,
            r#"{"builders":[],"Variables":{}}"#,
        ] {
            assert_eq!(
                recipe_build_refusal(content),
                Some("recipe_forbidden_top_level_key"),
                "{content}"
            );
        }
    }

    #[test]
    fn non_ascii_keys_are_refused_at_any_depth() {
        // Go's EqualFold folds U+017F (long s) to `s` and U+212A (Kelvin) to
        // `k`: Packer 1.16.1 honors `provi\u{17f}ioners` as `provisioners`.
        // The fixtures spell the keys with JSON `\u` escapes, which decode to
        // the non-ASCII characters before the check.
        for content in [
            r#"{"builders":[],"provi\u017fioners":[]}"#,
            r#"{"builders":[],"post-proce\u017f\u017fors":[]}"#,
            r#"{"builders":[{"type":"proxmox-clone","\u212aey":"x"}]}"#,
            r#"{"builders":[],"variables":{"caf\u00e9":"x"}}"#,
        ] {
            assert_eq!(
                recipe_build_refusal(content),
                Some("recipe_non_ascii_key"),
                "{content}"
            );
        }
        // Non-ASCII values are fine.
        assert_eq!(
            recipe_build_refusal(r#"{"description":"caf\u00e9","builders":[]}"#),
            None
        );
    }

    #[test]
    fn the_template_lexer_follows_text_template_quoting() {
        let scan = |text: &str| {
            recipe_build_refusal(&serde_json::json!({ "variables": { "v": text } }).to_string())
        };
        let forbidden = Some("recipe_forbidden_template_function");
        let malformed = Some("recipe_template_malformed");
        // A `}}` inside a string literal does not close the action (Packer
        // 1.16.1 accepts `{{ printf "%s}}" "a" }}`), so a call after it is
        // still inside the action.
        assert_eq!(scan(r#"{{ printf "%s}}" (env `T`) }}"#), forbidden);
        assert_eq!(scan(r#"{{ "a\"b" | printf "%s" }}{{env `T`}}"#), forbidden);
        assert_eq!(scan(r"{{ printf `%c` 'a' }}{{ env `T` }}"), forbidden);
        assert_eq!(scan(r"{{ printf `%c` '\'' }}{{ env `T` }}"), forbidden);
        // An unterminated literal or action cannot hide what follows: Packer
        // refuses all of these, and so does Fleet.
        for text in [
            "{{ printf `%s` 'ab }} {{env `T`}}",
            "{{ 'x}}",
            "{{ \"open }}",
            "{{ \"a\nb\" }}",
            "{{ `raw",
            "{{ timestamp",
            "{{/* note }}",
            "{{/* note */ x}}",
        ] {
            assert_eq!(scan(text), malformed, "{text:?}");
        }
        // Comments, trim markers, and plain text pass.
        for text in [
            "{{/* env */}}",
            "{{- /* note */ -}}",
            "{{- timestamp -}}",
            "{{ printf \"%s}}\" \"a\" }}",
            "plain }} text",
            "{{user `env`}}",
        ] {
            assert_eq!(scan(text), None, "{text:?}");
        }
    }

    #[test]
    fn builders_may_not_read_or_fetch_controller_inputs() {
        let builder = |extra: serde_json::Value| {
            let mut block = serde_json::json!({ "type": "proxmox-iso" });
            for (key, value) in extra.as_object().unwrap() {
                block[key] = value.clone();
            }
            recipe_build_refusal(&serde_json::json!({ "builders": [block] }).to_string())
        };
        let refused = Some("recipe_controller_file_input");
        for extra in [
            serde_json::json!({ "http_directory": "." }),
            serde_json::json!({ "HTTP_Directory": "." }),
            serde_json::json!({ "additional_iso_files": [{ "cd_files": ["./x"] }] }),
            serde_json::json!({ "boot_iso": { "iso_url": "https://example.test/x.iso" } }),
            serde_json::json!({ "boot_iso": { "iso_url": "./x.iso", "iso_download_pve": true } }),
            serde_json::json!({ "boot_iso": { "iso_url": "file:///x.iso", "iso_download_pve": true } }),
            serde_json::json!({ "boot_iso": { "iso_urls": ["https://example.test/x.iso", "git::x"], "iso_download_pve": true } }),
            serde_json::json!({ "boot_iso": { "iso_url": "https://example.test/x.iso", "iso_download_pve": "true" } }),
            serde_json::json!({ "iso_url": "https://example.test/{{user `p`}}", "iso_download_pve": true }),
            serde_json::json!({ "boot_iso": { "iso_file": "local:iso/x.iso", "iso_checksum": "file:./sums" } }),
            serde_json::json!({ "boot_iso": { "iso_file": "local:iso/x.iso", "iso_checksum": "https://example.test/sums" } }),
            serde_json::json!({ "boot_iso": { "iso_file": "local:iso/x.iso", "iso_checksum": "{{user `c`}}" } }),
        ] {
            assert_eq!(builder(extra.clone()), refused, "{extra}");
        }
        for extra in [
            serde_json::json!({ "boot_iso": { "iso_file": "local:iso/x.iso" } }),
            serde_json::json!({ "boot_iso": { "iso_url": "https://example.test/x.iso", "iso_download_pve": true, "iso_checksum": "sha256:000000000000000000000000000000000000000000000000000000000000abcd" } }),
            serde_json::json!({ "boot_iso": { "iso_file": "local:iso/x.iso", "iso_checksum": "none" } }),
            serde_json::json!({ "http_content": { "/user-data": "#cloud-config" } }),
        ] {
            assert_eq!(builder(extra.clone()), None, "{extra}");
        }
    }

    /// One `proxmox-clone` builder with the SSH communicator plus `extra`.
    fn ssh_builder(extra: &serde_json::Value) -> Option<&'static str> {
        let mut block = serde_json::json!({
            "type": "proxmox-clone",
            "communicator": "ssh",
            "ssh_username": "debian",
        });
        for (key, value) in extra.as_object().unwrap() {
            block[key] = value.clone();
        }
        recipe_build_refusal(&serde_json::json!({ "builders": [block] }).to_string())
    }

    #[test]
    fn communicator_options_that_reach_the_controller_are_refused() {
        let refused = Some("recipe_communicator_forbidden_option");
        // packer-plugin-sdk v0.6.10 `communicator/config.go`: every option
        // that reads a controller file, uses the controller's agent, picks
        // another host or route, or is an undocumented internal.
        let options: &[(&str, serde_json::Value)] = &[
            ("ssh_private_key_file", "~/.ssh/id_ed25519".into()),
            ("ssh_certificate_file", "/etc/ssh/cert.pub".into()),
            ("ssh_bastion_private_key_file", "~/.ssh/id_rsa".into()),
            ("ssh_bastion_certificate_file", "/x".into()),
            ("ssh_agent_auth", true.into()),
            ("ssh_bastion_agent_auth", true.into()),
            ("ssh_host", "192.0.2.1".into()),
            ("ssh_bastion_host", "192.0.2.1".into()),
            ("ssh_bastion_port", 22.into()),
            ("ssh_bastion_username", "u".into()),
            ("ssh_bastion_password", "p".into()),
            ("ssh_bastion_interactive", true.into()),
            ("ssh_proxy_host", "192.0.2.1".into()),
            ("ssh_proxy_port", 1080.into()),
            ("ssh_proxy_username", "u".into()),
            ("ssh_proxy_password", "p".into()),
            (
                "ssh_local_tunnels",
                serde_json::json!(["8080:localhost:80"]),
            ),
            (
                "ssh_remote_tunnels",
                serde_json::json!(["9090:localhost:80"]),
            ),
            ("ssh_keypair_name", "k".into()),
            ("temporary_key_pair_name", "k".into()),
            ("ssh_public_key", "ssh-ed25519 AAAA".into()),
            ("ssh_private_key", "x".into()),
            ("winrm_host", "192.0.2.1".into()),
            // Unknown keys under a communicator prefix fail closed.
            ("ssh_interface", "public_ip".into()),
            ("ssh_forward_agent", true.into()),
            ("winrm_cert_file", "/x".into()),
            ("temporary_key_pair_path", "/x".into()),
        ];
        for (key, value) in options {
            for spelling in [(*key).to_owned(), key.to_ascii_uppercase(), {
                let mut mixed = (*key).to_owned();
                mixed.replace_range(..1, &key[..1].to_ascii_uppercase());
                mixed
            }] {
                let extra = serde_json::json!({ spelling.clone(): value });
                assert_eq!(ssh_builder(&extra), refused, "{extra}");
                // Nested inside the builder counts too, as for file inputs.
                let nested = serde_json::json!({ "additional_iso_files": [{ spelling: value }] });
                assert_eq!(ssh_builder(&nested), refused, "{nested}");
            }
            // A repeated key, exactly or in another case, stays a duplicate.
            let content = format!(
                r#"{{"builders":[{{"type":"proxmox-clone","{key}":1,"{}":1}}]}}"#,
                key.to_ascii_uppercase()
            );
            assert_eq!(
                recipe_build_refusal(&content),
                Some("recipe_duplicate_key"),
                "{content}"
            );
        }
    }

    #[test]
    fn agent_forwarding_may_only_be_disabled() {
        let refused = Some("recipe_communicator_forbidden_option");
        assert_eq!(
            ssh_builder(&serde_json::json!({ "ssh_disable_agent_forwarding": true })),
            None
        );
        assert_eq!(
            ssh_builder(&serde_json::json!({ "SSH_Disable_Agent_Forwarding": true })),
            None
        );
        for value in [
            serde_json::json!(false),
            serde_json::json!("true"),
            serde_json::json!("{{user `f`}}"),
            serde_json::json!(null),
        ] {
            let extra = serde_json::json!({ "ssh_disable_agent_forwarding": value });
            assert_eq!(ssh_builder(&extra), refused, "{extra}");
        }
    }

    #[test]
    fn guest_only_communicator_options_pass() {
        let extra = serde_json::json!({
            "communicator": "ssh",
            "pause_before_connecting": "5s",
            "ssh_port": 22,
            "SSH_Password": "{{user `guest_password`}}",
            "ssh_ciphers": ["aes128-ctr"],
            "ssh_key_exchange_algorithms": ["curve25519-sha256@libssh.org"],
            "ssh_clear_authorized_keys": true,
            "ssh_pty": true,
            "ssh_timeout": "15m",
            "ssh_wait_timeout": "15m",
            "ssh_handshake_attempts": 10,
            "ssh_file_transfer_method": "sftp",
            "ssh_keep_alive_interval": "5s",
            "ssh_read_write_timeout": "5m",
            "temporary_key_pair_type": "ed25519",
            "temporary_key_pair_bits": 256,
        });
        assert_eq!(ssh_builder(&extra), None);
        let winrm = serde_json::json!({
            "builders": [{
                "type": "proxmox-iso",
                "communicator": "winrm",
                "winrm_username": "Administrator",
                "winrm_password": "{{user `p`}}",
                "winrm_port": 5986,
                "winrm_timeout": "30m",
                "winrm_use_ssl": true,
                "winrm_insecure": true,
                "winrm_use_ntlm": true,
                "winrm_no_proxy": true,
            }]
        });
        assert_eq!(recipe_build_refusal(&winrm.to_string()), None);
    }

    #[test]
    fn communicator_ports_are_pinned_to_the_sdk_defaults() {
        // #337: the guest chooses the address, so the port is pinned.
        let refused = Some("recipe_communicator_port");
        let winrm = |extra: &serde_json::Value| {
            let mut block = serde_json::json!({
                "type": "proxmox-iso",
                "communicator": "winrm",
                "winrm_username": "Administrator",
                "winrm_no_proxy": true,
            });
            for (key, value) in extra.as_object().unwrap() {
                block[key] = value.clone();
            }
            recipe_build_refusal(&serde_json::json!({ "builders": [block] }).to_string())
        };
        // Absent ports use the SDK defaults.
        assert_eq!(ssh_builder(&serde_json::json!({})), None);
        assert_eq!(winrm(&serde_json::json!({})), None);
        for spelling in ["ssh_port", "SSH_PORT", "Ssh_Port"] {
            assert_eq!(ssh_builder(&serde_json::json!({ spelling: 22 })), None);
        }
        for port in [5985, 5986] {
            for spelling in ["winrm_port", "WINRM_PORT"] {
                assert_eq!(winrm(&serde_json::json!({ spelling: port })), None);
            }
        }
        let bad: &[serde_json::Value] = &[
            serde_json::json!(0),
            serde_json::json!(2222),
            serde_json::json!(5985),
            serde_json::json!(5986),
            serde_json::json!(6379),
            serde_json::json!(-22),
            serde_json::json!(22.0),
            serde_json::json!(22.5),
            serde_json::json!(65_558),
            serde_json::json!("22"),
            serde_json::json!("{{user `port`}}"),
            serde_json::json!(null),
            serde_json::json!(true),
            serde_json::json!([22]),
        ];
        for value in bad {
            for spelling in ["ssh_port", "SSH_Port"] {
                let extra = serde_json::json!({ spelling: value });
                assert_eq!(ssh_builder(&extra), refused, "{extra}");
                let nested = serde_json::json!({ "additional_iso_files": [{ spelling: value }] });
                assert_eq!(ssh_builder(&nested), refused, "{nested}");
            }
        }
        for value in bad
            .iter()
            .filter(|value| !matches!(value.as_u64(), Some(5985 | 5986)))
            .chain([&serde_json::json!(22)])
        {
            for spelling in ["winrm_port", "WinRM_Port"] {
                let extra = serde_json::json!({ spelling: value });
                assert_eq!(winrm(&extra), refused, "{extra}");
                let nested = serde_json::json!({ "additional_iso_files": [{ spelling: value }] });
                assert_eq!(winrm(&nested), refused, "{nested}");
            }
        }
        // Raw JSON that is numerically 22 or overflows u64 parses as a
        // float, so it is refused rather than read as 22 or truncated.
        for raw in ["2.2e1", "22e0", "18446744073709551638", "220e-1"] {
            let content =
                format!(r#"{{"builders":[{{"type":"proxmox-clone","ssh_port":{raw}}}]}}"#);
            assert_eq!(recipe_build_refusal(&content), refused, "{content}");
        }
        // `communicator: none` never dials, but a stray port is still
        // refused rather than special-cased.
        let none = serde_json::json!({
            "builders": [{ "type": "proxmox-clone", "communicator": "none", "ssh_port": 2222 }]
        });
        assert_eq!(recipe_build_refusal(&none.to_string()), refused);
        // A forbidden option still wins over a port refusal.
        assert_eq!(
            ssh_builder(&serde_json::json!({ "ssh_host": "192.0.2.1", "ssh_port": 2222 })),
            Some("recipe_communicator_forbidden_option")
        );
        // The publish-time path applies the same gate.
        let mut published = recipe(
            &serde_json::json!({ "builders": [{ "type": "proxmox-clone", "ssh_port": 2222 }] })
                .to_string(),
        );
        assert!(published.validate().is_err());
        published.content =
            serde_json::json!({ "builders": [{ "type": "proxmox-clone", "ssh_port": 22 }] })
                .to_string();
        assert!(published.validate().is_ok());
    }

    #[test]
    fn templated_keys_are_refused_at_any_depth() {
        // Packer renders map keys, so a templated key could become any
        // option after Fleet's key checks.
        for content in [
            r#"{"builders":[{"type":"proxmox-clone","{{lower `SSH_HOST`}}":"192.0.2.1"}]}"#,
            r#"{"builders":[{"type":"proxmox-clone","{{user `k`}}":"."}]}"#,
            r#"{"builders":[{"type":"proxmox-clone","x\u007b\u007b `ssh_host` }}":"."}]}"#,
            r#"{"builders":[{"type":"proxmox-clone","additional_iso_files":[{"{{ `cd_files` }}":["."]}]}]}"#,
            r#"{"builders":[],"provisioners":[{"type":"shell","{{ `scripts` }}":["./x"]}]}"#,
            r#"{"builders":[],"variables":{"{{ `v` }}":"x"}}"#,
        ] {
            assert_eq!(
                recipe_build_refusal(content),
                Some("recipe_templated_key"),
                "{content}"
            );
        }
    }

    fn builder_with(extra: &serde_json::Value) -> Option<&'static str> {
        let mut block = serde_json::json!({ "type": "proxmox-iso" });
        for (key, value) in extra.as_object().unwrap() {
            block[key] = value.clone();
        }
        recipe_build_refusal(&serde_json::json!({ "builders": [block] }).to_string())
    }

    #[test]
    fn cd_content_paths_must_stay_inside_the_cd_root() {
        let refused = Some("recipe_controller_file_input");
        for path in [
            "..",
            ".",
            "../x",
            "a/../../x",
            "a/./b",
            "/etc/x",
            "\\..\\x",
            "a\\b",
            "a//b",
            "a/",
            "",
            "user data",
            "a:b",
        ] {
            for extra in [
                serde_json::json!({ "cd_content": { path: "x" } }),
                serde_json::json!({ "CD_Content": { path: "x" } }),
                serde_json::json!({ "boot_iso": { "iso_file": "local:iso/x.iso", "cd_content": { path: "x" } } }),
                serde_json::json!({ "additional_iso_files": [{ "cd_content": { path: "x" } }] }),
            ] {
                assert_eq!(builder_with(&extra), refused, "{extra}");
            }
        }
        assert_eq!(
            builder_with(&serde_json::json!({ "cd_content": ["meta-data"] })),
            refused
        );
        for path in [
            "meta-data",
            "user-data",
            "a/b.c/d_e",
            "..a",
            "a..",
            ".hidden",
        ] {
            let extra =
                serde_json::json!({ "additional_iso_files": [{ "cd_content": { path: "x" } }] });
            assert_eq!(builder_with(&extra), None, "{extra}");
        }
    }

    #[test]
    fn checksums_must_be_literal_digests_of_a_known_type() {
        let refused = Some("recipe_controller_file_input");
        let hex = |n: usize| "a".repeat(n);
        for checksum in [
            format!("file:{}", hex(64)),
            format!("sha384:{}", hex(96)),
            format!("sha256:{}", hex(63)),
            format!("sha256:{}", hex(40)),
            format!("md5:{}", hex(64)),
            format!(":{}", hex(64)),
            hex(63),
            "abcd".to_owned(),
            "NONE".to_owned(),
            format!("sha256:{}g", hex(63)),
        ] {
            let extra = serde_json::json!({ "boot_iso": { "iso_file": "local:iso/x.iso", "iso_checksum": checksum } });
            assert_eq!(builder_with(&extra), refused, "{extra}");
        }
        for checksum in [
            "none".to_owned(),
            hex(32),
            hex(40),
            hex(64),
            hex(128),
            format!("md5:{}", hex(32)),
            format!("sha1:{}", hex(40)),
            format!("SHA256:{}", hex(64).to_ascii_uppercase()),
            format!("sha512:{}", hex(128)),
        ] {
            let extra = serde_json::json!({ "boot_iso": { "iso_file": "local:iso/x.iso", "iso_checksum": checksum } });
            assert_eq!(builder_with(&extra), None, "{extra}");
        }
    }

    #[test]
    fn the_http_server_listens_only_on_tcp_at_a_literal_address() {
        let refused = Some("recipe_http_server_option");
        for extra in [
            serde_json::json!({ "http_network_protocol": "unix" }),
            serde_json::json!({ "HTTP_Network_Protocol": "unixpacket" }),
            serde_json::json!({ "http_network_protocol": "tcp6" }),
            serde_json::json!({ "http_network_protocol": "TCP" }),
            serde_json::json!({ "http_network_protocol": "{{user `p`}}" }),
            serde_json::json!({ "http_bind_address": "/tmp/x" }),
            serde_json::json!({ "http_bind_address": "pve.example.test" }),
            serde_json::json!({ "HTTP_BIND_ADDRESS": "{{user `a`}}" }),
            serde_json::json!({ "http_bind_address": 1 }),
            serde_json::json!({ "additional_iso_files": [{ "http_network_protocol": "unix" }] }),
        ] {
            assert_eq!(builder_with(&extra), refused, "{extra}");
        }
        for extra in [
            serde_json::json!({ "http_network_protocol": "tcp" }),
            serde_json::json!({ "http_network_protocol": "tcp4", "http_bind_address": "192.0.2.10" }),
            serde_json::json!({ "http_bind_address": "0.0.0.0", "http_port_min": 8100, "http_port_max": 8200 }),
            serde_json::json!({ "http_bind_address": "::1" }),
        ] {
            assert_eq!(builder_with(&extra), None, "{extra}");
        }
    }

    #[test]
    fn builders_may_not_set_packer_core_keys() {
        for key in [
            "packer_debug",
            "PACKER_ON_ERROR",
            "Packer_User_Variables",
            "packer_",
        ] {
            for extra in [
                serde_json::json!({ key: true }),
                serde_json::json!({ "boot_iso": { key: true } }),
            ] {
                assert_eq!(
                    builder_with(&extra),
                    Some("recipe_packer_internal_key"),
                    "{extra}"
                );
            }
        }
    }

    #[test]
    fn the_communicator_is_a_literal_kind_and_winrm_bypasses_the_proxy() {
        let refused = Some("recipe_communicator_forbidden_option");
        for extra in [
            serde_json::json!({ "communicator": "{{user `c`}}" }),
            serde_json::json!({ "communicator": "docker" }),
            serde_json::json!({ "communicator": "SSH" }),
            serde_json::json!({ "communicator": true }),
            serde_json::json!({ "communicator": "winrm" }),
            serde_json::json!({ "Communicator": "winrm", "winrm_no_proxy": false }),
            serde_json::json!({ "communicator": "winrm", "winrm_no_proxy": "true" }),
        ] {
            assert_eq!(builder_with(&extra), refused, "{extra}");
        }
        for extra in [
            serde_json::json!({}),
            serde_json::json!({ "communicator": "none" }),
            serde_json::json!({ "communicator": "ssh" }),
            serde_json::json!({ "COMMUNICATOR": "winrm", "WinRM_No_Proxy": true }),
        ] {
            assert_eq!(builder_with(&extra), None, "{extra}");
        }
    }

    #[test]
    fn packer_root_comments_are_refused() {
        // Packer accepts `_`-prefixed root keys as comments; Fleet has no use
        // for them and refuses every key outside the allowlist.
        assert_eq!(
            recipe_build_refusal(r#"{"_comment":"note","builders":[]}"#),
            Some("recipe_forbidden_top_level_key")
        );
    }

    #[test]
    fn every_refusal_reason_has_a_message() {
        for reason in RECIPE_REFUSAL_REASONS {
            assert!(!recipe_refusal_message(reason).is_empty(), "{reason}");
        }
    }

    #[test]
    fn validate_enforces_the_recipe_structure_gate() {
        let mut bad = recipe(r#"{"builders":[],"post-processors":[]}"#);
        assert!(bad.validate().is_err());
        bad.content = r#"{"variables":{"t":"{{env `PROXMOX_TOKEN`}}"},"builders":[]}"#.to_owned();
        assert!(bad.validate().is_err());
        bad.content = r#"{"builders":[{"type":"proxmox-clone"}],"provisioners":[{"type":"shell","inline":["echo hi"]}]}"#.to_owned();
        assert!(bad.validate().is_ok());
    }

    #[test]
    fn validation_refuses_malformed_metadata_and_oversized_content() {
        let mut bad = recipe("{}");
        bad.name = String::new();
        assert!(bad.validate().is_err());
        bad.name = "ok".to_owned();
        bad.node = String::new();
        assert!(bad.validate().is_err());
        bad.node = "pve".to_owned();
        bad.content = "x".repeat(MAX_RECIPE_CONTENT_BYTES + 1);
        assert!(bad.validate().is_err());
        assert!(recipe("{}").validate().is_ok());
    }

    #[test]
    fn sources_round_trip_their_ids() {
        for id in ["iso", "clone"] {
            let source = RecipeSource::from_id(id).unwrap();
            assert_eq!(source.id(), id);
        }
        assert!(RecipeSource::from_id("mystery").is_err());
    }
}

/// The structured recipe: exactly the supported Proxmox field subset,
/// mapped onto a canonical `.pkr.json` skeleton. Fields outside the
/// subset live only in the raw content and survive every round-trip.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredRecipe {
    /// The PVE node the recipe builds on.
    pub node: String,
    /// The PVE storage pool of the builder's first declared disk
    /// (`disks[0].storage_pool`). `None` when the builder declares no disk:
    /// a `proxmox-clone` without `disks` keeps the source template's
    /// storage, which the plugin offers no key for.
    pub storage_pool: Option<String>,
    /// What the recipe builds from.
    pub source: RecipeSource,
    /// The ISO file path, for the iso source: `boot_iso.iso_file`, or the
    /// plugin's deprecated top-level `iso_file`.
    pub iso_file: Option<String>,
    /// The ISO's storage pool, for the iso source: `boot_iso.iso_storage_pool`,
    /// or the deprecated top-level `iso_storage_pool`.
    pub iso_storage_pool: Option<String>,
    /// The guest to clone, for the clone source.
    pub clone_vm: Option<String>,
    /// The vCPU count.
    pub cores: Option<u32>,
    /// The memory in MiB.
    pub memory: Option<u32>,
    /// The first disk's size (`disks[0].disk_size`), as Packer's
    /// `G`-suffixed string.
    pub disk_size: Option<String>,
    /// The first network adapter's bridge (`network_adapters[0].bridge`).
    pub bridge: Option<String>,
}

/// A parsed `.pkr.json`'s shape, as the structured view needs: the
/// builders' `proxmox-*` block and whether the content parsed as JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedTemplate {
    /// Whether the content parsed as JSON at all.
    pub is_json: bool,
    /// The first `proxmox-*` builder block, when the content carries one.
    pub builder: Option<BuilderBlock>,
}

/// One builder block's fields, as the structured view reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderBlock {
    /// The builder's `type`, e.g. `proxmox-clone`.
    pub ptype: String,
    /// The block's fields, as raw JSON.
    pub fields: serde_json::Value,
}

/// Extracts the parsed template shape from raw content. Tolerant: a
/// non-JSON template (`.pkr.hcl`) reports `is_json: false` and no
/// structured view is offered.
#[must_use]
pub fn parse_template(content: &str) -> ParsedTemplate {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return ParsedTemplate::default();
    };
    let builder = value
        .get("builders")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .find_map(|builder| {
            // Only the two supported builders receive a structured view:
            // arbitrary `proxmox*` types would get a misleading one.
            let ptype = builder
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            (ptype == "proxmox-iso" || ptype == "proxmox-clone").then(|| BuilderBlock {
                ptype: ptype.to_owned(),
                fields: builder.clone(),
            })
        });
    ParsedTemplate {
        is_json: true,
        builder,
    }
}

fn field_str<'a>(builder: &'a BuilderBlock, key: &str) -> Option<&'a str> {
    builder.fields.get(key).and_then(serde_json::Value::as_str)
}

/// One string field of the first entry of a builder's list field, e.g.
/// `disks[0].storage_pool`: the plugin's block shape (packer-plugin-proxmox
/// 1.2.x, `builder/proxmox/common/config.go`).
fn first_entry_str<'a>(builder: &'a BuilderBlock, list: &str, key: &str) -> Option<&'a str> {
    builder
        .fields
        .get(list)
        .and_then(serde_json::Value::as_array)
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get(key))
        .and_then(serde_json::Value::as_str)
}

/// A `boot_iso` field, falling back to the deprecated top-level key.
fn boot_iso_str<'a>(builder: &'a BuilderBlock, key: &str) -> Option<&'a str> {
    builder
        .fields
        .get("boot_iso")
        .and_then(|iso| iso.get(key))
        .and_then(serde_json::Value::as_str)
        .or_else(|| field_str(builder, key))
}

impl StructuredRecipe {
    /// The structured view of raw content, when it carries a Proxmox
    /// builder block. `None` means the content has no structured view (a
    /// non-JSON template or no Proxmox builder).
    #[must_use]
    pub fn from_raw(content: &str) -> Option<Self> {
        let parsed = parse_template(content);
        let builder = parsed.builder?;
        Some(Self {
            node: field_str(&builder, "node")?.to_owned(),
            storage_pool: first_entry_str(&builder, "disks", "storage_pool").map(str::to_owned),

            // The builder type is the source of truth, not the presence
            // of a clone field.
            source: match builder.ptype.as_str() {
                "proxmox-clone" => RecipeSource::Clone,
                _ => RecipeSource::Iso,
            },
            iso_file: boot_iso_str(&builder, "iso_file").map(str::to_owned),
            iso_storage_pool: boot_iso_str(&builder, "iso_storage_pool").map(str::to_owned),
            // Packer's `clone_vm` is the VM **name** (a string); the
            // numeric VMID is the separate `clone_vm_id` field. Both are
            // accepted; the name form is the documented one.
            clone_vm: builder
                .fields
                .get("clone_vm")
                .map(|value| match value {
                    serde_json::Value::String(text) => text.clone(),
                    serde_json::Value::Number(number) => number.to_string(),
                    other => other.to_string(),
                })
                .or_else(|| {
                    builder
                        .fields
                        .get("clone_vm_id")
                        .and_then(serde_json::Value::as_u64)
                        .map(|value| value.to_string())
                }),
            cores: builder
                .fields
                .get("cores")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            memory: builder
                .fields
                .get("memory")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            disk_size: first_entry_str(&builder, "disks", "disk_size").map(str::to_owned),
            bridge: first_entry_str(&builder, "network_adapters", "bridge").map(str::to_owned),
        })
    }
}

#[cfg(test)]
mod structured_tests {
    use super::*;

    #[test]
    fn the_structured_view_parses_a_proxmox_builder() {
        let content = r#"{
            "builders": [{
                "type": "proxmox-clone",
                "node": "pve",
                "clone_vm": 101,
                "cores": 2,
                "memory": 2048,
                "disks": [{"type": "scsi", "storage_pool": "local-lvm", "disk_size": "10G"}],
                "network_adapters": [{"model": "virtio", "bridge": "vmbr0"}],
                "unknown_field": {"nested": true}
            }],
            "variables": {"x": 1}
        }"#;
        let structured = StructuredRecipe::from_raw(content).expect("a structured view");
        assert_eq!(structured.node, "pve");
        assert_eq!(structured.source, RecipeSource::Clone);
        assert_eq!(structured.clone_vm.as_deref(), Some("101"));
        assert_eq!(structured.storage_pool.as_deref(), Some("local-lvm"));
        assert_eq!(structured.cores, Some(2));
        assert_eq!(structured.memory, Some(2048));
        assert_eq!(structured.disk_size.as_deref(), Some("10G"));
        assert_eq!(structured.bridge.as_deref(), Some("vmbr0"));
    }

    #[test]
    fn the_structured_view_reads_only_keys_the_plugin_has() {
        // The plugin has no top-level storage, disk size, or bridge key
        // (`packer validate` refuses them), so the view ignores them rather
        // than presenting a value Packer would never apply.
        let invalid = r#"{"builders": [{
            "type": "proxmox-iso", "node": "pve",
            "vm_storage_pool": "local-lvm", "storage_pool": "local-lvm",
            "disk_size": "10G", "bridge": "vmbr0"
        }]}"#;
        let structured = StructuredRecipe::from_raw(invalid).expect("a structured view");
        assert_eq!(structured.storage_pool, None);
        assert_eq!(structured.disk_size, None);
        assert_eq!(structured.bridge, None);
        // boot_iso wins over the deprecated top-level ISO keys.
        let iso = r#"{"builders": [{
            "type": "proxmox-iso", "node": "pve",
            "boot_iso": {"iso_file": "local:iso/new.iso", "iso_storage_pool": "local"},
            "iso_file": "local:iso/old.iso"
        }]}"#;
        let structured = StructuredRecipe::from_raw(iso).expect("a structured view");
        assert_eq!(structured.iso_file.as_deref(), Some("local:iso/new.iso"));
        assert_eq!(structured.iso_storage_pool.as_deref(), Some("local"));
        let deprecated = r#"{"builders": [{"type": "proxmox-iso", "node": "pve", "iso_file": "local:iso/old.iso"}]}"#;
        assert_eq!(
            StructuredRecipe::from_raw(deprecated)
                .and_then(|s| s.iso_file)
                .as_deref(),
            Some("local:iso/old.iso")
        );
    }

    #[test]
    fn non_json_templates_have_no_structured_view() {
        // HCL2 content: honest absence, not a guess.
        assert!(StructuredRecipe::from_raw("source \"proxmox-clone\" {} {}").is_none());
        // JSON without a Proxmox builder: no structured view.
        assert!(StructuredRecipe::from_raw(r#"{"builders":[{"type":"docker"}]}"#).is_none());
    }
}

/// A safe, immutable snapshot of an image build. Raw variables, credentials,
/// filesystem paths and Packer output are deliberately excluded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageBuildRecord {
    /// Stable build identity (the durable operation id).
    pub id: String,
    /// The durable operation executing this build.
    pub operation_id: String,
    /// The recipe this build belongs to.
    pub recipe_id: String,
    /// The immutable recipe version.
    pub version_id: String,
    /// Digest binding the build to all recipe inputs.
    pub content_digest: String,
    /// Digests of provisioning assets; never their paths or contents.
    pub asset_digests: Vec<String>,
    /// Probed Packer version; absent when the probe failed.
    pub packer_version: Option<String>,
    /// Probed Proxmox plugin version; absent when the probe failed.
    pub proxmox_plugin_version: Option<String>,
    /// Resolved target Fleet account; absent only when target binding failed.
    pub account_id: Option<String>,
    /// Frozen target node.
    pub node: String,
    /// Frozen target storage pool.
    pub storage_pool: String,
    /// Start time in epoch milliseconds.
    pub started_at: i64,
    /// Completion time in epoch milliseconds.
    pub ended_at: Option<i64>,
    /// Running, succeeded, failed, or cancelled.
    pub outcome: String,
    /// Safe terminal reason code; never provider output.
    pub reason: Option<String>,
    /// Concrete output template identity, present only on success.
    pub template: Option<ImageBuildTemplate>,
}

/// The concrete template produced by an image build.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageBuildTemplate {
    /// Target node reported by the artifact or frozen recipe.
    pub node: String,
    /// Proxmox VMID.
    pub vmid: u32,
    /// Template name from the frozen recipe builder.
    pub name: String,
}

impl RecipeVersion {
    /// Whether a single builder's declared target matches this version's
    /// immutable Fleet metadata. Dynamic or ambiguous targets cannot be
    /// represented by one reproducible build record.
    #[must_use]
    pub fn has_frozen_build_target(&self) -> bool {
        let Some(structured) = StructuredRecipe::from_raw(&self.content) else {
            return false;
        };
        let Ok(content) = serde_json::from_str::<serde_json::Value>(&self.content) else {
            return false;
        };
        content
            .get("builders")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|builders| builders.len() == 1)
            && [self.node.as_str(), self.storage_pool.as_str()]
                .iter()
                .all(|target| {
                    !target.is_empty()
                        && target.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                })
            && structured.node == self.node
            && self.frozen_storage(&content)
            && structured.source == self.source
    }

    /// Whether the builder's storage matches the version's. Every declared
    /// disk must name the version's pool literally. A `proxmox-clone` with
    /// no `disks` keeps the source template's storage, for which the plugin
    /// has no key: the version's pool is then the operator's declaration,
    /// not something the recipe can prove. An ISO build always needs a disk.
    fn frozen_storage(&self, content: &serde_json::Value) -> bool {
        let disks = content
            .get("builders")
            .and_then(|builders| builders.get(0))
            .and_then(|builder| builder.get("disks"));
        match disks {
            None => self.source == RecipeSource::Clone,
            Some(serde_json::Value::Array(disks)) if !disks.is_empty() => {
                disks.iter().all(|disk| {
                    disk.get("storage_pool").and_then(serde_json::Value::as_str)
                        == Some(self.storage_pool.as_str())
                })
            }
            Some(_) => false,
        }
    }
}

#[cfg(test)]
mod frozen_target_tests {
    use super::*;

    #[test]
    fn matching_metadata_cannot_freeze_interpolated_targets() {
        for (node, storage_pool, expected) in [
            ("pve-1", "local-lvm", true),
            ("{{user `node`}}", "local-lvm", false),
            ("pve", "{{user `storage`}}", false),
            ("${var.node}", "local-lvm", false),
            ("pve", "${var.storage}", false),
        ] {
            let version = RecipeVersion {
                id: "v".to_owned(), recipe_id: "r".to_owned(), name: "image".to_owned(),
                description: String::new(), content_digest: "digest".to_owned(),
                content: serde_json::json!({"builders":[{"type":"proxmox-clone", "node":node, "disks":[{"type":"scsi", "storage_pool":storage_pool, "disk_size":"8G"}]}]}).to_string(),
                source: RecipeSource::Clone, node: node.to_owned(), storage_pool: storage_pool.to_owned(),
                published_at: 1, promoted_at: None, promoted_by: None, promoted_build_id: None, allow_insecure_tls: false,
            };
            assert_eq!(version.has_frozen_build_target(), expected);
        }
    }

    fn version(source: RecipeSource, builder: &serde_json::Value) -> RecipeVersion {
        RecipeVersion {
            id: "v".to_owned(),
            recipe_id: "r".to_owned(),
            name: "image".to_owned(),
            description: String::new(),
            content_digest: "digest".to_owned(),
            content: serde_json::json!({ "builders": [builder] }).to_string(),
            source,
            node: "pve".to_owned(),
            storage_pool: "local-lvm".to_owned(),
            published_at: 1,
            promoted_at: None,
            promoted_by: None,
            promoted_build_id: None,
            allow_insecure_tls: false,
        }
    }

    #[test]
    fn the_storage_target_follows_the_plugin_schema() {
        let clone =
            serde_json::json!({"type": "proxmox-clone", "node": "pve", "clone_vm_id": 7000});
        // A disk-less clone inherits the source's storage.
        assert!(version(RecipeSource::Clone, &clone).has_frozen_build_target());
        // Declared disks must all name the version's pool.
        let mut with_disks = clone.clone();
        with_disks["disks"] = serde_json::json!([
            {"type": "scsi", "storage_pool": "local-lvm", "disk_size": "8G"},
            {"type": "scsi", "storage_pool": "other", "disk_size": "8G"}
        ]);
        assert!(!version(RecipeSource::Clone, &with_disks).has_frozen_build_target());
        // An ISO build without a disk has no storage target at all.
        let iso = serde_json::json!({"type": "proxmox-iso", "node": "pve"});
        assert!(!version(RecipeSource::Iso, &iso).has_frozen_build_target());
        let mut iso_disk = iso;
        iso_disk["disks"] =
            serde_json::json!([{"type": "scsi", "storage_pool": "local-lvm", "disk_size": "8G"}]);
        assert!(version(RecipeSource::Iso, &iso_disk).has_frozen_build_target());
        // The plugin-invalid top-level key no longer freezes anything.
        let legacy = serde_json::json!({"type": "proxmox-iso", "node": "pve", "vm_storage_pool": "local-lvm"});
        assert!(!version(RecipeSource::Iso, &legacy).has_frozen_build_target());
    }
}
