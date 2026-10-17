//! `fleetctl services templates` and `fleetctl services deploy` (FM-1035):
//! deploy a new site on Coolify from a template. An adapter over
//! `/api/v1/site-templates` and `/api/v1/site-deployments`; the template
//! pin, the target checks, the policy, and the audit are the controller's.
//!
//! `deploy` files one `approve`-class action request. With `--wait-approval`
//! the command waits for the request and prints what the operation did (the
//! created uuid and every step); after a success it prints the
//! `fleetctl registry set` / `relate` patch that records the new site, and
//! `--output json` carries the same lines as `registryPatch`. A deployment
//! that stopped after creating the resource is a failed operation: the
//! answer still names the uuid and the steps.
//!
//! `--dns --dns-target <value>` also files a Cloudflare DNS change request
//! (`fleetctl dns set`, risk class `approve`) for the domain, before the
//! wait. It is a separate request: it fails alone when no Cloudflare zone
//! covers the domain, and the deploy request is unaffected.

use std::fmt::Write as _;
use std::time::Duration;

use serde_json::{Value, json};

use crate::requests::parse_wait_approval;
use crate::{CliError, Command, Invocation, Output, RequestShape, usage};

/// The arguments of `services deploy`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeployArgs {
    /// The template id.
    pub template: String,
    /// The Fleet Coolify account id.
    pub account: String,
    /// The target server's uuid or exact name.
    pub server: String,
    /// The target project's uuid or exact name.
    pub project: String,
    /// The environment name.
    pub environment: String,
    /// The destination uuid, when the server has several.
    pub destination: Option<String>,
    /// The site's domain.
    pub domain: String,
    /// The resource name.
    pub name: Option<String>,
    /// The public repository (Git templates).
    pub repository: Option<String>,
    /// The branch (Git templates).
    pub branch: Option<String>,
    /// Why, for the approver.
    pub reason: Option<String>,
    /// A key making a retry return the request already made.
    pub idempotency_key: Option<String>,
    /// Wait this long for the request to reach an outcome.
    pub wait: Option<Duration>,
    /// The DNS request to file beside the deploy, when asked.
    pub dns: Option<DnsArgs>,
}

/// The DNS record to request for the domain.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsArgs {
    /// The record value (an address or a host name).
    pub target: String,
    /// The record type; inferred from the target when absent.
    pub record_type: Option<String>,
    /// The Cloudflare account (id or label), when several hold the zone.
    pub account: Option<String>,
}

fn bad(message: impl Into<String>) -> CliError {
    CliError {
        message: format!("{}\n\n{}", message.into(), usage()),
    }
}

/// Parses `templates` and `deploy ...` (the words after `services`).
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let (verb, flags) = rest.split_first().ok_or_else(|| bad("missing command"))?;
    let templates = *verb == "templates";
    let mut args = DeployArgs::default();
    let mut dns = false;
    let mut dns_args = DnsArgs::default();
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        if !templates && let Some(duration) = parse_wait_approval("--wait-approval", flag)? {
            args.wait = Some(duration);
            continue;
        }
        let mut value = |name: &str| {
            flags
                .next()
                .filter(|candidate| !candidate.starts_with("--"))
                .map(str::to_owned)
                .ok_or_else(|| CliError {
                    message: format!("--{name} requires a value"),
                })
        };
        match flag {
            "--output" => {
                *output = match value("output")?.as_str() {
                    "json" => Output::Json,
                    "text" => Output::Text,
                    other => {
                        return Err(CliError {
                            message: format!("--output must be json or text, not {other:?}"),
                        });
                    }
                };
            }
            "--template" if !templates => args.template = value("template")?,
            "--account" if !templates => args.account = value("account")?,
            "--server" if !templates => args.server = value("server")?,
            "--project" if !templates => args.project = value("project")?,
            "--environment" if !templates => args.environment = value("environment")?,
            "--destination" if !templates => args.destination = Some(value("destination")?),
            "--domain" if !templates => args.domain = value("domain")?,
            "--name" if !templates => args.name = Some(value("name")?),
            "--repo" if !templates => args.repository = Some(value("repo")?),
            "--branch" if !templates => args.branch = Some(value("branch")?),
            "--reason" if !templates => args.reason = Some(value("reason")?),
            "--idempotency-key" if !templates => {
                args.idempotency_key = Some(value("idempotency-key")?);
            }
            "--dns" if !templates => dns = true,
            "--dns-target" if !templates => dns_args.target = value("dns-target")?,
            "--dns-type" if !templates => dns_args.record_type = Some(value("dns-type")?),
            "--dns-account" if !templates => dns_args.account = Some(value("dns-account")?),
            other => {
                return Err(bad(format!("unknown flag {other:?}")));
            }
        }
    }
    if templates {
        return Ok(Command::Services(super::ServicesAction::Templates));
    }
    for (name, value) in [
        ("template", &args.template),
        ("account", &args.account),
        ("server", &args.server),
        ("project", &args.project),
        ("environment", &args.environment),
        ("domain", &args.domain),
    ] {
        if value.is_empty() {
            return Err(bad(format!("services deploy needs --{name}")));
        }
    }
    if dns {
        if dns_args.target.is_empty() {
            return Err(bad(
                "--dns needs --dns-target <address or host name> (the record's value)",
            ));
        }
        args.dns = Some(dns_args);
    } else if !dns_args.target.is_empty()
        || dns_args.record_type.is_some()
        || dns_args.account.is_some()
    {
        return Err(bad(
            "--dns-target, --dns-type, and --dns-account need --dns",
        ));
    }
    Ok(Command::Services(super::ServicesAction::Deploy(Box::new(
        args,
    ))))
}

/// The controller request of `templates`.
pub(crate) fn templates_request() -> RequestShape {
    (
        reqwest::Method::GET,
        "/api/v1/site-templates".to_owned(),
        Vec::new(),
        None,
    )
}

/// The controller request of `deploy`.
pub(crate) fn request(args: &DeployArgs) -> RequestShape {
    let mut body = json!({
        "accountId": args.account,
        "templateId": args.template,
        "serverUuid": args.server,
        "projectUuid": args.project,
        "environmentName": args.environment,
        "domain": args.domain,
        "reason": args.reason.clone().unwrap_or_default(),
    });
    for (key, value) in [
        ("destinationUuid", &args.destination),
        ("name", &args.name),
        ("repository", &args.repository),
        ("branch", &args.branch),
        ("idempotencyKey", &args.idempotency_key),
    ] {
        if let Some(value) = value {
            body[key] = json!(value);
        }
    }
    (
        reqwest::Method::POST,
        "/api/v1/site-deployments".to_owned(),
        Vec::new(),
        Some(body),
    )
}

/// The record type for a DNS target: an address is `A` or `AAAA`, anything
/// else a `CNAME`.
fn dns_type(args: &DnsArgs) -> String {
    if let Some(record_type) = &args.record_type {
        return record_type.to_ascii_uppercase();
    }
    match args.target.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => "A",
        Ok(std::net::IpAddr::V6(_)) => "AAAA",
        Err(_) => "CNAME",
    }
    .to_owned()
}

/// The host of a domain argument (a bare host or a URL).
fn host_of(domain: &str) -> String {
    let rest = domain.split_once("://").map_or(domain, |(_, rest)| rest);
    rest.split(['/', ':'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Files the optional DNS request for a filed deploy. The answer is the DNS
/// request, or an error sentence: a DNS failure never undoes the deploy
/// request.
pub(crate) fn file_dns(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    args: &DeployArgs,
) -> Option<Value> {
    let dns = args.dns.as_ref()?;
    let host = host_of(&args.domain);
    let mut body = json!({
        "operation": "upsert",
        "name": host,
        "type": dns_type(dns),
        "content": dns.target,
        "reason": format!("point {host} at the new {} site", args.template),
    });
    if let Some(account) = &dns.account {
        body["account"] = json!(account);
    }
    if let Some(key) = &args.idempotency_key {
        body["idempotencyKey"] = json!(format!("{key}-dns"));
    }
    let sent = crate::send_classified(
        client,
        invocation,
        reqwest::Method::POST,
        "/api/v1/dns/changes",
        &[],
        Some(&body),
        uuid::Uuid::now_v7().to_string(),
        None,
        Some(Duration::from_secs(30)),
    );
    Some(match sent {
        Ok(created) => created.get("data").cloned().unwrap_or(created),
        Err((error, _)) => json!({ "error": clean(&error.message) }),
    })
}

/// The `fleetctl registry` commands that record a deployed site.
fn registry_patch(domain: &str, uuid: &str) -> Vec<String> {
    let host = host_of(domain);
    vec![
        format!("fleetctl registry set domain/{host} --field fqdn={host}"),
        format!("fleetctl registry relate domain/{host} hosted-on coolify:{uuid}"),
    ]
}

/// Adds the DNS request and, for a site that exists, the registry patch to
/// the answer (`registryPatchReady` is false while the deployment still runs).
pub(crate) fn annotate(answer: &mut Value, dns: Option<Value>) {
    if let Some(dns) = dns {
        answer["dnsRequest"] = dns;
    }
    // The patch records a site that exists. A deployment still building is
    // `started`: the patch is given with the note that it is for once the
    // deployment finishes, and a partial deployment gets none.
    let result = answer["result"].clone();
    let outcome = result["outcome"].as_str();
    if matches!(outcome, Some("deployed" | "started"))
        && let (Some(domain), Some(uuid)) = (result["domain"].as_str(), result["uuid"].as_str())
    {
        let patch = registry_patch(domain, uuid);
        answer["registryPatch"] = json!(patch);
        answer["registryPatchReady"] = json!(outcome == Some("deployed"));
    }
}

/// Server-supplied text for a terminal: control characters become spaces.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn text_of(value: &Value) -> String {
    clean(value.as_str().unwrap_or("-"))
}

/// Renders the template list.
pub(crate) fn render_templates(value: &Value) -> String {
    let data = value.get("data").unwrap_or(value);
    let Some(templates) = data["templates"].as_array() else {
        return String::new();
    };
    let mut lines = vec![format!(
        "{:<14} {:<4} {:<9} {:<16} NEEDS",
        "ID", "VER", "KIND", "WHAT"
    )];
    for template in templates {
        let source = &template["source"];
        let what = source["serviceType"]
            .as_str()
            .or_else(|| source["buildPack"].as_str())
            .unwrap_or("-");
        lines.push(format!(
            "{:<14} {:<4} {:<9} {:<16} {}",
            text_of(&template["id"]),
            template["version"],
            text_of(&source["kind"]),
            clean(what),
            if template["needsRepository"].as_bool() == Some(true) {
                "--repo <https url> --branch <name>"
            } else {
                "-"
            }
        ));
    }
    lines.join("\n")
}

/// Renders a filed deploy request, or a wait's answer with the operation
/// result: the created resource, each step, and the registry patch.
pub(crate) fn render_deploy(value: &Value) -> String {
    let mut text = crate::requests::render(value);
    if let Some(dns) = value.get("dnsRequest") {
        match dns["error"].as_str() {
            Some(error) => {
                let _ = write!(text, "\n  dns request not filed: {error}");
            }
            None => {
                let _ = write!(
                    text,
                    "\n  dns request {}: {} ({})",
                    text_of(&dns["id"]),
                    text_of(&dns["target"]),
                    text_of(&dns["state"])
                );
            }
        }
    }
    if let Some(warning) = value["resultWarning"].as_str() {
        let _ = write!(text, "\n  warning: {}", clean(warning));
    }
    let result = &value["result"];
    if !result.is_object() {
        return text;
    }
    let _ = write!(
        text,
        "\n  result: {} {} {} at {}",
        text_of(&result["outcome"]),
        text_of(&result["resourceKind"]),
        text_of(&result["uuid"]),
        text_of(&result["domain"])
    );
    for step in result["steps"].as_array().into_iter().flatten() {
        let _ = write!(
            text,
            "\n    {:<7} {:<8} {}",
            text_of(&step["step"]),
            text_of(&step["status"]),
            clean(step["detail"].as_str().unwrap_or(""))
        );
    }
    if let Some(deployment) = result["deploymentUuid"].as_str() {
        let _ = write!(
            text,
            "\n  deployment: {} ({}) (fleetctl services logs {} --deployment {})",
            clean(deployment),
            text_of(&result["deploymentStatus"]),
            text_of(&result["serviceId"]),
            clean(deployment)
        );
    }
    if let Some(error) = result["error"].as_str() {
        let _ = write!(
            text,
            "\n  stopped: {}\n  the resource exists in Coolify (uuid above): finish there, or delete it there and file a new request",
            clean(error)
        );
    }
    let keys: Vec<&str> = result["followUpEnvKeys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !keys.is_empty() {
        let _ = write!(
            text,
            "\n  set these variables next: fleetctl services env set {} --stdin ({})",
            text_of(&result["serviceId"]),
            clean(&keys.join(", "))
        );
    }
    if let Some(patch) = value["registryPatch"].as_array() {
        text.push_str(if value["registryPatchReady"].as_bool() == Some(false) {
            "\n  the deployment has not finished yet; once it has, record it in the registry (in a Fleet Git checkout):"
        } else {
            "\n  record it in the registry (in a Fleet Git checkout):"
        });
        for line in patch.iter().filter_map(Value::as_str) {
            let _ = write!(text, "\n    {}", clean(line));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ServicesAction;

    fn parsed(words: &[&str]) -> Result<ServicesAction, CliError> {
        let args: Vec<String> = words.iter().map(ToString::to_string).collect();
        crate::parse(&args).map(|invocation| match invocation.command {
            Command::Services(action) => action,
            other => panic!("not a services command: {other:?}"),
        })
    }

    const FULL: [&str; 16] = [
        "services",
        "deploy",
        "--template",
        "node-app",
        "--account",
        "acct",
        "--server",
        "edge-1",
        "--project",
        "sites",
        "--environment",
        "production",
        "--domain",
        "app.example.test",
        "--repo",
        "https://example.test/o/r",
    ];

    #[test]
    fn deploy_needs_its_target_and_parses_every_flag() {
        let mut words: Vec<&str> = FULL.to_vec();
        words.extend([
            "--branch",
            "main",
            "--name",
            "app",
            "--dns",
            "--dns-target",
            "203.0.113.9",
            "--wait-approval=10m",
            "--reason",
            "launch",
        ]);
        let ServicesAction::Deploy(args) = parsed(&words).unwrap() else {
            panic!("not a deploy");
        };
        assert_eq!(args.template, "node-app");
        assert_eq!(args.server, "edge-1");
        assert_eq!(args.branch.as_deref(), Some("main"));
        assert_eq!(args.wait, Some(Duration::from_secs(600)));
        assert_eq!(args.dns.as_ref().unwrap().target, "203.0.113.9");
        assert_eq!(dns_type(args.dns.as_ref().unwrap()), "A");
        for missing in [
            "--template",
            "--account",
            "--server",
            "--project",
            "--environment",
            "--domain",
        ] {
            let mut words: Vec<&str> = Vec::new();
            let mut skip = false;
            for word in &FULL {
                if skip {
                    skip = false;
                } else if *word == missing {
                    skip = true;
                } else {
                    words.push(word);
                }
            }
            assert!(parsed(&words).is_err(), "{missing} is required");
        }
        assert!(parsed(&["services", "deploy", "--template", "x", "--bogus"]).is_err());
    }

    #[test]
    fn dns_needs_a_target_and_the_type_follows_it() {
        let mut words: Vec<&str> = FULL.to_vec();
        words.push("--dns");
        assert!(parsed(&words).is_err());
        let mut words: Vec<&str> = FULL.to_vec();
        words.extend(["--dns-target", "x.example.test"]);
        assert!(parsed(&words).is_err());
        let dns = |target: &str| DnsArgs {
            target: target.to_owned(),
            ..DnsArgs::default()
        };
        assert_eq!(dns_type(&dns("203.0.113.9")), "A");
        assert_eq!(dns_type(&dns("2001:db8::1")), "AAAA");
        assert_eq!(dns_type(&dns("lb.example.test")), "CNAME");
        assert_eq!(host_of("https://App.Example.Test/x"), "app.example.test");
    }

    #[test]
    fn templates_and_deploy_build_the_documented_requests() {
        assert!(matches!(
            parsed(&["services", "templates"]).unwrap(),
            ServicesAction::Templates
        ));
        let (method, path, _, body) = templates_request();
        assert_eq!(
            (method, path.as_str(), body),
            (reqwest::Method::GET, "/api/v1/site-templates", None)
        );
        let mut words: Vec<&str> = FULL.to_vec();
        words.extend(["--branch", "main", "--idempotency-key", "k1"]);
        let ServicesAction::Deploy(args) = parsed(&words).unwrap() else {
            panic!("not a deploy");
        };
        let (method, path, _, body) = request(&args);
        assert_eq!(method, reqwest::Method::POST);
        assert_eq!(path, "/api/v1/site-deployments");
        let body = body.unwrap();
        assert_eq!(body["templateId"], "node-app");
        assert_eq!(body["serverUuid"], "edge-1");
        assert_eq!(body["idempotencyKey"], "k1");
        assert!(body.get("destinationUuid").is_none());
    }

    #[test]
    fn a_success_prints_the_registry_patch_and_a_partial_does_not() {
        let mut done = json!({
            "outcome": "executed",
            "request": {"id": "r1", "state": "succeeded", "actionId": "coolify.site.deploy", "target": "site:a:app.example.test"},
            "result": {
                "outcome": "deployed", "resourceKind": "application", "uuid": "app123",
                "serviceId": "coolify:a:app123", "domain": "https://app.example.test",
                "steps": [{"step": "create", "status": "done"}],
                "deploymentUuid": "dep1", "deploymentStatus": "finished",
                "followUpEnvKeys": ["API_KEY"]
            }
        });
        annotate(
            &mut done,
            Some(json!({"id": "d1", "target": "dns.record.upsert", "state": "pending"})),
        );
        let text = render_deploy(&done);
        assert!(
            text.contains(
                "fleetctl registry set domain/app.example.test --field fqdn=app.example.test"
            ),
            "{text}"
        );
        assert!(text.contains("hosted-on coolify:app123"), "{text}");
        assert!(text.contains("dns request d1"), "{text}");
        assert!(text.contains("API_KEY"), "{text}");
        assert_eq!(done["registryPatch"].as_array().unwrap().len(), 2);

        let mut partial = json!({
            "outcome": "failed",
            "request": {"id": "r2", "state": "failed"},
            "result": {"outcome": "partial", "resourceKind": "application", "uuid": "app9",
                       "domain": "https://x.example.test", "error": "boom",
                       "steps": [{"step": "start", "status": "failed", "detail": "boom"}]}
        });
        annotate(&mut partial, None);
        let text = render_deploy(&partial);
        assert!(!text.contains("registry set"), "{text}");
        assert!(
            text.contains("delete it there and file a new request"),
            "{text}"
        );
        assert!(partial.get("registryPatch").is_none());
    }

    #[test]
    fn a_dns_account_without_dns_is_refused_like_the_other_dns_flags() {
        for flag in [
            ["--dns-account", "cf"],
            ["--dns-type", "A"],
            ["--dns-target", "203.0.113.9"],
        ] {
            let mut words: Vec<&str> = FULL.to_vec();
            words.extend(flag);
            assert!(parsed(&words).is_err(), "{flag:?}");
        }
    }

    #[test]
    fn a_deployment_still_running_gets_a_patch_marked_not_ready() {
        let mut answer = json!({
            "outcome": "executed",
            "request": {"id": "r3", "state": "succeeded"},
            "result": {"outcome": "started", "resourceKind": "application", "uuid": "app7",
                       "domain": "https://x.example.test", "steps": []}
        });
        annotate(&mut answer, None);
        assert_eq!(answer["registryPatchReady"], json!(false));
        let text = render_deploy(&answer);
        assert!(text.contains("has not finished yet"), "{text}");
        assert!(text.contains("hosted-on coolify:app7"), "{text}");
    }

    #[test]
    fn the_template_table_lists_what_each_needs() {
        let text = render_templates(&json!({"data": {"templates": [
            {"id": "ghost", "version": 1, "needsRepository": false, "source": {"kind": "service", "serviceType": "ghost"}},
            {"id": "node-app", "version": 1, "needsRepository": true, "source": {"kind": "git", "buildPack": "nixpacks"}}
        ]}}));
        assert!(text.contains("ghost") && text.contains("--repo"), "{text}");
    }
}
