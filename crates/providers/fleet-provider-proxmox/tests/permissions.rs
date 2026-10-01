//! Contract tests for the token-permissions read (FM-604) over recorded-shape
//! PVE 8.x and 9.x fixtures: a full token, a read-only token, a
//! privilege-separated token without ACLs, and a refused read.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_core::SensitiveString;
use fleet_provider_proxmox::{
    ProxmoxClient, ProxmoxSource, PveApiError, PveCredentials, PveHttpMethod, PveHttpRequest,
    PveHttpResponse, PveTransport, PveTransportError,
};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";

/// Answers `/version` from the family's fixture and `/access/permissions`
/// with the given status and body; anything else is a contract violation.
#[derive(Debug)]
struct PermissionsTransport {
    family: &'static str,
    status: u16,
    body: &'static str,
    requests: Mutex<Vec<PveHttpRequest>>,
}

impl PermissionsTransport {
    fn new(family: &'static str, status: u16, body: &'static str) -> Arc<Self> {
        Arc::new(Self {
            family,
            status,
            body,
            requests: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl PveTransport for PermissionsTransport {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        assert_eq!(request.method, PveHttpMethod::Get, "the read never mutates");
        assert_eq!(
            request.pinned_fingerprint.as_deref(),
            Some(FP),
            "every credential-carrying call is pinned"
        );
        self.requests.lock().unwrap().push(request.clone());
        let (status, body) = match (self.family, request.path.as_str()) {
            ("pve8", "/api2/json/version") => (200, include_str!("fixtures/pve8/version.json")),
            ("pve9", "/api2/json/version") => (200, include_str!("fixtures/pve9/version.json")),
            (_, "/api2/json/access/permissions") => (self.status, self.body),
            (_, path) => panic!("unexpected PVE request path: {path}"),
        };
        Ok(PveHttpResponse {
            status,
            body: body.as_bytes().to_vec(),
        })
    }

    async fn execute_with_body(
        &self,
        _request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        panic!("the permissions read sends no body");
    }
}

fn request() -> PveHttpRequest {
    PveHttpRequest {
        host: "pve.test".to_owned(),
        port: 8006,
        path: "/api2/json/version".to_owned(),
        pinned_fingerprint: Some(FP.to_owned()),
        credentials: Arc::new(PveCredentials {
            token_id: "fleet@pve!fleet".to_owned(),
            token: SensitiveString::new("fixture-secret"),
        }),
        method: PveHttpMethod::Get,
    }
}

const ROOTS: [&str; 8] = [
    "/",
    "/access",
    "/access/groups",
    "/nodes",
    "/pool",
    "/sdn",
    "/storage",
    "/vms",
];

#[tokio::test]
async fn pve9_full_token_lists_every_root_with_the_guest_agent_split() {
    let transport = PermissionsTransport::new(
        "pve9",
        200,
        include_str!("fixtures/pve9/access-permissions-full.json"),
    );
    let client = ProxmoxClient::new(transport.clone());

    let permissions = client.token_permissions(request()).await.unwrap();

    assert_eq!(permissions.version, "9.2.2");
    assert!(
        permissions.warnings.is_empty(),
        "{:?}",
        permissions.warnings
    );
    assert!(!permissions.truncated);
    assert_eq!(
        permissions
            .paths
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        {
            let mut roots = ROOTS.to_vec();
            roots.sort_unstable();
            roots
        }
    );
    let root = &permissions.paths["/"];
    assert_eq!(root.get("VM.GuestAgent.Audit"), Some(&true));
    assert_eq!(root.get("VM.GuestAgent.Unrestricted"), Some(&true));
    assert_eq!(root.get("VM.Monitor"), None, "PVE 9 removed VM.Monitor");
    // A privilege Fleet does not use is kept, not rejected.
    assert_eq!(root.get("VM.Replicate"), Some(&true));

    let requests = transport.requests.lock().unwrap();
    assert_eq!(
        requests.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        ["/api2/json/version", "/api2/json/access/permissions"],
        "no userid or path parameter: the token reads its own full map"
    );
}

#[tokio::test]
async fn pve8_full_token_carries_vm_monitor_and_no_guest_agent_privileges() {
    let transport = PermissionsTransport::new(
        "pve8",
        200,
        include_str!("fixtures/pve8/access-permissions-full.json"),
    );
    let client = ProxmoxClient::new(transport);

    let permissions = client.token_permissions(request()).await.unwrap();

    assert_eq!(permissions.version, "8.4.1");
    assert_eq!(permissions.paths.len(), ROOTS.len());
    let root = &permissions.paths["/"];
    assert_eq!(root.get("VM.Monitor"), Some(&true));
    assert!(root.keys().all(|name| !name.starts_with("VM.GuestAgent.")));
    assert_eq!(root.get("VM.Allocate"), Some(&true));
}

#[tokio::test]
async fn readonly_tokens_hold_only_audit_privileges_per_major() {
    for (family, body, agent_audit) in [
        (
            "pve8",
            include_str!("fixtures/pve8/access-permissions-readonly.json"),
            false,
        ),
        (
            "pve9",
            include_str!("fixtures/pve9/access-permissions-readonly.json"),
            true,
        ),
    ] {
        let client = ProxmoxClient::new(PermissionsTransport::new(family, 200, body));
        let permissions = client.token_permissions(request()).await.unwrap();
        for path in ROOTS {
            let privileges = &permissions.paths[path];
            assert!(
                privileges.keys().all(|name| name.ends_with(".Audit")),
                "{family} {path}: {privileges:?}"
            );
            assert_eq!(privileges.get("VM.Audit"), Some(&true));
            assert_eq!(privileges.get("VM.PowerMgmt"), None);
            assert_eq!(
                privileges.contains_key("VM.GuestAgent.Audit"),
                agent_audit,
                "{family}: PVEAuditor gained VM.GuestAgent.Audit in 9.x"
            );
        }
    }
}

#[tokio::test]
async fn a_privilege_separated_token_without_acls_reads_an_empty_map() {
    for (family, body) in [
        (
            "pve8",
            include_str!("fixtures/pve8/access-permissions-privsep-empty.json"),
        ),
        (
            "pve9",
            include_str!("fixtures/pve9/access-permissions-privsep-empty.json"),
        ),
    ] {
        let client = ProxmoxClient::new(PermissionsTransport::new(family, 200, body));
        let permissions = client.token_permissions(request()).await.unwrap();
        assert!(permissions.paths.is_empty(), "{family}");
        assert!(permissions.warnings.is_empty(), "{family}");
    }
}

#[tokio::test]
async fn pool_scoped_tokens_keep_pool_member_propagation_flags() {
    for family in ["pve8", "pve9"] {
        let body = if family == "pve8" {
            include_str!("fixtures/pve8/access-permissions-pool-scoped.json")
        } else {
            include_str!("fixtures/pve9/access-permissions-pool-scoped.json")
        };
        let client = ProxmoxClient::new(PermissionsTransport::new(family, 200, body));
        let permissions = client.token_permissions(request()).await.unwrap();
        assert_eq!(
            permissions.paths["/vms/101"].get("VM.PowerMgmt"),
            Some(&false)
        );
        assert_eq!(
            permissions.paths["/pool/fleet"].get("VM.PowerMgmt"),
            Some(&true)
        );
        assert_eq!(
            permissions.paths["/sdn/zones/localnetwork/vmbr0"].get("SDN.Use"),
            Some(&true)
        );
        assert!(!permissions.paths.contains_key("/"), "{family}");
    }
}

#[tokio::test]
async fn a_refused_permissions_read_is_a_forbidden_error_with_bounded_detail() {
    for family in ["pve8", "pve9"] {
        let client = ProxmoxClient::new(PermissionsTransport::new(
            family,
            403,
            r#"{"data":null,"message":"Permission check failed (/access, Sys.Audit)\n"}"#,
        ));
        let error = client.token_permissions(request()).await.unwrap_err();
        let PveApiError::Forbidden { detail } = error else {
            panic!("{family}: expected Forbidden, got {error:?}");
        };
        assert!(detail.contains("Permission check failed"), "{detail}");
        assert!(!detail.contains("fixture-secret"));
    }
}

#[tokio::test]
async fn an_oversized_refusal_body_is_capped_at_256_characters() {
    let body = format!(
        r#"{{"data":null,"message":"Permission check failed {}"}}"#,
        "x".repeat(1024)
    );
    let client = ProxmoxClient::new(PermissionsTransport::new(
        "pve9",
        403,
        Box::leak(body.clone().into_boxed_str()),
    ));
    let error = client.token_permissions(request()).await.unwrap_err();
    let PveApiError::Forbidden { detail } = error else {
        panic!("expected Forbidden, got {error:?}");
    };
    assert!(body.chars().count() > 256);
    assert_eq!(detail.chars().count(), 256, "{detail}");
    assert!(detail.contains("Permission check failed"));
}
