//! The delegated credential's authorization catalog (ADR 0011): every
//! catalog action is classified for a credential principal, each allowed
//! action is allowed only on the resources its row names, and everything
//! else is refused with a stable reason.

use std::sync::Arc;

use fleet_application::authz::{
    AccessRequest, Authorizer, Decision, Permission, ReasonId, delegated_principal_id,
    is_delegated_principal, owner_scope_permits, resource_owner,
};
use fleet_application::credentials::{DelegatedGrant, GrantBook};
use fleet_auth::{
    DELEGATED_LAB_LOOP, DelegatedAction, LAN_PRINCIPAL_ID, ResourceRule, ScopedAuthorizer,
};

const CREDENTIAL: &str = "cred-1";
const OTHER_CREDENTIAL: &str = "cred-2";

fn principal() -> String {
    delegated_principal_id("release-qa", CREDENTIAL)
}

fn authorizer() -> ScopedAuthorizer {
    let grants = Arc::new(GrantBook::new());
    grants.register(
        &principal(),
        DelegatedGrant {
            templates: vec!["tpl-allowed".to_owned()],
            versions: vec!["ver-pinned".to_owned()],
        },
    );
    // Same owner, a narrower credential.
    grants.register(
        &delegated_principal_id("release-qa", OTHER_CREDENTIAL),
        DelegatedGrant {
            templates: vec!["tpl-other".to_owned()],
            versions: vec![],
        },
    );
    ScopedAuthorizer::new(grants)
}

fn decide(authorizer: &ScopedAuthorizer, action: Permission, resource: Option<&str>) -> Decision {
    authorizer.decide(AccessRequest {
        principal_id: &principal(),
        action,
        resource,
    })
}

/// The actions the Lab loop allows, and a resource each is allowed on.
const ALLOWED: &[(Permission, Option<&str>)] = &[
    (Permission::LabTemplateUse, Some("tpl-allowed/ver-1")),
    (Permission::LabLease, Some("lease-or-version")),
    (Permission::LabLeaseProvision, Some("lease-1")),
    (Permission::LabLeaseRead, Some("lease-1")),
    (Permission::LabLeaseRead, None),
    (Permission::LabExtend, Some("lease-1")),
    (Permission::LabExec, Some("lease-1")),
    (Permission::LabArtifacts, Some("lease-1")),
    (Permission::LabArtifactRead, None),
    (Permission::LabArtifactRead, Some("artifact-1")),
    (Permission::OperationCreate, Some("lab.provision")),
    (Permission::OperationCreate, Some("lab.exec")),
    (Permission::OperationCreate, Some("lab.collect")),
    (Permission::OperationCreate, Some("lab.cleanup")),
    (Permission::OperationRead, Some("op-1")),
];

#[test]
fn the_allowed_actions_are_exactly_the_lab_loop() {
    let authorizer = authorizer();
    for (action, resource) in ALLOWED {
        assert_eq!(
            decide(&authorizer, *action, *resource),
            Decision::allow(),
            "{action} on {resource:?} must be allowed"
        );
    }
}

#[test]
fn every_other_catalog_action_is_refused_whatever_the_resource() {
    let authorizer = authorizer();
    let allowed: Vec<Permission> = ALLOWED.iter().map(|(action, _)| *action).collect();
    for action in Permission::ALL.iter().filter(|a| !allowed.contains(a)) {
        for resource in [None, Some("anything"), Some("lease-1")] {
            assert_eq!(
                decide(&authorizer, *action, resource),
                Decision::deny(ReasonId::ActionNotDelegated),
                "{action} on {resource:?} must be refused"
            );
        }
    }
}

#[test]
fn the_catalog_table_and_the_allowed_list_agree() {
    let mut rows: Vec<&str> = DELEGATED_LAB_LOOP
        .iter()
        .map(|row| row.action.id())
        .collect();
    let mut expected: Vec<&str> = ALLOWED.iter().map(|(action, _)| action.id()).collect();
    rows.sort_unstable();
    rows.dedup();
    expected.sort_unstable();
    expected.dedup();
    assert_eq!(
        rows, expected,
        "a row without a test, or a test without a row"
    );
}

#[test]
fn the_named_refusals_of_the_issue_are_refused() {
    let authorizer = authorizer();
    let refused = [
        // keep
        (Permission::LabKeep, Some("lease-1")),
        // standalone provisioning: it leaves a VM no lease owns
        (Permission::LabProvision, Some("ver-pinned")),
        // machine exec outside Lab and the other machine mutations
        (Permission::MiseOperate, Some("machine-1")),
        (Permission::FrogenvOperate, Some("machine-1")),
        (Permission::ProjectsGitWrite, Some("machine-1")),
        (Permission::ApplyExecute, Some("machine-1")),
        (Permission::MachineDelete, Some("machine-1")),
        // secrets
        (Permission::SecretRead, Some("secret-1")),
        (Permission::SecretWrite, None),
        (Permission::SecretList, None),
        // templates, images, pools
        (Permission::LabConfig, None),
        (Permission::LabRead, None),
        (Permission::ImagesConfig, None),
        (Permission::ImagesRead, None),
        // Proxmox and settings administration
        (Permission::ProxmoxConfig, None),
        (Permission::ProxmoxOperate, None),
        (Permission::ProxmoxDestructive, None),
        (Permission::TailnetConfig, None),
        (Permission::SourceActivate, None),
        // administering Fleet and its credentials
        (Permission::NodeEnroll, Some("machine-1")),
        (Permission::AuditRead, None),
        (Permission::CredentialIssue, None),
        (Permission::CredentialRead, None),
        (Permission::CredentialRevoke, Some(CREDENTIAL)),
        (Permission::OperationCancel, Some("op-1")),
        (Permission::SystemRead, None),
        (Permission::EventsRead, None),
    ];
    for (action, resource) in refused {
        let decision = decide(&authorizer, action, resource);
        assert!(
            !decision.allowed,
            "{action} on {resource:?} must be refused"
        );
        assert_eq!(decision.reason, ReasonId::ActionNotDelegated);
    }
}

#[test]
fn template_use_is_decided_on_the_allow_list_of_the_presented_credential() {
    let authorizer = authorizer();
    // The allowed template: every version of it.
    assert!(
        decide(
            &authorizer,
            Permission::LabTemplateUse,
            Some("tpl-allowed/ver-new")
        )
        .allowed
    );
    // The pinned version of another template.
    assert!(
        decide(
            &authorizer,
            Permission::LabTemplateUse,
            Some("tpl-x/ver-pinned")
        )
        .allowed
    );
    // A template outside the allow-list, even one another credential of
    // the same owner may use.
    for resource in ["tpl-other/ver-1", "tpl-x/ver-x", "tpl-allowed", "/"] {
        let decision = decide(&authorizer, Permission::LabTemplateUse, Some(resource));
        assert_eq!(
            decision,
            Decision::deny(ReasonId::OutOfScope),
            "{resource} must be refused"
        );
    }
    assert_eq!(
        decide(&authorizer, Permission::LabTemplateUse, None),
        Decision::deny(ReasonId::OutOfScope)
    );
}

#[test]
fn a_principal_without_a_registered_grant_has_no_template_access() {
    let authorizer = ScopedAuthorizer::new(Arc::new(GrantBook::new()));
    assert_eq!(
        decide(
            &authorizer,
            Permission::LabTemplateUse,
            Some("tpl-allowed/ver-1")
        ),
        Decision::deny(ReasonId::OutOfScope)
    );
}

#[test]
fn resource_bound_rows_refuse_a_missing_or_wrong_resource() {
    let authorizer = authorizer();
    for action in [
        Permission::LabLease,
        Permission::LabLeaseProvision,
        Permission::LabExtend,
        Permission::LabExec,
        Permission::LabArtifacts,
        Permission::OperationRead,
    ] {
        assert_eq!(
            decide(&authorizer, action, None),
            Decision::deny(ReasonId::OutOfScope),
            "{action} needs a resource"
        );
    }
    // The retention sweep names a reserved resource.
    assert_eq!(
        decide(&authorizer, Permission::LabArtifacts, Some("retention")),
        Decision::deny(ReasonId::OutOfScope)
    );
    // Only the Lab kinds may be queued; the generic surface may not.
    for kind in [
        "machine.exec",
        "mise.exec",
        "proxmox.destroy",
        "lab.pool.fill",
        "",
    ] {
        assert_eq!(
            decide(&authorizer, Permission::OperationCreate, Some(kind)),
            Decision::deny(ReasonId::OutOfScope),
            "{kind:?} must not be queueable"
        );
    }
    assert_eq!(
        decide(&authorizer, Permission::OperationCreate, None),
        Decision::deny(ReasonId::OutOfScope)
    );
}

#[test]
fn administrators_keep_the_whole_catalog_and_credentials_get_nothing_from_it() {
    let authorizer = authorizer();
    for action in Permission::ALL {
        assert_eq!(
            authorizer.decide(AccessRequest {
                principal_id: LAN_PRINCIPAL_ID,
                action: *action,
                resource: Some("resource-1"),
            }),
            Decision::allow(),
            "{action} must stay allowed for the LAN principal"
        );
        assert_eq!(
            authorizer.decide(AccessRequest {
                principal_id: "tailscale:alice@example.com",
                action: *action,
                resource: Some("resource-1"),
            }),
            Decision::allow(),
        );
    }
}

#[test]
fn malformed_credential_principal_ids_are_not_delegated_and_not_administrators() {
    let authorizer = authorizer();
    for id in [
        "credential:",
        "credential:owner",
        "credential::id",
        "credential:owner:",
        "credentials:o:i",
    ] {
        assert!(!is_delegated_principal(id), "{id}");
        assert_eq!(
            authorizer.decide(AccessRequest {
                principal_id: id,
                action: Permission::SecretRead,
                resource: Some("x"),
            }),
            Decision::deny(ReasonId::UnknownPrincipal),
            "{id} must be refused as an unknown principal"
        );
    }
}

#[test]
fn owner_identity_is_shared_by_one_owners_credentials() {
    let first = delegated_principal_id("release-qa", "a");
    let second = delegated_principal_id("release-qa", "b");
    let other = delegated_principal_id("release-qa2", "a");
    assert_eq!(resource_owner(&first), "credential:release-qa");
    assert_eq!(resource_owner(&first), resource_owner(&second));
    assert!(owner_scope_permits(&second, "credential:release-qa"));
    assert!(!owner_scope_permits(&other, "credential:release-qa"));
    assert!(!owner_scope_permits(&first, LAN_PRINCIPAL_ID));
    assert!(!owner_scope_permits(&first, "credential:release"));
    // Administrators are decided by the catalog alone.
    assert!(owner_scope_permits(
        LAN_PRINCIPAL_ID,
        "credential:release-qa"
    ));
    assert_eq!(resource_owner(LAN_PRINCIPAL_ID), LAN_PRINCIPAL_ID);
}

#[test]
fn a_new_lab_action_is_one_catalog_row() {
    // A deployment-specific table: the loop plus one added row.
    static EXTENDED: &[DelegatedAction] = &[
        DelegatedAction {
            action: Permission::LabExec,
            resource: ResourceRule::Named,
        },
        DelegatedAction {
            action: Permission::LabKeep,
            resource: ResourceRule::OneOf(&["lease-9"]),
        },
    ];
    let authorizer = ScopedAuthorizer::with_catalog(Arc::new(GrantBook::new()), EXTENDED);
    assert!(decide(&authorizer, Permission::LabKeep, Some("lease-9")).allowed);
    assert!(!decide(&authorizer, Permission::LabKeep, Some("lease-8")).allowed);
    assert!(!decide(&authorizer, Permission::LabLease, Some("lease-8")).allowed);
}
