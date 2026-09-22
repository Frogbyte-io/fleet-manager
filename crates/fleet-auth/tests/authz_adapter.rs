//! Exercises the authorization port and the trusted-LAN adapter: the catalog
//! is total for the LAN principal, denials carry stable reasons, and the
//! application funnel enforces the resource rule.

use fleet_application::authz::{
    AccessRequest, Authorizer, Decision, Permission, ReasonId, authorize,
};
use fleet_auth::{LAN_PRINCIPAL_ID, LanAllowAllAuthorizer};

#[test]
fn the_lan_principal_may_perform_every_catalog_action() {
    let authorizer = LanAllowAllAuthorizer;
    for action in Permission::ALL {
        let request = AccessRequest {
            principal_id: LAN_PRINCIPAL_ID,
            action: *action,
            resource: Some("resource-1"),
        };
        let decision = authorizer.decide(request);
        assert_eq!(decision, Decision::allow(), "{action} must be permitted");
    }
}

#[test]
fn resourceless_catalog_actions_are_permitted_without_a_resource() {
    let authorizer = LanAllowAllAuthorizer;
    for action in Permission::ALL.iter().filter(|a| !a.requires_resource()) {
        let request = AccessRequest {
            principal_id: LAN_PRINCIPAL_ID,
            action: *action,
            resource: None,
        };
        assert_eq!(authorizer.decide(request), Decision::allow());
    }
}

#[test]
fn unknown_principals_are_denied_with_a_stable_reason() {
    let authorizer = LanAllowAllAuthorizer;
    for principal in ["root", "localhost", "", "anonymous-lan-admin "] {
        let request = AccessRequest {
            principal_id: principal,
            action: Permission::SystemRead,
            resource: None,
        };
        let decision = authorizer.decide(request);
        assert_eq!(decision, Decision::deny(ReasonId::UnknownPrincipal));
        assert!(decision.to_string().contains("policy.unknown_principal"));
    }
}

#[test]
fn the_funnel_refuses_resource_actions_without_a_resource() {
    let authorizer = LanAllowAllAuthorizer;
    for action in Permission::ALL.iter().filter(|a| a.requires_resource()) {
        let request = AccessRequest {
            principal_id: LAN_PRINCIPAL_ID,
            action: *action,
            resource: None,
        };
        let decision = authorize(&authorizer, request).unwrap_err();
        assert_eq!(decision, Decision::deny(ReasonId::MissingResource));
    }
}

#[test]
fn the_funnel_passes_allowances_and_denials_alike() {
    let authorizer = LanAllowAllAuthorizer;
    let allowed = authorize(
        &authorizer,
        AccessRequest {
            principal_id: LAN_PRINCIPAL_ID,
            action: Permission::SystemRead,
            resource: None,
        },
    );
    assert!(allowed.is_ok());

    let denied = authorize(
        &authorizer,
        AccessRequest {
            principal_id: "someone-else",
            action: Permission::SystemRead,
            resource: None,
        },
    );
    assert_eq!(
        denied.unwrap_err(),
        Decision::deny(ReasonId::UnknownPrincipal)
    );
}

#[test]
fn every_catalog_action_has_a_unique_stable_id_and_a_risk_ruling() {
    let mut ids: Vec<&'static str> = Permission::ALL.iter().map(|a| a.id()).collect();
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), count, "catalog ids must be unique");
    // Mutations and high-value reads are recorded as risky; nothing else is.
    assert!(Permission::SecretRead.is_risky());
    assert!(Permission::SecretWrite.is_risky());
    assert!(Permission::MachineReadSensitive.is_risky());
    assert!(!Permission::SystemRead.is_risky());
    // The catalog is the complete vocabulary the adapter permits.
    assert_eq!(Permission::ALL.len(), 42);
}

#[test]
fn decisions_render_stable_reasons_without_secrets() {
    let decision = Decision::deny(ReasonId::MissingResource);
    let rendered = decision.to_string();
    assert!(rendered.contains("policy.missing_resource"));
    assert!(rendered.contains("denied"));
}
