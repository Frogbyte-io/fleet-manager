//! The trusted-LAN authorization adapter.
//!
//! The initial deployment grants the full permission catalog to the
//! `anonymous-lan-admin` principal and, when enabled, Tailscale Serve user
//! principals. "Full" is defined honestly here: the adapter permits exactly
//! the actions in the application's catalog for those validated principal
//! ids and answers every other request with a stable denial reason.

use fleet_application::authz::{AccessRequest, Authorizer, Decision, ReasonId};

use crate::{LAN_PRINCIPAL_ID, is_tailscale_principal_id};

/// Permits the full catalog to the anonymous LAN principal and validated
/// `tailscale:<login>` principals; denies everything else with stable reasons.
/// This explicit allow-all policy is shared by trusted-LAN and optional
/// Tailscale identity mode; it does not implement per-user roles.
#[derive(Debug)]
pub struct LanAllowAllAuthorizer;

impl Authorizer for LanAllowAllAuthorizer {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.principal_id != LAN_PRINCIPAL_ID
            && !is_tailscale_principal_id(request.principal_id)
        {
            return Decision::deny(ReasonId::UnknownPrincipal);
        }
        // The action is in the request as a catalog type, so it cannot name
        // an action outside the catalog; the catalog rule on resources is
        // enforced by the application helper. Everything this principal asks
        // for is permitted — loudly, by the deployment's trust mode.
        Decision::allow()
    }
}
