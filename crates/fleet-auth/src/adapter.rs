//! The trusted-LAN authorization adapter.
//!
//! The initial deployment grants the full permission catalog to the
//! `anonymous-lan-admin` principal. "Full" is defined honestly here: the
//! adapter permits exactly the actions in the application's catalog, for the
//! one principal it recognizes, and answers every other request with a stable
//! denial reason. It does not bypass the port — it is an implementation of
//! the port, so the later authenticated mode can replace it without any call
//! site changing.

use fleet_application::authz::{AccessRequest, Authorizer, Decision, ReasonId};

use crate::LAN_PRINCIPAL_ID;

/// Permits the full catalog to the anonymous LAN principal; denies everything
/// else with stable reasons. This is the explicit allow-all adapter: its
/// permissiveness is a reviewed property of the trusted-LAN deployment, not a
/// default that authentication must first undo.
#[derive(Debug)]
pub struct LanAllowAllAuthorizer;

impl Authorizer for LanAllowAllAuthorizer {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.principal_id != LAN_PRINCIPAL_ID {
            return Decision::deny(ReasonId::UnknownPrincipal);
        }
        // The action is in the request as a catalog type, so it cannot name
        // an action outside the catalog; the catalog rule on resources is
        // enforced by the application helper. Everything this principal asks
        // for is permitted — loudly, by the deployment's trust mode.
        Decision::allow()
    }
}
