//! Agent-requested persistent VMs (#496): the broker action that carries a
//! `machine.create` spec, the policy bounds that may auto-approve one, and
//! the request use case.
//!
//! A restricted agent cannot call the direct create (it lacks
//! `machines.provision`). It files an action request instead; the request
//! carries the validated spec, and the requesting principal and purpose are
//! stamped onto the spec when the operation is built, so the machine records
//! its owner. Approval runs #489's executor through the same
//! `machine.create` operation and review token as a direct create.
//!
//! # Policy
//!
//! The action's class is `approve`: everything waits for a person. An
//! operator may configure bounds ([`PersistentBounds`], the
//! `FLEET_PERSISTENT_AUTO_POLICY` variable); a request inside them is then
//! approved by policy. A bound the spec does not state (a template default
//! for cores, memory, disk, node or storage) cannot be shown to be inside
//! it, so the request needs a person. Bounds only widen `approve` to `auto`
//! for a request they admit; the operator's `FLEET_ACTION_POLICY` override
//! (including `deny`) always wins.
//!
//! # Secrets
//!
//! The parameters hold references and public keys only. A broker rejects
//! parameters with credential-like key names, so the spec's `credential`,
//! `secret` and `publicKey` keys travel under reference-style names
//! ([`to_parameters`] and [`from_parameters`] translate); a product key is
//! never a parameter, only the `machines/product-key/` id.
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{ActionRequestState, RiskClass};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Permission, authorize};
use crate::broker::{
    ActionRequest, ActionRequestPort, AutoGuard, Bounds, Broker, BrokerError, NewActionRequest,
    ProviderAction,
};
use crate::lab::LabUseCaseError;
use crate::operation::{NewOperation, review_token_for};
use crate::persistent::{CreateMachineSpec, PersistentMachines, RequestedBy};

/// The id of the action.
pub const ACTION_ID: &str = "proxmox.machine.create";
/// The operation kind it runs: #489's.
pub const OPERATION_KIND: &str = "machine.create";
/// The environment variable holding the auto-approval bounds as JSON.
pub const POLICY_VAR: &str = "FLEET_PERSISTENT_AUTO_POLICY";

/// The request states that count against a per-principal quota: a request
/// still waiting, on its way to run, running, or done.
const QUOTA_STATES: [ActionRequestState; 4] = [
    ActionRequestState::Pending,
    ActionRequestState::Approved,
    ActionRequestState::Executing,
    ActionRequestState::Succeeded,
];

/// The target a request names: `machine:<account>:<name>`.
#[must_use]
pub fn target_of(spec: &CreateMachineSpec) -> String {
    format!("machine:{}:{}", spec.account_id, spec.name)
}

/// The bounds inside which a persistent-VM request is approved by policy.
/// Every field is optional; with none set the feature is off and every
/// request needs a person.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersistentBounds {
    /// The most vCPU cores a request may state.
    #[serde(default)]
    pub max_cores: Option<u32>,
    /// The most memory, in MiB.
    #[serde(default)]
    pub max_memory_mib: Option<u32>,
    /// The largest boot disk, in GiB.
    #[serde(default)]
    pub max_disk_gib: Option<u32>,
    /// The image versions that may be requested; empty means any.
    #[serde(default)]
    pub image_versions: BTreeSet<String>,
    /// The nodes that may be requested; empty means any.
    #[serde(default)]
    pub nodes: BTreeSet<String>,
    /// The storages that may be requested; empty means any.
    #[serde(default)]
    pub storages: BTreeSet<String>,
    /// The most live requests one principal may have (pending, approved,
    /// running or succeeded). Machines destroyed later still count: the
    /// quota is a guard against a runaway agent, not an inventory.
    #[serde(default)]
    pub max_per_principal: Option<u32>,
}

impl PersistentBounds {
    /// Reads the variable's value; unset or blank is no bounds.
    ///
    /// # Errors
    ///
    /// Fails on malformed JSON or an unknown field, naming the variable: a
    /// typo in policy must stop startup, not silently drop a bound.
    pub fn from_env_value(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None => Ok(Self::default()),
            Some(text) => serde_json::from_str(text)
                .map_err(|error| format!("{POLICY_VAR} must be a JSON object of bounds: {error}")),
        }
    }

    /// Whether any bound is set.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        *self != Self::default()
    }

    /// Whether the spec is inside every static bound. A bound the spec does
    /// not state cannot be shown to hold, so it fails. A guest whose
    /// Proxmox protection is off is never auto-approved: a persistent VM is
    /// protected against deletion unless a person says otherwise.
    #[must_use]
    pub fn admits(&self, spec: &CreateMachineSpec) -> bool {
        let within = |limit: Option<u32>, value: Option<u32>| match limit {
            None => true,
            Some(limit) => value.is_some_and(|value| value <= limit),
        };
        let listed = |set: &BTreeSet<String>, value: Option<&str>| {
            set.is_empty() || value.is_some_and(|value| set.contains(value))
        };
        spec.protection
            && within(self.max_cores, spec.cores)
            && within(self.max_memory_mib, spec.memory_mib)
            && within(self.max_disk_gib, spec.disk_gib)
            && (self.image_versions.is_empty()
                || self.image_versions.contains(&spec.image_version_id))
            && listed(&self.nodes, spec.node.as_deref())
            && listed(&self.storages, spec.storage.as_deref())
    }
}

/// The broker action that creates a persistent machine.
pub struct PersistentCreateAction {
    bounds: PersistentBounds,
    requests: Option<Arc<dyn ActionRequestPort>>,
}

impl fmt::Debug for PersistentCreateAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentCreateAction")
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl PersistentCreateAction {
    /// The action. Without a request store the per-principal count cannot
    /// be read, so a configured quota then fails closed (needs a person).
    #[must_use]
    pub fn new(bounds: PersistentBounds, requests: Option<Arc<dyn ActionRequestPort>>) -> Self {
        Self { bounds, requests }
    }
}

#[async_trait]
impl AutoGuard for PersistentCreateAction {
    async fn assess(
        &self,
        requester: &str,
        parameters: &Value,
        except_request: Option<&str>,
    ) -> Result<Bounds, String> {
        if !self.bounds.is_configured() {
            return Ok(Bounds::Unconfigured);
        }
        let Ok(spec) = from_parameters(parameters) else {
            return Ok(Bounds::Outside);
        };
        if !self.bounds.admits(&spec) {
            return Ok(Bounds::Outside);
        }
        if let Some(max) = self.bounds.max_per_principal {
            let Some(requests) = &self.requests else {
                return Ok(Bounds::Outside);
            };
            let live = requests
                .count_for(requester, ACTION_ID, &QUOTA_STATES, except_request)
                .await?;
            if live >= max {
                return Ok(Bounds::Outside);
            }
        }
        Ok(Bounds::Within)
    }
}

impl ProviderAction for PersistentCreateAction {
    fn id(&self) -> &str {
        ACTION_ID
    }

    fn operation_kind(&self) -> &str {
        OPERATION_KIND
    }

    fn risk_class(&self) -> RiskClass {
        // ADR 0016: a permanent machine takes capacity indefinitely; a
        // person decides unless the operator configured bounds.
        RiskClass::Approve
    }

    fn validate(&self, target: &str, parameters: &Value) -> Result<(), String> {
        let spec = from_parameters(parameters)?;
        spec.validate()?;
        if spec.requested_by.is_some() {
            return Err("requestedBy is set by the broker, not by the request".to_owned());
        }
        if target_of(&spec) != target {
            return Err("the target must be machine:<account>:<name>".to_owned());
        }
        Ok(())
    }

    fn operation(&self, request: &ActionRequest) -> Result<NewOperation, String> {
        let mut spec = from_parameters(&request.parameters)?;
        spec.requested_by = Some(RequestedBy {
            principal: request.requester.clone(),
            purpose: request.reason.clone(),
            request_id: request.id.clone(),
        });
        spec.validate()?;
        let payload = spec.to_payload()?;
        let review_token = review_token_for(OPERATION_KIND, &payload);
        Ok(NewOperation {
            kind: OPERATION_KIND.to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(payload),
            review_token: Some(review_token),
        })
    }

    fn auto_guard(&self) -> Option<&dyn AutoGuard> {
        Some(self)
    }

    fn approver_permission(&self) -> Option<Permission> {
        Some(Permission::MachineProvision)
    }
}

/// Every persistent-machine action, for the controller's registry.
#[must_use]
pub fn persistent_actions(
    bounds: PersistentBounds,
    requests: Option<Arc<dyn ActionRequestPort>>,
) -> Vec<Arc<dyn ProviderAction>> {
    vec![Arc::new(PersistentCreateAction::new(bounds, requests))]
}

/// Renames the keys a broker would take for credentials. Each pair is
/// (path from the spec root, old key, new key).
const RENAMES: [(&[&str], &str, &str); 6] = [
    (&[], "credential", "sshKey"),
    (&["sshKey"], "credential", "reference"),
    (&["sshKey"], "publicKey", "authorizedKey"),
    (&["windows", "activation"], "secret", "productKeyRef"),
    (&["bootstrap", "auth"], "credential", "reference"),
    (&["windows"], "adminPassword", "localAdminPolicy"),
];

fn rename(value: &mut Value) {
    for (path, from, to) in RENAMES {
        // The path names the parent as it stands at that step: `sshKey` is
        // already renamed by the first entry.
        let mut node = Some(&mut *value);
        for step in path {
            node = node.and_then(|node| node.get_mut(*step));
        }
        if let Some(object) = node.and_then(Value::as_object_mut)
            && let Some(inner) = object.remove(from)
        {
            object.insert(to.to_owned(), inner);
        }
    }
}

/// The request parameters of a spec: its JSON with the credential-like key
/// names replaced by reference-style ones. The values are references and
/// public keys already.
#[must_use]
pub fn to_parameters(spec: &CreateMachineSpec) -> Value {
    let mut value = serde_json::to_value(spec).unwrap_or(Value::Null);
    rename(&mut value);
    value
}

/// The spec a request's parameters describe.
///
/// # Errors
///
/// Answers that the parameters are not a persistent machine spec.
pub fn from_parameters(parameters: &Value) -> Result<CreateMachineSpec, String> {
    let mut value = parameters.clone();
    // Going back, the parent path is the renamed one, so undo in reverse.
    for (path, from, to) in RENAMES.iter().rev() {
        let mut node = Some(&mut value);
        for step in *path {
            node = node.and_then(|node| node.get_mut(*step));
        }
        if let Some(object) = node.and_then(Value::as_object_mut)
            && let Some(inner) = object.remove(*to)
        {
            object.insert((*from).to_owned(), inner);
        }
    }
    serde_json::from_value(value).map_err(|error| {
        format!("the parameters are not a persistent machine spec; use POST /machines/create/request: {error}")
    })
}

/// What a caller asks for: a persistent machine and why.
#[derive(Clone, Debug)]
pub struct MachineRequest {
    /// The spec; it must not carry a `requestedBy` stamp.
    pub spec: CreateMachineSpec,
    /// Why the machine is needed. Recorded as the machine's purpose.
    pub purpose: String,
    /// The surface (`api`, `cli`).
    pub origin: String,
    /// The correlation id of the call.
    pub correlation_id: Option<String>,
    /// A key making a retry return the request already made.
    pub idempotency_key: Option<String>,
}

/// Why filing a request failed.
#[derive(Debug)]
pub enum RequestError {
    /// A spec rule, reference or promotion check, or a denial.
    Lab(LabUseCaseError),
    /// The broker refused or failed.
    Broker(BrokerError),
}

/// Files a request for a persistent machine: checks the spec and its
/// references as the review does, then records the broker request. The
/// permission is `action.request`; the machine is created only when the
/// request is approved, by a person or by policy bounds.
///
/// # Errors
///
/// Fails on denial, an invalid spec or purpose, an image that is not
/// promoted, a missing reference, a policy denial, or a backend failure.
pub async fn request_machine(
    machines: &PersistentMachines,
    broker: &Broker,
    authorizer: &dyn Authorizer,
    principal: &ActingPrincipal,
    request: MachineRequest,
    now: i64,
) -> Result<ActionRequest, RequestError> {
    authorize(
        authorizer,
        AccessRequest {
            principal_id: &principal.id,
            action: Permission::ActionRequest,
            resource: Some(ACTION_ID),
        },
    )
    .map_err(|decision| RequestError::Lab(LabUseCaseError::Denied(decision)))?;
    if request.spec.requested_by.is_some() {
        return Err(RequestError::Lab(LabUseCaseError::Invalid {
            detail: "requestedBy is set by the broker; a request cannot carry it".to_owned(),
        }));
    }
    if request.purpose.trim().is_empty() {
        return Err(RequestError::Lab(LabUseCaseError::Invalid {
            detail: "a persistent machine request needs a purpose".to_owned(),
        }));
    }
    machines
        .check_spec(&request.spec)
        .await
        .map_err(RequestError::Lab)?;
    broker
        .create(
            authorizer,
            &principal.id,
            NewActionRequest {
                action_id: ACTION_ID.to_owned(),
                target: target_of(&request.spec),
                parameters: to_parameters(&request.spec),
                reason: request.purpose,
                origin: request.origin,
                correlation_id: request.correlation_id,
                idempotency_key: request.idempotency_key,
            },
            now,
        )
        .await
        .map_err(RequestError::Broker)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(extra: &Value) -> CreateMachineSpec {
        let mut base = serde_json::json!({
            "accountId": "acct-1", "imageVersionId": "ver-1", "name": "build-box",
        });
        for (key, value) in extra.as_object().unwrap() {
            base[key] = value.clone();
        }
        serde_json::from_value(base).unwrap()
    }

    #[test]
    fn parameters_round_trip_and_hold_no_credential_like_key() {
        let original = spec(&serde_json::json!({
            "credential": {"type": "reference", "credential": "machines/ssh/abc"},
            "bootstrap": {"auth": {"type": "secret", "credential": "machines/ssh/boot"}},
            "guestOs": "windows",
            "windows": {"activation": {"type": "productKey", "secret": "machines/product-key/k1"}},
        }));
        let parameters = to_parameters(&original);
        assert!(!crate::broker::credential_like(&parameters), "{parameters}");
        assert_eq!(from_parameters(&parameters).unwrap(), original);
        let key = spec(&serde_json::json!({
            "credential": {"type": "publicKey", "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl a@b"},
        }));
        let parameters = to_parameters(&key);
        assert!(!crate::broker::credential_like(&parameters), "{parameters}");
        assert_eq!(from_parameters(&parameters).unwrap(), key);
    }

    #[test]
    fn bounds_admit_only_what_they_can_show_is_inside() {
        let bounds = PersistentBounds {
            max_cores: Some(4),
            max_memory_mib: Some(8192),
            max_disk_gib: Some(100),
            image_versions: ["ver-1".to_owned()].into(),
            nodes: ["pve1".to_owned()].into(),
            storages: BTreeSet::new(),
            max_per_principal: None,
        };
        let inside = serde_json::json!({
            "cores": 4, "memoryMib": 8192, "diskGib": 100, "node": "pve1",
        });
        assert!(bounds.admits(&spec(&inside)));
        for (key, value) in [
            ("cores", serde_json::json!(5)),
            ("memoryMib", serde_json::json!(8193)),
            ("diskGib", serde_json::json!(101)),
            ("node", serde_json::json!("pve2")),
            ("imageVersionId", serde_json::json!("ver-2")),
            ("protection", serde_json::json!(false)),
        ] {
            let mut over = inside.clone();
            over[key] = value;
            assert!(!bounds.admits(&spec(&over)), "{key}");
        }
        // A limit the spec leaves to the template default cannot be shown.
        for key in ["cores", "memoryMib", "diskGib", "node"] {
            let mut missing = inside.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(!bounds.admits(&spec(&missing)), "missing {key}");
        }
    }

    #[test]
    fn the_variable_parses_strictly() {
        assert!(
            !PersistentBounds::from_env_value(None)
                .unwrap()
                .is_configured()
        );
        assert!(
            !PersistentBounds::from_env_value(Some("  "))
                .unwrap()
                .is_configured()
        );
        let bounds =
            PersistentBounds::from_env_value(Some(r#"{"maxCores":2,"nodes":["pve1"]}"#)).unwrap();
        assert!(bounds.is_configured());
        assert_eq!(bounds.max_cores, Some(2));
        assert!(PersistentBounds::from_env_value(Some(r#"{"maxCore":2}"#)).is_err());
        assert!(PersistentBounds::from_env_value(Some("nope")).is_err());
    }

    #[test]
    fn the_action_stamps_the_requester_and_builds_the_reviewed_payload() {
        let action = PersistentCreateAction::new(PersistentBounds::default(), None);
        let parameters = to_parameters(&spec(&serde_json::json!({})));
        action
            .validate("machine:acct-1:build-box", &parameters)
            .unwrap();
        assert!(
            action
                .validate("machine:acct-1:other", &parameters)
                .is_err()
        );
        let request = ActionRequest {
            id: "req-1".to_owned(),
            requester: "credential:ci:c1".to_owned(),
            origin: "api".to_owned(),
            action_id: ACTION_ID.to_owned(),
            target: "machine:acct-1:build-box".to_owned(),
            parameters,
            risk_class: RiskClass::Approve,
            reason: "nightly build host".to_owned(),
            state: ActionRequestState::Approved,
            decided_by: Some("operator".to_owned()),
            decided_at: Some(1),
            decision_note: None,
            operation_id: None,
            failure: None,
            correlation_id: None,
            idempotency_key: None,
            created_at: 0,
            expires_at: 10,
            updated_at: 1,
        };
        let new = action.operation(&request).unwrap();
        let payload = new.payload_json.clone().unwrap();
        let stamped: CreateMachineSpec = serde_json::from_str(&payload).unwrap();
        let by = stamped.requested_by.unwrap();
        assert_eq!(by.principal, "credential:ci:c1");
        assert_eq!(by.purpose, "nightly build host");
        assert_eq!(by.request_id, "req-1");
        assert_eq!(
            new.review_token.unwrap(),
            review_token_for("machine.create", &payload)
        );
        // Deterministic, as recovery requires.
        assert_eq!(
            action.operation(&request).unwrap().payload_json.unwrap(),
            payload
        );
    }

    #[test]
    fn a_caller_cannot_forge_the_owner_stamp() {
        let action = PersistentCreateAction::new(PersistentBounds::default(), None);
        let mut forged = spec(&serde_json::json!({}));
        forged.requested_by = Some(RequestedBy {
            principal: "someone".to_owned(),
            purpose: "x".to_owned(),
            request_id: "r".to_owned(),
        });
        assert!(
            action
                .validate("machine:acct-1:build-box", &to_parameters(&forged))
                .is_err()
        );
    }
}
