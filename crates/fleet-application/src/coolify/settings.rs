//! Coolify settings: environment variables, domains, and health checks
//! (FM-1034, ADR 0016).
//!
//! Every change is a brokered action request (risk class `approve`), never a
//! direct call. This module is the provider-neutral half:
//!
//! - the [`CoolifySettingsPort`] the provider crate implements (a separate
//!   mutating client; read discovery stays GET-only);
//! - the three [`ProviderAction`]s, `coolify.env.update`,
//!   `coolify.application.domains.set`, and
//!   `coolify.application.health.set`, which all run as one durable
//!   operation kind, [`SETTINGS_KIND`];
//! - [`CoolifySettings`], the use cases: the read view, filing a request with
//!   its preview, executing an approved request, and sweeping held values.
//!
//! # Scope
//!
//! Environment variables of applications and services. Domains and health
//! checks of applications only: a Coolify service keeps its domains per
//! sub-application, and an application built from a Compose file keeps them
//! per Compose service, so Fleet refuses `domains` there rather than guess.
//! A health check of type `cmd` (which runs a command inside the container)
//! is not offered. Shared (team, project, environment) variables, build
//! settings, resource limits, and storages are out of scope.
//!
//! # Environment variable values are write-only
//!
//! Coolify hides `value` and `real_value` from a token without
//! `read:sensitive`; Fleet never asks for that ability and its parser has no
//! value field, so a listing carries keys and flags only. A value written
//! through Fleet travels exactly one way:
//!
//! 1. the caller sends it with the filing call; it is validated and moved
//!    into the encrypted secret store as one *held value* record
//!    (`coolify-env-hold/<holdId>`, a [`HeldValueStore`]);
//! 2. the action request stores only key names, flags, and the `holdId`.
//!    There is no digest or any other function of a value in a request. The
//!    approver reads key names and flags, never a value;
//! 3. the record is *bound to its request*: the controller writes into it a
//!    hash of the request's canonical parameters (without the display-only
//!    name) and, once the broker has made the request, the request id. At
//!    execution both must match the operation's own, so a second request
//!    that copies a `holdId` (the parameters are public) cannot spend, read,
//!    or delete another request's values. A mismatch changes nothing and
//!    leaves the record alone. The executor then sends the values to Coolify
//!    and deletes the record on every exit;
//! 4. a held value whose request was denied or expired, or whose operation
//!    died before deleting it, is removed by [`CoolifySettings::sweep_held`].
//!
//! No value is in a request, an operation payload or result, an audit event,
//! a log line, or any response, and a Coolify failure on a value write
//! carries only its status, never Coolify's own text (which could quote the
//! input).
//!
//! # Preview and staleness
//!
//! The preview is computed from a read when the request is made and stored in
//! the parameters, so the approver sees what the requester saw. The action
//! refuses a preview whose field list is not the difference of its `before`
//! and `after`. [`CoolifySettings::execute`] reads again and refuses a
//! change whose `before` no longer holds, rather than overwrite what is
//! there now; a change already in place (a replay after a crash) is
//! accepted.
//!
//! # Redeploy
//!
//! A change may ask to be applied (`redeploy`): an application is
//! redeployed, a service restarted. It is part of the same operation, not a
//! second request, so one approval covers the change and its application,
//! there is one audit trail, and a redeploy can never run without the change
//! that was approved (a chained `auto` request would not be tied to it).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{IdGenerator as _, RiskClass, SensitiveString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::lifecycle::{
    CoolifyLifecycle, LifecycleError, LifecycleFailure, LifecycleResource, LifecycleVerb,
    bounded_name, parse_service_id, safe_id, service_id,
};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Permission, authorize};
use crate::broker::{
    ActionRequest, ActionRequestPort, Broker, BrokerError, NewActionRequest, ProviderAction,
};
use crate::dns::{FieldChange, PlanOp};
use crate::operation::NewOperation;
use fleet_core::ActionRequestState;

/// The operation kind every Coolify settings action runs as.
pub const SETTINGS_KIND: &str = "coolify.settings";
/// The action id that sets or unsets environment variables.
pub const ENV_ACTION: &str = "coolify.env.update";
/// The action id that replaces an application's domains.
pub const DOMAINS_ACTION: &str = "coolify.application.domains.set";
/// The action id that changes an application's health check.
pub const HEALTH_ACTION: &str = "coolify.application.health.set";
/// The most variables one request may change. The broker bounds parameters
/// to 8 KiB and each change appears twice (the change and its preview).
pub const MAX_ENV_CHANGES: usize = 8;
/// The longest variable name, in bytes (Coolify allows 255).
pub const MAX_ENV_KEY_LEN: usize = 128;
/// The longest variable value, in bytes.
pub const MAX_ENV_VALUE_BYTES: usize = 16 * 1024;
/// The most domains one application may be given.
pub const MAX_DOMAINS: usize = 12;
/// The longest domain URL, in bytes.
pub const MAX_DOMAIN_LEN: usize = 253;
/// How long a held value may exist before the sweep may remove it when no
/// live request names it: the time between storing it and filing the request.
pub const HOLD_GRACE_MILLIS: i64 = 10 * 60 * 1000;
/// The longest health-check text field, in bytes.
const MAX_HEALTH_TEXT: usize = 256;
/// The most requests the sweep reads per state before it gives up rather
/// than risk deleting the value of a request it did not see.
const SWEEP_PAGE: u32 = 500;
/// The most requests per state the sweep will read.
const SWEEP_MAX: u32 = 200_000;

// ---------------------------------------------------------------------
// The model.
// ---------------------------------------------------------------------

/// The flags of one environment variable, in Fleet's shape.
#[allow(clippy::struct_excessive_bools)] // Coolify's own five independent flags
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvFlags {
    /// Available while building (applications).
    pub is_buildtime: bool,
    /// Available at runtime (applications).
    pub is_runtime: bool,
    /// The value spans several lines.
    pub is_multiline: bool,
    /// The value is literal: nothing is escaped or expanded.
    pub is_literal: bool,
    /// Coolify hides the value after saving.
    pub is_shown_once: bool,
}

impl Default for EnvFlags {
    /// What Coolify gives a variable created without flags.
    fn default() -> Self {
        Self {
            is_buildtime: true,
            is_runtime: true,
            is_multiline: false,
            is_literal: false,
            is_shown_once: false,
        }
    }
}

impl EnvFlags {
    /// Whether two flag sets agree on everything Fleet sends to Coolify for
    /// `resource`. A service's variables have no build or runtime scope.
    #[must_use]
    pub fn same_for(&self, other: &Self, resource: LifecycleResource) -> bool {
        let scoped = resource == LifecycleResource::Application;
        (!scoped
            || (self.is_buildtime == other.is_buildtime && self.is_runtime == other.is_runtime))
            && self.is_multiline == other.is_multiline
            && self.is_literal == other.is_literal
            && self.is_shown_once == other.is_shown_once
    }

    fn fields(self) -> [(&'static str, Value); 5] {
        [
            ("isBuildtime", Value::Bool(self.is_buildtime)),
            ("isRuntime", Value::Bool(self.is_runtime)),
            ("isMultiline", Value::Bool(self.is_multiline)),
            ("isLiteral", Value::Bool(self.is_literal)),
            ("isShownOnce", Value::Bool(self.is_shown_once)),
        ]
    }
}

/// One variable as Coolify lists it to a token without `read:sensitive`:
/// the key and the flags. There is no value field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteEnv {
    /// Coolify's id for the variable (needed to delete it).
    pub uuid: String,
    /// The variable's name.
    pub key: String,
    /// Whether it belongs to preview deployments.
    pub is_preview: bool,
    /// Whether the value is a reference to a shared variable.
    pub is_shared: bool,
    /// The flags.
    pub flags: EnvFlags,
}

/// An application's health check (the HTTP kind), in Fleet's shape.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthSettings {
    /// `http`, or `cmd` for a command check Fleet shows but does not edit.
    #[serde(default = "default_check_type")]
    pub check_type: String,
    /// Whether Coolify runs the check.
    pub enabled: bool,
    /// The request path.
    pub path: String,
    /// The port, when not the application's own.
    #[serde(default)]
    pub port: Option<u16>,
    /// The host header, when set.
    #[serde(default)]
    pub host: Option<String>,
    /// The HTTP method.
    pub method: String,
    /// `http` or `https`.
    pub scheme: String,
    /// The status code that counts as healthy.
    pub return_code: u16,
    /// Text the response must contain, when set.
    #[serde(default)]
    pub response_text: Option<String>,
    /// Seconds between checks.
    pub interval: u32,
    /// Seconds a check may take.
    pub timeout: u32,
    /// Failures before the application is unhealthy.
    pub retries: u32,
    /// Seconds before the first check.
    pub start_period: u32,
}

fn default_check_type() -> String {
    "http".to_owned()
}

/// The health-check fields a request changes; absent fields stay.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthPatch {
    /// Turn the check on or off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// The request path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The host header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The HTTP method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// `http` or `https`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// The healthy status code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_code: Option<u16>,
    /// Text the response must contain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_text: Option<String>,
    /// Seconds between checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u32>,
    /// Seconds a check may take.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    /// Failures before unhealthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    /// Seconds before the first check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_period: Option<u32>,
    /// Fields to clear: `port`, `host`, `responseText`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clear: Vec<String>,
}

impl HealthPatch {
    /// Whether the patch changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Checks every present field against Coolify's own rules.
    ///
    /// # Errors
    ///
    /// Returns a caller-safe reason.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(path) = &self.path
            && (path.is_empty()
                || path.len() > MAX_HEALTH_TEXT
                || !path.starts_with('/')
                || !path
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/-_.~%,;".contains(c)))
        {
            return Err(
                "path must start with '/' and use only letters, digits, and /-_.~%,; (at most 256 bytes)"
                    .to_owned(),
            );
        }
        for name in &self.clear {
            let set = match name.as_str() {
                "port" => self.port.is_some(),
                "host" => self.host.is_some(),
                "responseText" => self.response_text.is_some(),
                _ => return Err("clear may name port, host, or responseText".to_owned()),
            };
            if set {
                return Err(format!("{name} is both set and cleared"));
            }
        }
        if self.port == Some(0) {
            return Err("port must be 1 to 65535".to_owned());
        }
        if let Some(host) = &self.host
            && (host.is_empty()
                || host.len() > MAX_DOMAIN_LEN
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)))
        {
            return Err("host must be a plain host name (letters, digits, - _ .)".to_owned());
        }
        if let Some(method) = &self.method
            && !matches!(method.as_str(), "GET" | "HEAD" | "POST" | "OPTIONS")
        {
            return Err("method must be GET, HEAD, POST, or OPTIONS".to_owned());
        }
        if let Some(scheme) = &self.scheme
            && !matches!(scheme.as_str(), "http" | "https")
        {
            return Err("scheme must be http or https".to_owned());
        }
        if let Some(code) = self.return_code
            && !(100..=599).contains(&code)
        {
            return Err("returnCode must be 100 to 599".to_owned());
        }
        if let Some(text) = &self.response_text
            && (text.is_empty()
                || text.len() > MAX_HEALTH_TEXT
                || text.chars().any(char::is_control))
        {
            return Err(
                "responseText must be 1 to 256 bytes with no control characters".to_owned(),
            );
        }
        for (name, value, min, max) in [
            ("interval", self.interval, 1, 3600),
            ("timeout", self.timeout, 1, 3600),
            ("retries", self.retries, 1, 100),
            ("startPeriod", self.start_period, 0, 3600),
        ] {
            if let Some(value) = value
                && !(min..=max).contains(&value)
            {
                return Err(format!("{name} must be {min} to {max}"));
            }
        }
        Ok(())
    }

    /// The settings after the patch.
    #[must_use]
    pub fn apply(&self, before: &HealthSettings) -> HealthSettings {
        HealthSettings {
            enabled: self.enabled.unwrap_or(before.enabled),
            path: self.path.clone().unwrap_or_else(|| before.path.clone()),
            check_type: before.check_type.clone(),
            port: if self.clear.iter().any(|n| n == "port") {
                None
            } else {
                self.port.or(before.port)
            },
            host: if self.clear.iter().any(|n| n == "host") {
                None
            } else {
                self.host.clone().or_else(|| before.host.clone())
            },
            method: self.method.clone().unwrap_or_else(|| before.method.clone()),
            scheme: self.scheme.clone().unwrap_or_else(|| before.scheme.clone()),
            return_code: self.return_code.unwrap_or(before.return_code),
            response_text: if self.clear.iter().any(|n| n == "responseText") {
                None
            } else {
                self.response_text
                    .clone()
                    .or_else(|| before.response_text.clone())
            },
            interval: self.interval.unwrap_or(before.interval),
            timeout: self.timeout.unwrap_or(before.timeout),
            retries: self.retries.unwrap_or(before.retries),
            start_period: self.start_period.unwrap_or(before.start_period),
        }
    }
}

/// An application as read for its settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteApplication {
    /// The build pack (`nixpacks`, `dockercompose`, ...).
    pub build_pack: String,
    /// The application's domains, in Coolify's order.
    pub domains: Vec<String>,
    /// The health check.
    pub health: HealthSettings,
}

/// What an application change writes. Absent parts stay.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApplicationPatch {
    /// The complete new domain list (an empty list clears the domains).
    pub domains: Option<Vec<String>>,
    /// Health-check fields to change.
    pub health: Option<HealthPatch>,
}

/// One variable write. The value is secret: it is redacted from `Debug` and
/// is only ever sent to Coolify.
#[derive(Debug)]
pub struct EnvWrite<'a> {
    /// The variable's name.
    pub key: &'a str,
    /// The value.
    pub value: &'a SensitiveString,
    /// Whether it belongs to preview deployments.
    pub is_preview: bool,
    /// The flags.
    pub flags: EnvFlags,
}

/// The mutating Coolify settings client port. The provider crate implements
/// it; it is a separate surface from the GET-only discovery source.
#[async_trait]
pub trait CoolifySettingsPort: fmt::Debug + Send + Sync {
    /// Lists a resource's variables: keys and flags, never values.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn read_envs(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
    ) -> Result<Vec<RemoteEnv>, LifecycleFailure>;

    /// Reads an application's domains and health check.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn read_application(
        &self,
        base_url: &str,
        token: &SensitiveString,
        uuid: &str,
    ) -> Result<RemoteApplication, LifecycleFailure>;

    /// Creates a variable that does not exist yet.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure that never quotes Coolify.
    async fn create_env(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
        write: &EnvWrite<'_>,
    ) -> Result<(), LifecycleFailure>;

    /// Updates an existing variable's value and flags.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure that never quotes Coolify.
    async fn update_env(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
        write: &EnvWrite<'_>,
    ) -> Result<(), LifecycleFailure>;

    /// Deletes a variable by its Coolify id.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn delete_env(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
        env_uuid: &str,
    ) -> Result<(), LifecycleFailure>;

    /// Changes an application's domains and health check.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn patch_application(
        &self,
        base_url: &str,
        token: &SensitiveString,
        uuid: &str,
        patch: &ApplicationPatch,
    ) -> Result<(), LifecycleFailure>;
}

/// Where a request's env values wait between filing and execution. The
/// composition root implements it over the encrypted secret store.
#[async_trait]
pub trait HeldValueStore: fmt::Debug + Send + Sync {
    /// Stores a record (a JSON object of change index to value), replacing
    /// any with the same id.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be written.
    async fn put(&self, hold_id: &str, document: &SensitiveString) -> Result<(), String>;
    /// Reads a record.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn get(&self, hold_id: &str) -> Result<Option<SensitiveString>, String>;
    /// Deletes a record; a missing one is not an error.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be written.
    async fn discard(&self, hold_id: &str) -> Result<(), String>;
    /// The ids of every held record.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn list(&self) -> Result<Vec<String>, String>;
}

// ---------------------------------------------------------------------
// Request parameters and the preview.
// ---------------------------------------------------------------------

/// What an environment change does to one variable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvOp {
    /// Create the variable or replace its value (and flags).
    Set,
    /// Remove the variable.
    Unset,
}

/// One variable change as stored in a request. There is no value: a `set`
/// carries nothing of it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvChange {
    /// Set or unset.
    pub op: EnvOp,
    /// The variable's name.
    pub key: String,
    /// Whether the change is to the preview-deployment variable.
    pub is_preview: bool,
    /// The flags the variable will have (`set` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<EnvFlags>,
}

/// One variable's preview: what it is now and what it will be.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvPreviewEntry {
    /// The variable's name.
    pub key: String,
    /// Whether it is the preview-deployment variable.
    pub is_preview: bool,
    /// What happens: `create`, `update`, or `delete`.
    pub operation: PlanOp,
    /// The flags now, when the variable exists.
    #[serde(default)]
    pub before: Option<EnvFlags>,
    /// The flags after, unless the variable is deleted.
    #[serde(default)]
    pub after: Option<EnvFlags>,
    /// The fields that differ. A written value shows as write-only.
    #[serde(default)]
    pub changes: Vec<FieldChange>,
}

/// The parameters of a `coolify.env.update` request, and (inside the
/// payload) of its operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvParameters {
    /// The Fleet external account that discovered the resource.
    pub account_id: String,
    /// The resource kind (application or service).
    pub resource_kind: LifecycleResource,
    /// The resource's Coolify uuid.
    pub uuid: String,
    /// The resource's name, for the approver.
    pub name: String,
    /// The held-value record, present when any change is a `set`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_id: Option<String>,
    /// The changes, in order.
    pub changes: Vec<EnvChange>,
    /// Redeploy (application) or restart (service) after the change.
    #[serde(default)]
    pub redeploy: bool,
    /// The preview, one entry per change.
    pub preview: Vec<EnvPreviewEntry>,
}

/// A preview of a whole-setting change (domains or health check).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preview<T> {
    /// The setting now.
    pub before: T,
    /// The setting after.
    pub after: T,
    /// The fields that differ; must be the difference of the two.
    pub changes: Vec<FieldChange>,
}

/// The parameters of a `coolify.application.domains.set` request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DomainsParameters {
    /// The Fleet external account that discovered the application.
    pub account_id: String,
    /// The resource kind (always an application).
    pub resource_kind: LifecycleResource,
    /// The application's Coolify uuid.
    pub uuid: String,
    /// The application's name, for the approver.
    pub name: String,
    /// The complete new domain list, normalized.
    pub domains: Vec<String>,
    /// Redeploy after the change.
    #[serde(default)]
    pub redeploy: bool,
    /// The preview.
    pub preview: Preview<Vec<String>>,
}

/// The parameters of a `coolify.application.health.set` request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthParameters {
    /// The Fleet external account that discovered the application.
    pub account_id: String,
    /// The resource kind (always an application).
    pub resource_kind: LifecycleResource,
    /// The application's Coolify uuid.
    pub uuid: String,
    /// The application's name, for the approver.
    pub name: String,
    /// The fields to change.
    pub patch: HealthPatch,
    /// Redeploy after the change.
    #[serde(default)]
    pub redeploy: bool,
    /// The preview.
    pub preview: Preview<HealthSettings>,
}

fn target_of(account_id: &str, uuid: &str) -> String {
    service_id(account_id, uuid)
}

/// The JSON round trip a stored preview takes: a null value reads back as
/// absent, so the difference a preview must carry is compared in that form.
fn normalized(changes: Vec<FieldChange>) -> Vec<FieldChange> {
    serde_json::to_value(changes)
        .and_then(serde_json::from_value)
        .unwrap_or_default()
}

fn value_marker(replaces: bool) -> FieldChange {
    FieldChange {
        field: "value".to_owned(),
        from: replaces.then(|| Value::String("(write-only)".to_owned())),
        to: Some(Value::String("(write-only)".to_owned())),
    }
}

/// The difference one variable's preview must carry.
fn env_entry_changes(
    before: Option<&EnvFlags>,
    after: Option<&EnvFlags>,
    writes_value: bool,
) -> Vec<FieldChange> {
    let mut changes: Vec<FieldChange> = match (before, after) {
        (Some(before), Some(after)) => before
            .fields()
            .into_iter()
            .zip(after.fields())
            .filter(|((_, from), (_, to))| from != to)
            .map(|((field, from), (_, to))| FieldChange {
                field: field.to_owned(),
                from: Some(from),
                to: Some(to),
            })
            .collect(),
        (None, Some(after)) => after
            .fields()
            .into_iter()
            .map(|(field, to)| FieldChange {
                field: field.to_owned(),
                from: None,
                to: Some(to),
            })
            .collect(),
        (Some(before), None) => before
            .fields()
            .into_iter()
            .map(|(field, from)| FieldChange {
                field: field.to_owned(),
                from: Some(from),
                to: None,
            })
            .collect(),
        (None, None) => Vec::new(),
    };
    if writes_value {
        changes.push(value_marker(before.is_some()));
    }
    normalized(changes)
}

fn domain_changes(before: &[String], after: &[String]) -> Vec<FieldChange> {
    if before == after {
        return Vec::new();
    }
    normalized(vec![FieldChange {
        field: "domains".to_owned(),
        from: Some(serde_json::json!(before)),
        to: Some(serde_json::json!(after)),
    }])
}

fn health_changes(before: &HealthSettings, after: &HealthSettings) -> Vec<FieldChange> {
    let (Ok(Value::Object(from)), Ok(Value::Object(to))) =
        (serde_json::to_value(before), serde_json::to_value(after))
    else {
        return Vec::new();
    };
    let mut names: BTreeSet<&String> = from.keys().collect();
    names.extend(to.keys());
    let changes = names
        .into_iter()
        .filter_map(|name| {
            let (before, after) = (from.get(name), to.get(name));
            (before != after).then(|| FieldChange {
                field: name.clone(),
                from: before.cloned(),
                to: after.cloned(),
            })
        })
        .collect();
    normalized(changes)
}

/// The record a held value lives in: the values, and what binds them to
/// exactly one request. Written by the controller only; it never leaves the
/// secret store except into the executor.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HeldRecord {
    /// SHA-256 of the request's canonical parameters without `name`.
    binding: String,
    /// The request this record belongs to; absent between storing and the
    /// broker's answer.
    #[serde(default)]
    request_id: Option<String>,
    /// Change index to value.
    values: BTreeMap<String, String>,
}

/// The hash a held record is bound to: the request's parameters (account,
/// kind, uuid, changes with flags, redeploy, preview, hold id) without the
/// display-only `name`.
fn binding_of(parameters: &Value) -> String {
    let mut canonical = parameters.clone();
    if let Some(object) = canonical.as_object_mut() {
        object.remove("name");
    }
    let mut hasher = Sha256::new();
    hasher.update(b"fleet-coolify-env-binding\0");
    hasher.update(canonical.to_string().as_bytes());
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Whether `key` is a Coolify-acceptable variable name (`routes` upstream:
/// `[A-Za-z_][A-Za-z0-9_.]*`), bounded.
fn valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    key.len() <= MAX_ENV_KEY_LEN
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Normalizes one domain URL: `http` or `https`, a plain host, an optional
/// port, an optional path; no credentials and none of the characters Coolify
/// refuses because they reach a shell.
///
/// # Errors
///
/// Returns a caller-safe reason.
pub fn normalize_domain(raw: &str) -> Result<String, String> {
    let url = raw.trim();
    if url.is_empty() || url.len() > MAX_DOMAIN_LEN {
        return Err(format!("a domain must be 1 to {MAX_DOMAIN_LEN} bytes"));
    }
    if url
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || "`$;&|<>()\\,".contains(c))
    {
        return Err("a domain has a character that is not allowed".to_owned());
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err("a domain must start with http:// or https://".to_owned());
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err("a domain must start with http:// or https://".to_owned());
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('@') {
        return Err("a domain must not carry credentials".to_owned());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            let number: u16 = port
                .parse()
                .map_err(|_| "the domain's port must be 1 to 65535".to_owned())?;
            if number == 0 {
                return Err("the domain's port must be 1 to 65535".to_owned());
            }
            (host, Some(number))
        }
        _ => (authority, None),
    };
    let host = crate::dns::normalize_hostname(host, false)
        .map_err(|reason| format!("the domain's host is invalid: {reason}"))?;
    let port = port.map_or_else(String::new, |port| format!(":{port}"));
    Ok(format!("{scheme}://{host}{port}{tail}"))
}

/// Normalizes a whole domain list: each entry valid, no duplicates, at most
/// [`MAX_DOMAINS`]. An empty list clears the domains.
///
/// # Errors
///
/// Returns a caller-safe reason.
pub fn normalize_domains(raw: &[String]) -> Result<Vec<String>, String> {
    if raw.len() > MAX_DOMAINS {
        return Err(format!("at most {MAX_DOMAINS} domains"));
    }
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for domain in raw {
        let domain = normalize_domain(domain)?;
        if out.contains(&domain) {
            return Err("a domain is listed twice".to_owned());
        }
        out.push(domain);
    }
    Ok(out)
}

fn check_subject(account_id: &str, uuid: &str, name: &str) -> Result<(), String> {
    if !safe_id(account_id) {
        return Err("accountId is not a valid id".to_owned());
    }
    if !safe_id(uuid) {
        return Err("uuid is not a valid Coolify uuid".to_owned());
    }
    if name.len() > 128 || name.chars().any(char::is_control) {
        return Err("name is too long or has control characters".to_owned());
    }
    Ok(())
}

fn validate_env(params: &EnvParameters) -> Result<(), String> {
    check_subject(&params.account_id, &params.uuid, &params.name)?;
    if params.resource_kind == LifecycleResource::Database {
        return Err("a database has no environment variables Fleet can change".to_owned());
    }
    if params.changes.is_empty() || params.changes.len() > MAX_ENV_CHANGES {
        return Err(format!(
            "a request changes 1 to {MAX_ENV_CHANGES} variables"
        ));
    }
    if params.preview.len() != params.changes.len() {
        return Err("the preview must have one entry per change; use the settings endpoint, which computes it".to_owned());
    }
    let any_set = params.changes.iter().any(|c| c.op == EnvOp::Set);
    match (&params.hold_id, any_set) {
        (Some(id), true) if safe_id(id) => {}
        (None, false) => {}
        _ => return Err("holdId must be present exactly when a variable is set".to_owned()),
    }
    let mut seen = BTreeSet::new();
    for (change, entry) in params.changes.iter().zip(&params.preview) {
        if !valid_env_key(&change.key) {
            return Err(
                "a variable name must be letters, digits, '_' and '.', not starting with a digit"
                    .to_owned(),
            );
        }
        if !seen.insert((change.key.as_str(), change.is_preview)) {
            return Err("a variable is changed twice".to_owned());
        }
        if params.resource_kind == LifecycleResource::Service && change.is_preview {
            return Err("a service has no preview variables".to_owned());
        }
        match change.op {
            EnvOp::Set => {
                if change.flags.is_none() {
                    return Err("a set carries its flags".to_owned());
                }
            }
            EnvOp::Unset => {
                if change.flags.is_some() {
                    return Err("an unset carries no flags".to_owned());
                }
            }
        }
        // The preview must be the difference of what it shows.
        let operation_ok = match (change.op, entry.operation) {
            (EnvOp::Set, PlanOp::Create) => entry.before.is_none(),
            (EnvOp::Set, PlanOp::Update) | (EnvOp::Unset, PlanOp::Delete) => entry.before.is_some(),
            _ => false,
        };
        if !operation_ok
            || entry.key != change.key
            || entry.is_preview != change.is_preview
            || entry.after != change.flags
            || entry.changes
                != env_entry_changes(
                    entry.before.as_ref(),
                    entry.after.as_ref(),
                    change.op == EnvOp::Set,
                )
        {
            return Err(
                "the preview is not the difference of the change; use the settings endpoint, which computes it"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn validate_domains(params: &DomainsParameters) -> Result<(), String> {
    check_subject(&params.account_id, &params.uuid, &params.name)?;
    if params.resource_kind != LifecycleResource::Application {
        return Err("only an application's domains can be changed".to_owned());
    }
    let normal = normalize_domains(&params.domains)?;
    if normal != params.domains || params.preview.after != params.domains {
        return Err("the domains must be normalized and equal the preview's after".to_owned());
    }
    if params.preview.before == params.preview.after
        || params.preview.changes != domain_changes(&params.preview.before, &params.preview.after)
    {
        return Err(
            "the preview is not the difference of the change; use the settings endpoint, which computes it"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_health(params: &HealthParameters) -> Result<(), String> {
    check_subject(&params.account_id, &params.uuid, &params.name)?;
    if params.resource_kind != LifecycleResource::Application {
        return Err("only an application's health check can be changed".to_owned());
    }
    if params.patch.is_empty() {
        return Err("the patch changes nothing".to_owned());
    }
    params.patch.validate()?;
    if params.patch.apply(&params.preview.before) != params.preview.after
        || params.preview.before == params.preview.after
        || params.preview.changes != health_changes(&params.preview.before, &params.preview.after)
    {
        return Err(
            "the preview is not the difference of the change; use the settings endpoint, which computes it"
                .to_owned(),
        );
    }
    Ok(())
}

/// Which setting an action or operation is about.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Setting {
    /// Environment variables.
    Env,
    /// Domains.
    Domains,
    /// The health check.
    Health,
}

impl Setting {
    const fn action_id(self) -> &'static str {
        match self {
            Self::Env => ENV_ACTION,
            Self::Domains => DOMAINS_ACTION,
            Self::Health => HEALTH_ACTION,
        }
    }

    /// The stable id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Domains => "domains",
            Self::Health => "health",
        }
    }
}

/// The operation payload: which setting, and its parameters. No value.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Payload {
    setting: Setting,
    parameters: Value,
    /// The request the operation carries out; a held value is only released
    /// to the request it was bound to.
    request_id: String,
}

/// One settings provider action.
#[derive(Debug)]
pub struct CoolifySettingsAction {
    setting: Setting,
}

impl CoolifySettingsAction {
    /// The action for `setting`.
    #[must_use]
    pub const fn new(setting: Setting) -> Self {
        Self { setting }
    }
}

/// Every settings action, for the controller's action registry.
#[must_use]
pub fn settings_actions() -> Vec<Arc<dyn ProviderAction>> {
    [Setting::Env, Setting::Domains, Setting::Health]
        .into_iter()
        .map(|setting| Arc::new(CoolifySettingsAction::new(setting)) as Arc<dyn ProviderAction>)
        .collect()
}

impl ProviderAction for CoolifySettingsAction {
    fn id(&self) -> &str {
        self.setting.action_id()
    }

    fn operation_kind(&self) -> &str {
        SETTINGS_KIND
    }

    fn risk_class(&self) -> RiskClass {
        // ADR 0016: a configuration change is `approve` by default.
        RiskClass::Approve
    }

    fn validate(&self, target: &str, parameters: &Value) -> Result<(), String> {
        let malformed = || {
            "the parameters are not a Coolify settings change; use POST /services/{id}/settings/..., which computes the preview"
                .to_owned()
        };
        let expected = match self.setting {
            Setting::Env => {
                let params: EnvParameters =
                    serde_json::from_value(parameters.clone()).map_err(|_| malformed())?;
                validate_env(&params)?;
                target_of(&params.account_id, &params.uuid)
            }
            Setting::Domains => {
                let params: DomainsParameters =
                    serde_json::from_value(parameters.clone()).map_err(|_| malformed())?;
                validate_domains(&params)?;
                target_of(&params.account_id, &params.uuid)
            }
            Setting::Health => {
                let params: HealthParameters =
                    serde_json::from_value(parameters.clone()).map_err(|_| malformed())?;
                validate_health(&params)?;
                target_of(&params.account_id, &params.uuid)
            }
        };
        if expected != target {
            return Err("the target must be the service id (coolify:<account>:<uuid>)".to_owned());
        }
        Ok(())
    }

    fn comparable_parameters(&self, parameters: &Value) -> Value {
        let mut comparable = parameters.clone();
        if let Some(object) = comparable.as_object_mut() {
            object.remove("name");
        }
        comparable
    }

    fn operation(&self, request: &ActionRequest) -> Result<NewOperation, String> {
        let payload = serde_json::to_string(&Payload {
            setting: self.setting,
            parameters: request.parameters.clone(),
            request_id: request.id.clone(),
        })
        .map_err(|_| "the payload could not be built".to_owned())?;
        Ok(NewOperation {
            kind: SETTINGS_KIND.to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(payload),
            review_token: None,
        })
    }
}

// ---------------------------------------------------------------------
// The use cases.
// ---------------------------------------------------------------------

/// A settings request shared fields.
#[derive(Clone, Debug)]
pub struct RequestMeta {
    /// The running-service id.
    pub service_id: String,
    /// Apply the change afterwards (redeploy an application, restart a
    /// service).
    pub redeploy: bool,
    /// Why, for the approver.
    pub reason: String,
    /// Where the request came from.
    pub origin: String,
    /// The correlation identity.
    pub correlation_id: Option<String>,
    /// A key making a retry return the request already made.
    pub idempotency_key: Option<String>,
}

/// Flag overrides of a `set`; an absent flag keeps what the variable has
/// (or Coolify's default for a new one).
#[derive(Clone, Copy, Debug, Default)]
pub struct EnvFlagOverrides {
    /// Build-time availability (applications).
    pub is_buildtime: Option<bool>,
    /// Runtime availability (applications).
    pub is_runtime: Option<bool>,
    /// Multiline value.
    pub is_multiline: Option<bool>,
    /// Literal value.
    pub is_literal: Option<bool>,
    /// Hide the value after saving.
    pub is_shown_once: Option<bool>,
}

/// One variable the caller wants changed.
#[derive(Debug)]
pub struct EnvChangeInput {
    /// Set or unset.
    pub op: EnvOp,
    /// The variable's name.
    pub key: String,
    /// Whether it is the preview-deployment variable.
    pub is_preview: bool,
    /// The new value (`set` only). Redacted from `Debug`.
    pub value: Option<SensitiveString>,
    /// Flag overrides (`set` only).
    pub flags: EnvFlagOverrides,
}

/// An environment change request.
#[derive(Debug)]
pub struct EnvRequest {
    /// The shared fields.
    pub meta: RequestMeta,
    /// The variables.
    pub changes: Vec<EnvChangeInput>,
}

/// A domains change request.
#[derive(Clone, Debug)]
pub struct DomainsRequest {
    /// The shared fields.
    pub meta: RequestMeta,
    /// The complete new domain list; empty clears.
    pub domains: Vec<String>,
}

/// A health-check change request.
#[derive(Clone, Debug)]
pub struct HealthRequest {
    /// The shared fields.
    pub meta: RequestMeta,
    /// The fields to change.
    pub patch: HealthPatch,
}

/// One variable as the view shows it: key and flags, never a value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvView {
    /// The name.
    pub key: String,
    /// Whether it is the preview-deployment variable.
    pub is_preview: bool,
    /// Whether the value refers to a shared variable.
    pub is_shared: bool,
    /// The flags.
    #[serde(flatten)]
    pub flags: EnvFlags,
}

/// A resource's settings, as the console and `fleetctl` show them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    /// The running-service id.
    pub service_id: String,
    /// The resource kind.
    pub resource_kind: LifecycleResource,
    /// The resource's name.
    pub name: String,
    /// The variables (keys and flags), when the kind has them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<EnvView>>,
    /// The domains, when Fleet can change them for this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
    /// The health check, when the kind has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthSettings>,
    /// What Fleet cannot show or change here, and why.
    pub notes: Vec<String>,
}

/// How a follow-up redeploy or restart went.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FollowUp {
    /// `redeploy` or `restart`.
    pub verb: String,
    /// The deployment Coolify queued, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_uuid: Option<String>,
    /// Why it did not happen, when the change was applied but this failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// An execution that did not finish: the failure text, and what had been
/// applied before it (names only), so a partial change is recorded rather
/// than lost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettingsFailure {
    /// The caller-safe failure text.
    pub message: String,
    /// What was applied before the failure, when anything was.
    pub partial: Option<Box<SettingsOutcome>>,
}

impl From<String> for SettingsFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            partial: None,
        }
    }
}

impl fmt::Display for SettingsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// How an executed settings change ended. Recorded as the operation result;
/// it carries names and field names, never a value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsOutcome {
    /// `env`, `domains`, or `health`.
    pub setting: String,
    /// `applied`, `unchanged` (everything was already in place), or
    /// `partial` (the change stopped part way; see `error` and `changed`).
    pub outcome: String,
    /// What changed: `set KEY`, `unset KEY`, `domains`, or the field names.
    pub changed: Vec<String>,
    /// Whether the change was read back from Coolify.
    pub verified: bool,
    /// The redeploy or restart that followed, when asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follow_up: Option<FollowUp>,
    /// Why a partial change stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The Coolify settings use cases.
#[derive(Debug)]
pub struct CoolifySettings {
    lifecycle: Arc<CoolifyLifecycle>,
    port: Arc<dyn CoolifySettingsPort>,
    holds: Arc<dyn HeldValueStore>,
    requests: Arc<dyn ActionRequestPort>,
}

fn invalid(detail: impl Into<String>) -> LifecycleError {
    LifecycleError::Invalid {
        detail: detail.into(),
    }
}

fn backend(context: &'static str) -> impl Fn(String) -> LifecycleError {
    move |detail| LifecycleError::Backend { context, detail }
}

fn provider(failure: LifecycleFailure) -> LifecycleError {
    LifecycleError::Provider(failure)
}

/// The error text of a failed execution step, never a backend detail.
fn step_error(error: LifecycleError) -> String {
    match error {
        LifecycleError::Backend { context, .. } => format!("{context} failed"),
        LifecycleError::NotFound { .. } => {
            "the resource is not in the account's latest Coolify observation; run discovery and re-file the request"
                .to_owned()
        }
        other => other.to_string(),
    }
}

fn stale(reason: &str) -> String {
    format!("the preview is stale: {reason}; nothing further was changed, so re-file the request")
}

impl CoolifySettings {
    /// Composes the use cases from the lifecycle use cases (which own the
    /// account, credential, and observation ports) and the settings ports.
    #[must_use]
    pub fn new(
        lifecycle: Arc<CoolifyLifecycle>,
        port: Arc<dyn CoolifySettingsPort>,
        holds: Arc<dyn HeldValueStore>,
        requests: Arc<dyn ActionRequestPort>,
    ) -> Self {
        Self {
            lifecycle,
            port,
            holds,
            requests,
        }
    }

    fn require_read(
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<(), LifecycleError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ExternalAccountRead,
                resource: None,
            },
        )
        .map(|_| ())
        .map_err(LifecycleError::Denied)
    }

    /// The resource a service id names, checked against the account's latest
    /// observation: its kind and name.
    async fn locate<'a>(
        &self,
        service_id: &'a str,
    ) -> Result<(&'a str, &'a str, LifecycleResource, String), LifecycleError> {
        let (account_id, uuid) = parse_service_id(service_id).ok_or_else(|| {
            invalid("the service id must be a Coolify service (coolify:<account>:<uuid>)")
        })?;
        self.lifecycle.coolify_account(account_id).await?;
        let (resource, name) = self.lifecycle.observed_resource(account_id, uuid).await?;
        Ok((account_id, uuid, resource, bounded_name(&name)))
    }

    /// Reads a resource's settings from Coolify: keys and flags, domains,
    /// and the health check. Needs `external_account.read`.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown resource, an unsupported Coolify version,
    /// or a provider failure.
    pub async fn view(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        service_id: &str,
    ) -> Result<SettingsView, LifecycleError> {
        Self::require_read(authorizer, principal)?;
        let (account_id, uuid, resource, name) = self.locate(service_id).await?;
        let (account, token) = self.lifecycle.resolve(account_id).await?;
        let base = account.base_url.as_str();
        self.lifecycle
            .require_supported_version(base, &token)
            .await
            .map_err(provider)?;
        let mut view = SettingsView {
            service_id: service_id.to_owned(),
            resource_kind: resource,
            name,
            env: None,
            domains: None,
            health: None,
            notes: Vec::new(),
        };
        match resource {
            LifecycleResource::Database => {
                view.notes
                    .push("Fleet changes no settings of a database".to_owned());
            }
            LifecycleResource::Service => {
                let envs = self
                    .port
                    .read_envs(base, &token, resource, uuid)
                    .await
                    .map_err(provider)?;
                view.env = Some(envs.iter().map(env_view).collect());
                note_duplicates(&envs, &mut view.notes);
                view.notes.push(
                    "a service keeps its domains per sub-application in Coolify; change them there"
                        .to_owned(),
                );
            }
            LifecycleResource::Application => {
                let envs = self
                    .port
                    .read_envs(base, &token, resource, uuid)
                    .await
                    .map_err(provider)?;
                view.env = Some(envs.iter().map(env_view).collect());
                note_duplicates(&envs, &mut view.notes);
                let application = self
                    .port
                    .read_application(base, &token, uuid)
                    .await
                    .map_err(provider)?;
                if application.build_pack == "dockercompose" {
                    view.notes.push(
                        "this application is built from a Compose file; its domains belong to its Compose services and are changed in Coolify"
                            .to_owned(),
                    );
                } else {
                    view.domains = Some(application.domains);
                }
                if application.health.check_type != "http" {
                    view.notes.push(
                        "this application has a command health check; Fleet shows it but does not edit it"
                            .to_owned(),
                    );
                }
                view.health = Some(application.health);
            }
        }
        Ok(view)
    }

    /// Files a request to set or unset environment variables. The values go
    /// to the encrypted secret store, bound to the request; the request holds
    /// key names and flags only.
    ///
    /// A retry with the requester's idempotency key returns the request
    /// already made before anything is read or stored.
    ///
    /// # Errors
    ///
    /// Fails on denial, invalid input, an unknown resource, a provider
    /// failure, a change that would do nothing, or a broker refusal.
    #[allow(clippy::too_many_lines)]
    pub async fn request_env(
        &self,
        broker: &Broker,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: EnvRequest,
        now: i64,
    ) -> Result<ActionRequest, LifecycleError> {
        Self::require_read(authorizer, principal)?;
        let EnvRequest { meta, changes } = request;
        if changes.is_empty() || changes.len() > MAX_ENV_CHANGES {
            return Err(invalid(format!(
                "a request changes 1 to {MAX_ENV_CHANGES} variables"
            )));
        }
        for change in &changes {
            if !valid_env_key(&change.key) {
                return Err(invalid(
                    "a variable name must be letters, digits, '_' and '.', and must not start with a digit",
                ));
            }
            match (change.op, &change.value) {
                (EnvOp::Set, Some(value)) => {
                    let text = value.expose();
                    // An empty value is allowed: Coolify stores it as blank.
                    if text.len() > MAX_ENV_VALUE_BYTES || text.contains('\0') {
                        return Err(invalid(format!(
                            "a value is at most {MAX_ENV_VALUE_BYTES} bytes with no NUL"
                        )));
                    }
                }
                (EnvOp::Set, None) => return Err(invalid("a set needs a value")),
                (EnvOp::Unset, Some(_)) => return Err(invalid("an unset carries no value")),
                (EnvOp::Unset, None) => {}
            }
        }
        let (account_id, uuid, resource, name) = self.locate(&meta.service_id).await?;
        if resource == LifecycleResource::Database {
            return Err(invalid(
                "a database has no environment variables Fleet can change",
            ));
        }
        if resource == LifecycleResource::Service
            && changes.iter().any(|change| {
                change.is_preview
                    || change.flags.is_buildtime.is_some()
                    || change.flags.is_runtime.is_some()
            })
        {
            return Err(invalid(
                "a service has no preview variables and no build or runtime scope",
            ));
        }
        if let Some(key) = meta.idempotency_key.as_deref()
            && let Some(existing) = broker
                .existing_for_key(authorizer, &principal.id, key, now)
                .await
                .map_err(LifecycleError::Broker)?
        {
            return self.replay_env(existing, &changes, &meta).await;
        }
        let (account, token) = self.lifecycle.resolve(account_id).await?;
        let base = account.base_url.as_str();
        self.lifecycle
            .require_supported_version(base, &token)
            .await
            .map_err(provider)?;
        let current = self
            .port
            .read_envs(base, &token, resource, uuid)
            .await
            .map_err(provider)?;
        // Coolify can hold a variable twice (a name and a preview flag); a
        // request cannot say which one it means, so it is refused.
        for change in &changes {
            let count = current
                .iter()
                .filter(|env| env.key == change.key && env.is_preview == change.is_preview)
                .count();
            if count > 1 {
                return Err(invalid(format!(
                    "{} appears more than once in Coolify; resolve the duplicate there first",
                    change.key
                )));
            }
        }
        let hold_id = fleet_core::UuidV7Generator.next_resource_id().to_string();
        let mut stored: Vec<EnvChange> = Vec::with_capacity(changes.len());
        let mut preview: Vec<EnvPreviewEntry> = Vec::with_capacity(changes.len());
        let mut held: BTreeMap<String, String> = BTreeMap::new();
        for (index, change) in changes.iter().enumerate() {
            let now_env = current
                .iter()
                .find(|env| env.key == change.key && env.is_preview == change.is_preview);
            let before = now_env.map(|env| env.flags);
            match change.op {
                EnvOp::Set => {
                    let base_flags = before.unwrap_or_default();
                    let after = EnvFlags {
                        is_buildtime: change.flags.is_buildtime.unwrap_or(base_flags.is_buildtime),
                        is_runtime: change.flags.is_runtime.unwrap_or(base_flags.is_runtime),
                        is_multiline: change.flags.is_multiline.unwrap_or(base_flags.is_multiline),
                        is_literal: change.flags.is_literal.unwrap_or(base_flags.is_literal),
                        is_shown_once: change
                            .flags
                            .is_shown_once
                            .unwrap_or(base_flags.is_shown_once),
                    };
                    let value = change
                        .value
                        .as_ref()
                        .map(SensitiveString::expose)
                        .unwrap_or_default();
                    held.insert(index.to_string(), value.to_owned());
                    preview.push(EnvPreviewEntry {
                        key: change.key.clone(),
                        is_preview: change.is_preview,
                        operation: if before.is_some() {
                            PlanOp::Update
                        } else {
                            PlanOp::Create
                        },
                        before,
                        after: Some(after),
                        changes: env_entry_changes(before.as_ref(), Some(&after), true),
                    });
                    stored.push(EnvChange {
                        op: EnvOp::Set,
                        key: change.key.clone(),
                        is_preview: change.is_preview,
                        flags: Some(after),
                    });
                }
                EnvOp::Unset => {
                    let Some(before) = before else {
                        return Err(LifecycleError::NotFound {
                            what: format!(
                                "the variable {}{}",
                                change.key,
                                if change.is_preview { " (preview)" } else { "" }
                            ),
                        });
                    };
                    preview.push(EnvPreviewEntry {
                        key: change.key.clone(),
                        is_preview: change.is_preview,
                        operation: PlanOp::Delete,
                        before: Some(before),
                        after: None,
                        changes: env_entry_changes(Some(&before), None, false),
                    });
                    stored.push(EnvChange {
                        op: EnvOp::Unset,
                        key: change.key.clone(),
                        is_preview: change.is_preview,
                        flags: None,
                    });
                }
            }
        }
        let hold_id = (!held.is_empty()).then_some(hold_id);
        let params = EnvParameters {
            account_id: account_id.to_owned(),
            resource_kind: resource,
            uuid: uuid.to_owned(),
            name,
            hold_id: hold_id.clone(),
            changes: stored,
            redeploy: meta.redeploy,
            preview,
        };
        let target = target_of(account_id, uuid);
        let parameters =
            serde_json::to_value(&params).map_err(|error| LifecycleError::Backend {
                context: "parameters",
                detail: error.to_string(),
            })?;
        // The broker's own checks run before a value is stored, so a refused
        // request leaves nothing behind.
        let action = CoolifySettingsAction::new(Setting::Env);
        action
            .validate(&target, &parameters)
            .map_err(|detail| LifecycleError::Broker(BrokerError::Invalid { detail }))?;
        let _ = self.sweep_held(now).await;
        let binding = binding_of(&parameters);
        if let Some(hold_id) = &hold_id {
            self.store_held(hold_id, &binding, None, held.clone())
                .await?;
        }
        let created = broker
            .create(
                authorizer,
                &principal.id,
                NewActionRequest {
                    action_id: ENV_ACTION.to_owned(),
                    target,
                    parameters,
                    reason: meta.reason,
                    origin: meta.origin,
                    correlation_id: meta.correlation_id,
                    idempotency_key: meta.idempotency_key,
                },
                now,
            )
            .await;
        match created {
            Ok(request) => {
                if let Some(hold_id) = &hold_id {
                    if request.parameters.get("holdId").and_then(Value::as_str)
                        == Some(hold_id.as_str())
                    {
                        // Bind the record to the request the broker made. A
                        // record that cannot be bound is refused at
                        // execution, so a failure here is reported.
                        if let Err(error) = self
                            .store_held(hold_id, &binding, Some(request.id.clone()), held)
                            .await
                        {
                            // No orphan: the request cannot run without its
                            // values, so it is withdrawn now (a system denial, audited) and the
                            // hold deleted.
                            let _ = broker
                                .abandon(&request, "hold could not be bound", now)
                                .await;
                            let _ = self.holds.discard(hold_id).await;
                            return Err(error);
                        }
                    } else {
                        // A concurrent retry won: that request holds its own
                        // record, so ours is not needed.
                        let _ = self.holds.discard(hold_id).await;
                    }
                }
                Ok(request)
            }
            Err(error) => {
                if let Some(hold_id) = &hold_id {
                    let _ = self.holds.discard(hold_id).await;
                }
                Err(LifecycleError::Broker(error))
            }
        }
    }

    async fn store_held(
        &self,
        hold_id: &str,
        binding: &str,
        request_id: Option<String>,
        values: BTreeMap<String, String>,
    ) -> Result<(), LifecycleError> {
        let record = HeldRecord {
            binding: binding.to_owned(),
            request_id,
            values,
        };
        let document = SensitiveString::new(serde_json::to_string(&record).map_err(|error| {
            LifecycleError::Backend {
                context: "held values",
                detail: error.to_string(),
            }
        })?);
        self.holds
            .put(hold_id, &document)
            .await
            .map_err(backend("held values"))
    }

    /// A retry of an environment request: the same request when the keys,
    /// operations, and flags agree and each value equals the one still held.
    /// When the held record is gone (the request already ran) only the
    /// structure is compared.
    async fn replay_env(
        &self,
        existing: ActionRequest,
        changes: &[EnvChangeInput],
        meta: &RequestMeta,
    ) -> Result<ActionRequest, LifecycleError> {
        let Ok(stored) = serde_json::from_value::<EnvParameters>(existing.parameters.clone())
        else {
            return Err(key_conflict(&existing));
        };
        let held: Option<HeldRecord> = match &stored.hold_id {
            Some(id) => self
                .holds
                .get(id)
                .await
                .map_err(backend("held values"))?
                .and_then(|document| serde_json::from_str(document.expose()).ok()),
            None => None,
        };
        let mut same = existing.action_id == ENV_ACTION
            && existing.target == meta.service_id
            && stored.redeploy == meta.redeploy
            && stored.changes.len() == changes.len();
        if same {
            for (index, (have, want)) in stored.changes.iter().zip(changes).enumerate() {
                let flags_agree =
                    flag_agrees(want.flags.is_buildtime, have.flags, |f| f.is_buildtime)
                        && flag_agrees(want.flags.is_runtime, have.flags, |f| f.is_runtime)
                        && flag_agrees(want.flags.is_multiline, have.flags, |f| f.is_multiline)
                        && flag_agrees(want.flags.is_literal, have.flags, |f| f.is_literal)
                        && flag_agrees(want.flags.is_shown_once, have.flags, |f| f.is_shown_once);
                let value_agrees = match (&want.value, &held) {
                    (Some(value), Some(record)) => {
                        record.values.get(&index.to_string()).map(String::as_str)
                            == Some(value.expose())
                    }
                    (Some(_), None) => have.op == EnvOp::Set,
                    (None, _) => have.op == EnvOp::Unset,
                };
                same &= have.op == want.op
                    && have.key == want.key
                    && have.is_preview == want.is_preview
                    && flags_agree
                    && value_agrees;
            }
        }
        if same {
            Ok(existing)
        } else {
            Err(key_conflict(&existing))
        }
    }

    /// Files a request to replace an application's domains, with a preview
    /// of the difference.
    ///
    /// # Errors
    ///
    /// Fails on denial, invalid domains, an unknown or non-application
    /// resource, a Compose application, a change that would do nothing, a
    /// provider failure, or a broker refusal.
    pub async fn request_domains(
        &self,
        broker: &Broker,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: DomainsRequest,
        now: i64,
    ) -> Result<ActionRequest, LifecycleError> {
        Self::require_read(authorizer, principal)?;
        let DomainsRequest { meta, domains } = request;
        let domains = normalize_domains(&domains).map_err(invalid)?;
        let (account_id, uuid, resource, name) = self.locate(&meta.service_id).await?;
        require_application(resource, "domains")?;
        if let Some(key) = meta.idempotency_key.as_deref()
            && let Some(existing) = broker
                .existing_for_key(authorizer, &principal.id, key, now)
                .await
                .map_err(LifecycleError::Broker)?
        {
            let same = serde_json::from_value::<DomainsParameters>(existing.parameters.clone())
                .is_ok_and(|stored| {
                    existing.action_id == DOMAINS_ACTION
                        && existing.target == target_of(account_id, uuid)
                        && stored.domains == domains
                        && stored.redeploy == meta.redeploy
                });
            return if same {
                Ok(existing)
            } else {
                Err(key_conflict(&existing))
            };
        }
        let current = self.read_application(account_id, uuid).await?;
        if current.build_pack == "dockercompose" {
            return Err(invalid(
                "this application is built from a Compose file; its domains belong to its Compose services and are changed in Coolify",
            ));
        }
        let before: Vec<String> = current.domains.iter().map(|d| lenient(d)).collect();
        if before == domains {
            return Err(invalid(
                "the domains already match; there is nothing to change",
            ));
        }
        let params = DomainsParameters {
            account_id: account_id.to_owned(),
            resource_kind: resource,
            uuid: uuid.to_owned(),
            name,
            domains: domains.clone(),
            redeploy: meta.redeploy,
            preview: Preview {
                changes: domain_changes(&before, &domains),
                before,
                after: domains,
            },
        };
        self.file(
            broker,
            authorizer,
            principal,
            DOMAINS_ACTION,
            &params,
            meta,
            now,
        )
        .await
    }

    /// Files a request to change an application's health check, with a
    /// preview of the difference.
    ///
    /// # Errors
    ///
    /// Fails on denial, invalid fields, an unknown or non-application
    /// resource, a change that would do nothing, a provider failure, or a
    /// broker refusal.
    pub async fn request_health(
        &self,
        broker: &Broker,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: HealthRequest,
        now: i64,
    ) -> Result<ActionRequest, LifecycleError> {
        Self::require_read(authorizer, principal)?;
        let HealthRequest { meta, patch } = request;
        if patch.is_empty() {
            return Err(invalid("name at least one health-check field to change"));
        }
        patch.validate().map_err(invalid)?;
        let (account_id, uuid, resource, name) = self.locate(&meta.service_id).await?;
        require_application(resource, "health check")?;
        if let Some(key) = meta.idempotency_key.as_deref()
            && let Some(existing) = broker
                .existing_for_key(authorizer, &principal.id, key, now)
                .await
                .map_err(LifecycleError::Broker)?
        {
            let same = serde_json::from_value::<HealthParameters>(existing.parameters.clone())
                .is_ok_and(|stored| {
                    existing.action_id == HEALTH_ACTION
                        && existing.target == target_of(account_id, uuid)
                        && stored.patch == patch
                        && stored.redeploy == meta.redeploy
                });
            return if same {
                Ok(existing)
            } else {
                Err(key_conflict(&existing))
            };
        }
        let current = self.read_application(account_id, uuid).await?;
        if current.health.check_type != "http" {
            return Err(invalid(
                "this application has a command health check, which Fleet shows but does not edit; change it in Coolify",
            ));
        }
        let after = patch.apply(&current.health);
        if after == current.health {
            return Err(invalid(
                "the health check already matches; there is nothing to change",
            ));
        }
        let params = HealthParameters {
            account_id: account_id.to_owned(),
            resource_kind: resource,
            uuid: uuid.to_owned(),
            name,
            patch,
            redeploy: meta.redeploy,
            preview: Preview {
                changes: health_changes(&current.health, &after),
                before: current.health,
                after,
            },
        };
        self.file(
            broker,
            authorizer,
            principal,
            HEALTH_ACTION,
            &params,
            meta,
            now,
        )
        .await
    }

    async fn read_application(
        &self,
        account_id: &str,
        uuid: &str,
    ) -> Result<RemoteApplication, LifecycleError> {
        let (account, token) = self.lifecycle.resolve(account_id).await?;
        let base = account.base_url.as_str();
        self.lifecycle
            .require_supported_version(base, &token)
            .await
            .map_err(provider)?;
        self.port
            .read_application(base, &token, uuid)
            .await
            .map_err(provider)
    }

    #[allow(clippy::too_many_arguments)]
    async fn file<P: Serialize>(
        &self,
        broker: &Broker,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        action_id: &str,
        params: &P,
        meta: RequestMeta,
        now: i64,
    ) -> Result<ActionRequest, LifecycleError> {
        let parameters = serde_json::to_value(params).map_err(|error| LifecycleError::Backend {
            context: "parameters",
            detail: error.to_string(),
        })?;
        let target = meta.service_id.clone();
        broker
            .create(
                authorizer,
                &principal.id,
                NewActionRequest {
                    action_id: action_id.to_owned(),
                    target,
                    parameters,
                    reason: meta.reason,
                    origin: meta.origin,
                    correlation_id: meta.correlation_id,
                    idempotency_key: meta.idempotency_key,
                },
                now,
            )
            .await
            .map_err(LifecycleError::Broker)
    }

    /// Runs an approved settings request: the operation executor calls this
    /// with the operation's kind and payload. It checks the request against
    /// the latest observation, reads Coolify again, refuses a stale preview,
    /// applies the change, reads it back, and (when asked) redeploys. A held
    /// value is deleted on every exit.
    ///
    /// # Errors
    ///
    /// Fails with a caller-safe reason: a malformed payload, a request that
    /// no longer matches the observation, a stale preview, a held value that
    /// is gone or not bound to this request, an unsupported Coolify version,
    /// a provider failure, or a read-back that differs. A change that stopped
    /// part way, or whose redeploy failed, carries what was applied.
    pub async fn execute(
        &self,
        kind: &str,
        payload: &str,
    ) -> Result<SettingsOutcome, SettingsFailure> {
        if kind != SETTINGS_KIND {
            return Err(format!("{kind} is not a Coolify settings operation").into());
        }
        let payload: Payload = serde_json::from_str(payload)
            .map_err(|_| "the operation payload is not a Coolify settings request".to_owned())?;
        let action = CoolifySettingsAction::new(payload.setting);
        // The same validation the broker applied when the request was made.
        let target = match payload.setting {
            Setting::Env => serde_json::from_value::<EnvParameters>(payload.parameters.clone())
                .map(|p| target_of(&p.account_id, &p.uuid)),
            Setting::Domains => {
                serde_json::from_value::<DomainsParameters>(payload.parameters.clone())
                    .map(|p| target_of(&p.account_id, &p.uuid))
            }
            Setting::Health => {
                serde_json::from_value::<HealthParameters>(payload.parameters.clone())
                    .map(|p| target_of(&p.account_id, &p.uuid))
            }
        }
        .map_err(|_| "the operation payload is not a Coolify settings request".to_owned())?;
        action.validate(&target, &payload.parameters)?;
        match payload.setting {
            Setting::Env => {
                let params: EnvParameters = serde_json::from_value(payload.parameters.clone())
                    .map_err(|_| "the payload is malformed".to_owned())?;
                let mut owned = false;
                let result = self
                    .execute_env(
                        &params,
                        &payload.parameters,
                        &payload.request_id,
                        &mut owned,
                    )
                    .await;
                // On every exit after the record was proved to be this
                // request's, its values go. A record that is not this
                // request's is left for the request it belongs to.
                if owned && let Some(hold_id) = &params.hold_id {
                    let _ = self.holds.discard(hold_id).await;
                }
                let _ = self.sweep_held(now_millis()).await;
                result
            }
            Setting::Domains => {
                let params: DomainsParameters = serde_json::from_value(payload.parameters)
                    .map_err(|_| "the payload is malformed".to_owned())?;
                self.execute_domains(&params).await
            }
            Setting::Health => {
                let params: HealthParameters = serde_json::from_value(payload.parameters)
                    .map_err(|_| "the payload is malformed".to_owned())?;
                self.execute_health(&params).await
            }
        }
    }

    /// What the approver read must still be true: the uuid is in the
    /// account's latest observation with the same kind and name.
    async fn recheck(
        &self,
        account_id: &str,
        uuid: &str,
        kind: LifecycleResource,
        name: &str,
    ) -> Result<(), String> {
        let (observed, observed_name) = self
            .lifecycle
            .observed_resource(account_id, uuid)
            .await
            .map_err(step_error)?;
        if observed != kind || bounded_name(&observed_name) != name {
            return Err(
                "the request no longer matches the latest Coolify observation (the resource's kind or name differs); nothing was changed, so re-file the request"
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// Loads the held record and proves it is this request's: its binding
    /// is the hash of this request's parameters and its request id is this
    /// request's. The id is bound just after the broker answers, so a
    /// request that runs at once (an `auto` policy) waits briefly for it.
    async fn claim_held(
        &self,
        hold_id: &str,
        parameters: &Value,
        request_id: &str,
    ) -> Result<BTreeMap<String, String>, String> {
        let mut attempts = 0;
        loop {
            let document = self
                .holds
                .get(hold_id)
                .await
                .map_err(|_| "held values failed".to_owned())?
                .ok_or_else(|| {
                    "the held values for this request are gone (already used, expired, or removed); nothing was changed, so re-file the request"
                        .to_owned()
                })?;
            let record: HeldRecord = serde_json::from_str(document.expose())
                .map_err(|_| "the held values are unreadable; re-file the request".to_owned())?;
            if record.binding != binding_of(parameters) {
                return Err(
                    "the held values are not bound to this request; nothing was changed".to_owned(),
                );
            }
            match record.request_id.as_deref() {
                Some(id) if id == request_id => return Ok(record.values),
                Some(_) => {
                    return Err(
                        "the held values belong to another request; nothing was changed".to_owned(),
                    );
                }
                None if attempts < 10 => {
                    attempts += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
                None => {
                    return Err(
                        "the held values were never bound to a request; nothing was changed, so re-file the request"
                            .to_owned(),
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_env(
        &self,
        params: &EnvParameters,
        parameters: &Value,
        request_id: &str,
        owned: &mut bool,
    ) -> Result<SettingsOutcome, SettingsFailure> {
        // The held values come first: a request whose values are gone, or are
        // not its own, cannot run and must not touch Coolify.
        let mut values: BTreeMap<String, String> = BTreeMap::new();
        if let Some(hold_id) = &params.hold_id {
            values = self.claim_held(hold_id, parameters, request_id).await?;
            *owned = true;
            for (index, change) in params.changes.iter().enumerate() {
                if change.op == EnvOp::Set && !values.contains_key(&index.to_string()) {
                    return Err(
                        "a held value is missing; nothing was changed, so re-file the request"
                            .to_owned()
                            .into(),
                    );
                }
            }
        }
        self.recheck(
            &params.account_id,
            &params.uuid,
            params.resource_kind,
            &params.name,
        )
        .await?;
        let (account, token) = self
            .lifecycle
            .resolve(&params.account_id)
            .await
            .map_err(step_error)?;
        let base = account.base_url.as_str();
        let provider_text = |failure: LifecycleFailure| failure.to_string();
        self.lifecycle
            .require_supported_version(base, &token)
            .await
            .map_err(provider_text)?;
        let resource = params.resource_kind;
        let uuid = params.uuid.as_str();
        let current = self
            .port
            .read_envs(base, &token, resource, uuid)
            .await
            .map_err(provider_text)?;
        // Every staleness check runs before the first write, so a change that
        // is going to be refused is refused whole.
        let mut plan: Vec<Option<&RemoteEnv>> = Vec::with_capacity(params.changes.len());
        for (change, entry) in params.changes.iter().zip(&params.preview) {
            let mut matching = current
                .iter()
                .filter(|env| env.key == change.key && env.is_preview == change.is_preview);
            let now_env = matching.next();
            if matching.next().is_some() {
                return Err(stale(&format!("{} now appears more than once", change.key)).into());
            }
            let before_holds = |env: &RemoteEnv| {
                entry
                    .before
                    .as_ref()
                    .is_some_and(|b| b.same_for(&env.flags, resource))
            };
            let flags_moved = || {
                stale(&format!(
                    "the flags of {} changed since the request was made",
                    change.key
                ))
            };
            match (change.op, now_env) {
                (EnvOp::Set, Some(env)) => {
                    let in_place = change
                        .flags
                        .is_some_and(|after| env.flags.same_for(&after, resource));
                    if !(before_holds(env) || in_place) {
                        return Err(flags_moved().into());
                    }
                }
                (EnvOp::Unset, Some(env)) => {
                    if !before_holds(env) {
                        return Err(flags_moved().into());
                    }
                }
                (EnvOp::Set, None) => {
                    if entry.before.is_some() {
                        return Err(stale(&format!(
                            "the variable {} no longer exists",
                            change.key
                        ))
                        .into());
                    }
                }
                // Already gone: a replay after a crash.
                (EnvOp::Unset, None) => {}
            }
            plan.push(now_env);
        }
        let mut changed = Vec::new();
        let partial = |changed: &Vec<String>, message: &str| SettingsFailure {
            message: fleet_core::scrub_failure_detail(message),
            partial: Some(Box::new(SettingsOutcome {
                setting: Setting::Env.id().to_owned(),
                outcome: "partial".to_owned(),
                changed: changed.clone(),
                verified: false,
                follow_up: None,
                error: Some(fleet_core::scrub_failure_detail(message)),
            })),
        };
        for (index, (change, now_env)) in params.changes.iter().zip(plan).enumerate() {
            let label = |verb: &str| {
                format!(
                    "{verb} {}{}",
                    change.key,
                    if change.is_preview { " (preview)" } else { "" }
                )
            };
            let sent = match change.op {
                EnvOp::Set => {
                    let value = SensitiveString::new(
                        values.get(&index.to_string()).cloned().unwrap_or_default(),
                    );
                    let write = EnvWrite {
                        key: &change.key,
                        value: &value,
                        is_preview: change.is_preview,
                        flags: change.flags.unwrap_or_default(),
                    };
                    let outcome = if now_env.is_some() {
                        self.port
                            .update_env(base, &token, resource, uuid, &write)
                            .await
                    } else {
                        self.port
                            .create_env(base, &token, resource, uuid, &write)
                            .await
                    };
                    outcome.map(|()| Some(label("set")))
                }
                EnvOp::Unset => match now_env {
                    Some(env) => self
                        .port
                        .delete_env(base, &token, resource, uuid, &env.uuid)
                        .await
                        .map(|()| Some(label("unset"))),
                    None => Ok(None),
                },
            };
            match sent {
                Ok(Some(name)) => changed.push(name),
                Ok(None) => {}
                Err(failure) => {
                    let message = format!(
                        "stopped at {}: {failure}; {} of {} changes were applied (see the result), the rest were not",
                        change.key,
                        changed.len(),
                        params.changes.len()
                    );
                    return Err(partial(&changed, &message));
                }
            }
        }
        // Read back: every set exists with its flags, every unset is gone.
        let after = self
            .port
            .read_envs(base, &token, resource, uuid)
            .await
            .map_err(|failure| {
                partial(
                    &changed,
                    &format!("the change was applied but could not be read back: {failure}"),
                )
            })?;
        for change in &params.changes {
            let found = after
                .iter()
                .find(|env| env.key == change.key && env.is_preview == change.is_preview);
            let ok = match (change.op, found) {
                (EnvOp::Set, Some(env)) => change
                    .flags
                    .as_ref()
                    .is_some_and(|flags| flags.same_for(&env.flags, resource)),
                (EnvOp::Unset, None) => true,
                _ => false,
            };
            if !ok {
                return Err(partial(
                    &changed,
                    &format!(
                        "Coolify accepted the change but reading it back differs for {}; check it in Coolify",
                        change.key
                    ),
                ));
            }
        }
        let follow_up = self
            .follow_up(params.redeploy, base, &token, resource, uuid)
            .await;
        conclude(SettingsOutcome {
            setting: Setting::Env.id().to_owned(),
            outcome: if changed.is_empty() {
                "unchanged"
            } else {
                "applied"
            }
            .to_owned(),
            changed,
            verified: true,
            follow_up,
            error: None,
        })
    }

    async fn execute_domains(
        &self,
        params: &DomainsParameters,
    ) -> Result<SettingsOutcome, SettingsFailure> {
        self.recheck(
            &params.account_id,
            &params.uuid,
            params.resource_kind,
            &params.name,
        )
        .await?;
        let (account, token) = self
            .lifecycle
            .resolve(&params.account_id)
            .await
            .map_err(step_error)?;
        let base = account.base_url.as_str();
        let provider_text = |failure: LifecycleFailure| failure.to_string();
        self.lifecycle
            .require_supported_version(base, &token)
            .await
            .map_err(provider_text)?;
        let uuid = params.uuid.as_str();
        let current = self
            .port
            .read_application(base, &token, uuid)
            .await
            .map_err(provider_text)?;
        if current.build_pack == "dockercompose" {
            return Err(stale("the application is now built from a Compose file").into());
        }
        let now_domains: Vec<String> = current.domains.iter().map(|d| lenient(d)).collect();
        let already = now_domains == params.domains;
        if !already && now_domains != params.preview.before {
            return Err(stale("the domains changed since the request was made").into());
        }
        if !already {
            self.port
                .patch_application(
                    base,
                    &token,
                    uuid,
                    &ApplicationPatch {
                        domains: Some(params.domains.clone()),
                        health: None,
                    },
                )
                .await
                .map_err(provider_text)?;
            let after = self
                .port
                .read_application(base, &token, uuid)
                .await
                .map_err(provider_text)?;
            let read: Vec<String> = after.domains.iter().map(|d| lenient(d)).collect();
            if read != params.domains {
                return Err(
                    "Coolify accepted the change but reading the domains back differs; check them in Coolify"
                        .to_owned()
                        .into(),
                );
            }
        }
        let follow_up = self
            .follow_up(params.redeploy, base, &token, params.resource_kind, uuid)
            .await;
        conclude(SettingsOutcome {
            setting: Setting::Domains.id().to_owned(),
            outcome: if already { "unchanged" } else { "applied" }.to_owned(),
            changed: if already {
                Vec::new()
            } else {
                vec!["domains".to_owned()]
            },
            verified: true,
            follow_up,
            error: None,
        })
    }

    async fn execute_health(
        &self,
        params: &HealthParameters,
    ) -> Result<SettingsOutcome, SettingsFailure> {
        self.recheck(
            &params.account_id,
            &params.uuid,
            params.resource_kind,
            &params.name,
        )
        .await?;
        let (account, token) = self
            .lifecycle
            .resolve(&params.account_id)
            .await
            .map_err(step_error)?;
        let base = account.base_url.as_str();
        let provider_text = |failure: LifecycleFailure| failure.to_string();
        self.lifecycle
            .require_supported_version(base, &token)
            .await
            .map_err(provider_text)?;
        let uuid = params.uuid.as_str();
        let current = self
            .port
            .read_application(base, &token, uuid)
            .await
            .map_err(provider_text)?;
        let already = current.health == params.preview.after;
        if !already && current.health != params.preview.before {
            return Err(stale("the health check changed since the request was made").into());
        }
        if !already {
            self.port
                .patch_application(
                    base,
                    &token,
                    uuid,
                    &ApplicationPatch {
                        domains: None,
                        health: Some(params.patch.clone()),
                    },
                )
                .await
                .map_err(provider_text)?;
            let after = self
                .port
                .read_application(base, &token, uuid)
                .await
                .map_err(provider_text)?;
            if after.health != params.preview.after {
                return Err(
                    "Coolify accepted the change but reading the health check back differs; check it in Coolify"
                        .to_owned()
                        .into(),
                );
            }
        }
        let follow_up = self
            .follow_up(params.redeploy, base, &token, params.resource_kind, uuid)
            .await;
        conclude(SettingsOutcome {
            setting: Setting::Health.id().to_owned(),
            outcome: if already { "unchanged" } else { "applied" }.to_owned(),
            changed: params
                .preview
                .changes
                .iter()
                .map(|change| change.field.clone())
                .collect(),
            verified: true,
            follow_up,
            error: None,
        })
    }

    /// The redeploy (application) or restart (service) a change asked for.
    async fn follow_up(
        &self,
        asked: bool,
        base: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
    ) -> Option<FollowUp> {
        if !asked {
            return None;
        }
        let verb = if resource == LifecycleResource::Application {
            LifecycleVerb::Redeploy
        } else {
            LifecycleVerb::Restart
        };
        let mut follow = FollowUp {
            verb: verb.id().to_owned(),
            deployment_uuid: None,
            error: None,
        };
        match self
            .lifecycle
            .run_verb(base, token, resource, uuid, verb)
            .await
        {
            Err(failure) => {
                follow.error = Some(fleet_core::scrub_failure_detail(&failure.to_string()));
            }
            Ok(ack) if verb == LifecycleVerb::Redeploy && ack.deployment_uuid.is_none() => {
                follow.error = Some("Coolify did not queue a deployment".to_owned());
            }
            Ok(ack) => follow.deployment_uuid = ack.deployment_uuid,
        }
        Some(follow)
    }

    /// Deletes held values no live request names: those of denied, expired,
    /// failed, and succeeded requests (or of none), once past the grace that
    /// covers the moment between storing a value and filing its request.
    /// Returns how many were removed. A record is live when the request it
    /// is bound to is pending, approved, or executing. Every such request is
    /// read; if they cannot all be read, nothing is removed.
    ///
    /// # Errors
    ///
    /// Fails when a store cannot be read.
    pub async fn sweep_held(&self, now: i64) -> Result<usize, String> {
        let ids = self.holds.list().await?;
        if ids.is_empty() {
            return Ok(0);
        }
        // Every live request, however many: the page grows until it is not
        // full, and a page that cannot be read whole removes nothing.
        let mut live: BTreeSet<String> = BTreeSet::new();
        for state in [
            ActionRequestState::Pending,
            ActionRequestState::Approved,
            ActionRequestState::Executing,
        ] {
            let mut limit = SWEEP_PAGE;
            let page = loop {
                let page = self.requests.list(Some(state), limit).await?;
                if page.len() < limit as usize {
                    break page;
                }
                if limit >= SWEEP_MAX {
                    return Ok(0);
                }
                limit = limit.saturating_mul(4).min(SWEEP_MAX);
            };
            for request in page {
                // A pending request past its deadline is as good as expired.
                if state == ActionRequestState::Pending && request.expires_at <= now {
                    continue;
                }
                if request.action_id == ENV_ACTION {
                    live.insert(request.id);
                }
            }
        }
        let mut removed = 0;
        for id in ids {
            let bound_to = self
                .holds
                .get(&id)
                .await?
                .and_then(|document| serde_json::from_str::<HeldRecord>(document.expose()).ok())
                .and_then(|record| record.request_id);
            // A record bound to a live request is kept; so is one not yet
            // bound (it is between storing and the broker's answer) until
            // the grace has passed.
            if bound_to
                .as_ref()
                .is_some_and(|request| live.contains(request))
            {
                continue;
            }
            let age = uuid7_millis(&id).map_or(i64::MAX, |made| now.saturating_sub(made));
            if age > HOLD_GRACE_MILLIS {
                self.holds.discard(&id).await?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// A finished change: `Ok` when the follow-up (if asked) went through, else
/// a failure that still carries what was applied.
fn conclude(outcome: SettingsOutcome) -> Result<SettingsOutcome, SettingsFailure> {
    let failed = outcome.follow_up.as_ref().and_then(|follow| {
        follow
            .error
            .clone()
            .map(|error| (follow.verb.clone(), error))
    });
    match failed {
        None => Ok(outcome),
        Some((verb, error)) => Err(SettingsFailure {
            message: fleet_core::scrub_failure_detail(&format!(
                "the change was applied but the {verb} failed: {error}"
            )),
            partial: Some(Box::new(outcome)),
        }),
    }
}

fn now_millis() -> i64 {
    fleet_core::SystemClock::now_unix_millis()
}

/// The creation time in a `UUIDv7`'s first 48 bits.
fn uuid7_millis(id: &str) -> Option<i64> {
    let hex: String = id.chars().filter(|c| *c != '-').take(12).collect();
    if hex.len() != 12 {
        return None;
    }
    i64::from_str_radix(&hex, 16).ok()
}

fn require_application(resource: LifecycleResource, what: &str) -> Result<(), LifecycleError> {
    if resource == LifecycleResource::Application {
        Ok(())
    } else {
        Err(invalid(format!(
            "only an application's {what} can be changed here (a service keeps domains per sub-application in Coolify; a database has none)"
        )))
    }
}

/// Names Coolify holds more than once (same name and preview flag): Fleet
/// cannot tell which one a request means, so it refuses to change them.
fn note_duplicates(envs: &[RemoteEnv], notes: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    let mut named = BTreeSet::new();
    for env in envs {
        if !seen.insert((env.key.as_str(), env.is_preview)) {
            named.insert(env.key.as_str());
        }
    }
    for key in named {
        notes.push(format!(
            "{key} appears more than once in Coolify; Fleet will not change it until the duplicate is resolved there"
        ));
    }
}

fn env_view(env: &RemoteEnv) -> EnvView {
    EnvView {
        key: env.key.clone(),
        is_preview: env.is_preview,
        is_shared: env.is_shared,
        flags: env.flags,
    }
}

/// A domain as Coolify stores it, normalized when it can be and kept as read
/// when it cannot, so a comparison never fails on what Coolify holds.
fn lenient(domain: &str) -> String {
    normalize_domain(domain).unwrap_or_else(|_| domain.trim().to_owned())
}

fn key_conflict(existing: &ActionRequest) -> LifecycleError {
    LifecycleError::Broker(BrokerError::Conflict {
        state: existing.state,
        detail: "the idempotency key was already used for a different request".to_owned(),
    })
}

/// Whether a flag the caller named agrees with the stored one; a flag the
/// caller left out agrees with anything.
fn flag_agrees(wanted: Option<bool>, have: Option<EnvFlags>, pick: fn(&EnvFlags) -> bool) -> bool {
    wanted.is_none_or(|value| have.is_some_and(|flags| pick(&flags) == value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags() -> EnvFlags {
        EnvFlags::default()
    }

    fn health() -> HealthSettings {
        HealthSettings {
            check_type: "http".to_owned(),
            enabled: true,
            path: "/".to_owned(),
            port: None,
            host: None,
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            return_code: 200,
            response_text: None,
            interval: 5,
            timeout: 5,
            retries: 10,
            start_period: 5,
        }
    }

    #[test]
    fn domains_normalize_and_refuse_what_coolify_refuses() {
        assert_eq!(
            normalize_domain("HTTPS://Shop.Example.COM/Path?x=1").as_deref(),
            Ok("https://shop.example.com/Path?x=1")
        );
        assert_eq!(
            normalize_domain("http://example.com:8080").as_deref(),
            Ok("http://example.com:8080")
        );
        for bad in [
            "example.com",
            "ftp://example.com",
            "https://user:pw@example.com",
            "https://exa mple.com",
            "https://example.com/a;b",
            "https://example.com/$(x)",
            "https://example.com:0",
            "https://",
            "https://a,b.example.com",
        ] {
            assert!(normalize_domain(bad).is_err(), "{bad}");
        }
        assert!(
            normalize_domains(&[
                "https://a.example.com".into(),
                "https://A.example.com".into()
            ])
            .is_err(),
            "duplicates are refused"
        );
        assert_eq!(normalize_domains(&[]).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn a_health_patch_is_checked_field_by_field() {
        assert!(HealthPatch::default().is_empty());
        let ok = HealthPatch {
            path: Some("/healthz".to_owned()),
            interval: Some(30),
            ..HealthPatch::default()
        };
        ok.validate().unwrap();
        for bad in [
            HealthPatch {
                path: Some("healthz".into()),
                ..HealthPatch::default()
            },
            HealthPatch {
                path: Some("/a b".into()),
                ..HealthPatch::default()
            },
            HealthPatch {
                method: Some("DELETE".into()),
                ..HealthPatch::default()
            },
            HealthPatch {
                scheme: Some("ftp".into()),
                ..HealthPatch::default()
            },
            HealthPatch {
                return_code: Some(99),
                ..HealthPatch::default()
            },
            HealthPatch {
                port: Some(0),
                ..HealthPatch::default()
            },
            HealthPatch {
                retries: Some(0),
                ..HealthPatch::default()
            },
            HealthPatch {
                interval: Some(99_999),
                ..HealthPatch::default()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        let after = ok.apply(&health());
        assert_eq!(after.path, "/healthz");
        assert_eq!(after.interval, 30);
        assert_eq!(after.timeout, 5);
        let changes = health_changes(&health(), &after);
        assert_eq!(
            changes.iter().map(|c| c.field.as_str()).collect::<Vec<_>>(),
            vec!["interval", "path"]
        );
    }

    #[test]
    fn the_binding_covers_the_parameters_but_not_the_display_name() {
        let params = serde_json::to_value(env_params()).unwrap();
        let same = binding_of(&params);
        assert_eq!(same.len(), 64);
        let mut renamed = params.clone();
        renamed["name"] = serde_json::json!("renamed");
        assert_eq!(binding_of(&renamed), same, "the name is display-only");
        for edit in [
            |p: &mut Value| p["uuid"] = serde_json::json!("other"),
            |p: &mut Value| p["redeploy"] = serde_json::json!(false),
            |p: &mut Value| p["holdId"] = serde_json::json!("hold-2"),
            |p: &mut Value| p["changes"][0]["flags"]["isLiteral"] = serde_json::json!(false),
            |p: &mut Value| p["accountId"] = serde_json::json!("acct2"),
        ] {
            let mut changed = params.clone();
            edit(&mut changed);
            assert_ne!(binding_of(&changed), same);
        }
    }

    #[test]
    fn a_cleared_health_field_applies_and_never_conflicts_with_a_set() {
        let mut before = health();
        before.port = Some(8080);
        before.host = Some("app.example.org".to_owned());
        before.response_text = Some("ok".to_owned());
        let patch = HealthPatch {
            clear: vec![
                "port".to_owned(),
                "host".to_owned(),
                "responseText".to_owned(),
            ],
            ..HealthPatch::default()
        };
        patch.validate().unwrap();
        let after = patch.apply(&before);
        assert_eq!(
            (after.port, after.host, after.response_text),
            (None, None, None)
        );
        let both = HealthPatch {
            port: Some(1),
            clear: vec!["port".to_owned()],
            ..HealthPatch::default()
        };
        assert!(both.validate().is_err());
        let unknown = HealthPatch {
            clear: vec!["path".to_owned()],
            ..HealthPatch::default()
        };
        assert!(unknown.validate().is_err());
        // Coolify's host pattern: no colon.
        let host = HealthPatch {
            host: Some("a:b".to_owned()),
            ..HealthPatch::default()
        };
        assert!(host.validate().is_err());
    }

    #[test]
    fn env_keys_follow_coolifys_pattern() {
        for ok in ["A", "_x", "DATABASE_URL", "app.setting", "a1"] {
            assert!(valid_env_key(ok), "{ok}");
        }
        for bad in ["", "1A", "A-B", "A B", "A=B", "A\n"] {
            assert!(!valid_env_key(bad), "{bad:?}");
        }
        assert!(!valid_env_key(&"A".repeat(MAX_ENV_KEY_LEN + 1)));
    }

    fn env_params() -> EnvParameters {
        let after = EnvFlags {
            is_literal: true,
            ..flags()
        };
        EnvParameters {
            account_id: "acct".to_owned(),
            resource_kind: LifecycleResource::Application,
            uuid: "app1".to_owned(),
            name: "web".to_owned(),
            hold_id: Some("hold-1".to_owned()),
            changes: vec![
                EnvChange {
                    op: EnvOp::Set,
                    key: "API_URL".to_owned(),
                    is_preview: false,
                    flags: Some(after),
                },
                EnvChange {
                    op: EnvOp::Unset,
                    key: "OLD".to_owned(),
                    is_preview: false,
                    flags: None,
                },
            ],
            redeploy: true,
            preview: vec![
                EnvPreviewEntry {
                    key: "API_URL".to_owned(),
                    is_preview: false,
                    operation: PlanOp::Update,
                    before: Some(flags()),
                    after: Some(after),
                    changes: env_entry_changes(Some(&flags()), Some(&after), true),
                },
                EnvPreviewEntry {
                    key: "OLD".to_owned(),
                    is_preview: false,
                    operation: PlanOp::Delete,
                    before: Some(flags()),
                    after: None,
                    changes: env_entry_changes(Some(&flags()), None, false),
                },
            ],
        }
    }

    #[test]
    fn an_env_preview_is_bound_to_its_changes() {
        let good = env_params();
        validate_env(&good).unwrap();
        // The stored shape round-trips through JSON unchanged.
        let value = serde_json::to_value(&good).unwrap();
        let back: EnvParameters = serde_json::from_value(value).unwrap();
        validate_env(&back).unwrap();

        let mut tampered = env_params();
        tampered.preview[0].changes.clear();
        assert!(
            validate_env(&tampered).is_err(),
            "changes must be the difference"
        );
        let mut tampered = env_params();
        tampered.preview[1].operation = PlanOp::Update;
        assert!(validate_env(&tampered).is_err());
        let mut tampered = env_params();
        tampered.preview.pop();
        assert!(validate_env(&tampered).is_err());
        let mut tampered = env_params();
        tampered.hold_id = None;
        assert!(validate_env(&tampered).is_err(), "a set needs its hold");
        let mut tampered = env_params();
        tampered.changes[0].flags = None;
        assert!(validate_env(&tampered).is_err());
        let mut tampered = env_params();
        tampered.resource_kind = LifecycleResource::Database;
        assert!(validate_env(&tampered).is_err());
    }

    #[test]
    fn no_stored_shape_has_a_place_for_a_value() {
        // The parameters refuse a `value` field outright.
        let mut value = serde_json::to_value(env_params()).unwrap();
        value["changes"][0]["value"] = serde_json::json!("hunter2");
        assert!(serde_json::from_value::<EnvParameters>(value).is_err());
        // And the preview marks a written value as write-only.
        let params = env_params();
        let text = serde_json::to_string(&params).unwrap();
        assert!(text.contains("write-only"));
        assert!(!text.contains("x.test"));
    }

    #[test]
    fn the_broker_accepts_the_stored_shapes() {
        // The shapes pass the broker's credential-like refusal and its size
        // bound, including key names that sound like secrets.
        let mut params = env_params();
        params.changes[1].key = "DB_PASSWORD".to_owned();
        params.preview[1].key = "DB_PASSWORD".to_owned();
        let value = serde_json::to_value(&params).unwrap();
        assert!(!crate::broker::credential_like(&value), "{value}");
        assert!(value.to_string().len() < crate::broker::MAX_PARAMETERS_BYTES);
    }

    #[test]
    fn domain_and_health_previews_are_bound() {
        let before = vec!["https://a.example.com".to_owned()];
        let after = vec![
            "https://a.example.com".to_owned(),
            "https://b.example.com".to_owned(),
        ];
        let good = DomainsParameters {
            account_id: "acct".to_owned(),
            resource_kind: LifecycleResource::Application,
            uuid: "app1".to_owned(),
            name: "web".to_owned(),
            domains: after.clone(),
            redeploy: false,
            preview: Preview {
                changes: domain_changes(&before, &after),
                before: before.clone(),
                after: after.clone(),
            },
        };
        validate_domains(&good).unwrap();
        let mut bad = good.clone();
        bad.preview.changes.clear();
        assert!(validate_domains(&bad).is_err());
        let mut bad = good.clone();
        bad.preview.after = before;
        assert!(validate_domains(&bad).is_err());
        let mut bad = good;
        bad.resource_kind = LifecycleResource::Service;
        assert!(validate_domains(&bad).is_err());

        let patch = HealthPatch {
            retries: Some(3),
            ..HealthPatch::default()
        };
        let after = patch.apply(&health());
        let good = HealthParameters {
            account_id: "acct".to_owned(),
            resource_kind: LifecycleResource::Application,
            uuid: "app1".to_owned(),
            name: "web".to_owned(),
            patch,
            redeploy: false,
            preview: Preview {
                changes: health_changes(&health(), &after),
                before: health(),
                after,
            },
        };
        validate_health(&good).unwrap();
        let value = serde_json::to_value(&good).unwrap();
        validate_health(&serde_json::from_value(value).unwrap()).unwrap();
        let mut bad = good;
        bad.preview.after.retries = 4;
        assert!(validate_health(&bad).is_err());
    }

    #[test]
    fn a_hold_id_carries_its_creation_time() {
        let id = fleet_core::UuidV7Generator.next_resource_id().to_string();
        let made = uuid7_millis(&id).unwrap();
        assert!((now_millis() - made).abs() < 60_000);
        assert_eq!(uuid7_millis("short"), None);
    }
}
