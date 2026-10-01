//! The Proxmox task-history source over the provider client (FM-609).
//!
//! This adapter translates the provider's task model into the
//! application's model at the boundary. The provider's `TaskStatus`
//! becomes the application's `ProxmoxTaskState`, and the exit status
//! string travels unchanged. The account's token is resolved by the use
//! case and passed in for this one call only. Like discovery, an account
//! without a pinned fingerprint is refused before any credential is sent.

use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::proxmox::ProxmoxSourceError;
use fleet_application::proxmox::tasks::{
    ProxmoxTaskHistoryPort, ProxmoxTaskState, RawTask, RawTaskHistory, RawTaskQuery,
};
use fleet_core::SensitiveString;
use fleet_provider_proxmox::{
    PveCredentials, PveHttpRequest, PveTaskQuery, PveTaskSource, PveTaskSummary, TaskStatus,
};

/// The task-history source over the provider client.
#[derive(Debug)]
pub struct ProviderTaskHistory {
    client: fleet_provider_proxmox::ProxmoxClient,
}

impl ProviderTaskHistory {
    /// Composes the source over the provider client.
    #[must_use]
    pub fn new(client: fleet_provider_proxmox::ProxmoxClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ProxmoxTaskHistoryPort for ProviderTaskHistory {
    async fn task_history(
        &self,
        account: &fleet_application::proxmox::ProxmoxAccount,
        secret: &SensitiveString,
        query: &RawTaskQuery,
    ) -> Result<RawTaskHistory, ProxmoxSourceError> {
        let Some(pinned) = account.fingerprint.clone() else {
            return Err(ProxmoxSourceError::Connect {
                detail: "the account has no confirmed fingerprint; refusing to send credentials"
                    .to_owned(),
            });
        };
        let request = PveHttpRequest {
            host: account.host.clone(),
            port: account.port,
            path: "/api2/json/version".to_owned(),
            pinned_fingerprint: Some(pinned),
            credentials: Arc::new(PveCredentials {
                token_id: account.token_id.clone(),
                token: SensitiveString::new(secret.expose().to_owned()),
            }),
            method: fleet_provider_proxmox::PveHttpMethod::Get,
        };
        let history = self
            .client
            .task_history(
                request,
                &PveTaskQuery {
                    node: query.node.clone(),
                    vmid: query.vmid,
                    source: if query.running_only {
                        PveTaskSource::Active
                    } else {
                        PveTaskSource::All
                    },
                    limit_per_node: query.limit_per_node,
                },
            )
            .await
            .map_err(crate::proxmox_store::map_api_error)?;
        Ok(RawTaskHistory {
            version: history.version,
            tasks: history.tasks.into_iter().map(translate).collect(),
            warnings: history.warnings,
        })
    }
}

/// Translates one provider task into the application's model.
fn translate(task: PveTaskSummary) -> RawTask {
    let (state, exit_status) = match task.status {
        TaskStatus::Running => (ProxmoxTaskState::Running, None),
        TaskStatus::Ok => (ProxmoxTaskState::Ok, Some("OK".to_owned())),
        TaskStatus::Error { detail } => (ProxmoxTaskState::Error, Some(detail)),
        TaskStatus::Unknown => (ProxmoxTaskState::Unknown, None),
    };
    RawTask {
        target_id: (!task.upid.target.is_empty()).then(|| task.upid.target.clone()),
        node: task.upid.node.clone(),
        task_type: task.upid.task_type.clone(),
        upid: task.upid.raw,
        user: task.user,
        token_id: task.token_id,
        started_at_seconds: task.started_at,
        ended_at_seconds: task.ended_at,
        state,
        exit_status,
    }
}
