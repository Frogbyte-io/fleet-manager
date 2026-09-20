//! The Proxmox integration's composition: the credential store over the
//! encrypted secret store, the trust probe and discovery source over the
//! provider, and the use-case wiring (FM-600).
//!
//! Each account's API token lives as one secret record named
//! `proxmox/<account-id>` inside Fleet's encrypted store — the same store
//! every controller credential uses. The value is resolved just in time at
//! the discovery boundary; nothing else in the controller reads it, and
//! deleting the account deletes the record.
//!
//! The trust probe composes the provider's observe-only TLS policy: the
//! handshake is refused after the fingerprint is captured, so no credential
//! can be sent during a probe. Discovery composes the pinned-verifier
//! transport; an account without a confirmed fingerprint never reaches it.

use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::proxmox::{
    ProxmoxCredentialStore, ProxmoxDiscoverPort, ProxmoxSourceError, ProxmoxTrustProbe,
    RawDiscovery,
};
use fleet_core::SensitiveString;
use fleet_provider_proxmox::{ProxmoxSource as _, PveCredentials, PveHttpRequest, PveTransport};
use fleet_secrets::{SecretStore, SecretValue};

/// The secret-record name prefix for account tokens. The account id
/// completes it.
pub const SECRET_PREFIX: &str = "proxmox/";

fn secret_name(account_id: &str) -> String {
    format!("{SECRET_PREFIX}{account_id}")
}

/// The credential store over the secret store.
#[derive(Debug)]
pub struct SecretBackedProxmoxCredentials {
    secrets: Arc<SecretStore>,
}

impl SecretBackedProxmoxCredentials {
    /// Composes the store over the controller's secret store.
    #[must_use]
    pub fn new(secrets: Arc<SecretStore>) -> Self {
        Self { secrets }
    }

    async fn record_id(&self, name: &str) -> Result<Option<String>, String> {
        Ok(self
            .secrets
            .list()
            .await
            .map_err(|error| format!("the secret store is unreadable: {error}"))?
            .into_iter()
            .find(|record| record.name == name)
            .map(|record| record.id))
    }
}

#[async_trait]
impl ProxmoxCredentialStore for SecretBackedProxmoxCredentials {
    async fn load(
        &self,
        account_id: &str,
    ) -> Result<Option<String>, fleet_application::proxmox::CredentialStoreError> {
        let name = secret_name(account_id);
        let Some(id) = self.record_id(&name).await.map_err(|detail| {
            fleet_application::proxmox::CredentialStoreError::Backend { detail }
        })?
        else {
            return Ok(None);
        };
        let value = self.secrets.resolve(&id).await.map_err(|error| {
            fleet_application::proxmox::CredentialStoreError::Backend {
                detail: format!("the secret record {name:?} is unreadable: {error}"),
            }
        })?;
        String::from_utf8(value.expose().to_vec())
            .map(Some)
            .map_err(
                |_| fleet_application::proxmox::CredentialStoreError::Backend {
                    detail: format!("the secret record {name:?} is not UTF-8"),
                },
            )
    }

    async fn store(
        &self,
        account_id: &str,
        secret: &str,
    ) -> Result<(), fleet_application::proxmox::CredentialStoreError> {
        let name = secret_name(account_id);
        if let Some(id) = self.record_id(&name).await.map_err(|detail| {
            fleet_application::proxmox::CredentialStoreError::Backend { detail }
        })? {
            return self
                .secrets
                .update(&id, SecretValue::new(secret.as_bytes().to_vec()))
                .await
                .map(|_| ())
                .map_err(
                    |error| fleet_application::proxmox::CredentialStoreError::Backend {
                        detail: format!("cannot update {name:?}: {error}"),
                    },
                );
        }
        match self
            .secrets
            .create(&name, SecretValue::new(secret.as_bytes().to_vec()))
            .await
        {
            Ok(_) => Ok(()),
            Err(fleet_secrets::SecretError::DuplicateName { .. }) => {
                let id =
                    self.record_id(&name)
                        .await
                        .map_err(|detail| {
                            fleet_application::proxmox::CredentialStoreError::Backend { detail }
                        })?
                        .ok_or_else(|| {
                            fleet_application::proxmox::CredentialStoreError::Backend {
                                detail: format!("cannot store {name:?}: vanished after the race"),
                            }
                        })?;
                self.secrets
                    .update(&id, SecretValue::new(secret.as_bytes().to_vec()))
                    .await
                    .map(|_| ())
                    .map_err(
                        |error| fleet_application::proxmox::CredentialStoreError::Backend {
                            detail: format!("cannot update {name:?}: {error}"),
                        },
                    )
            }
            Err(other) => Err(fleet_application::proxmox::CredentialStoreError::Backend {
                detail: format!("cannot store {name:?}: {other}"),
            }),
        }
    }

    async fn clear(
        &self,
        account_id: &str,
    ) -> Result<(), fleet_application::proxmox::CredentialStoreError> {
        let name = secret_name(account_id);
        if let Some(id) = self.record_id(&name).await.map_err(|detail| {
            fleet_application::proxmox::CredentialStoreError::Backend { detail }
        })? {
            self.secrets.delete(&id).await.map_err(|error| {
                fleet_application::proxmox::CredentialStoreError::Backend {
                    detail: format!("cannot delete {name:?}: {error}"),
                }
            })?;
        }
        Ok(())
    }
}

/// The trust probe over the provider's observe-only TLS policy: no
/// credential exists in this path at all.
#[derive(Debug)]
pub struct ProviderTrustProbe {
    transport: Arc<dyn PveTransport>,
}

impl ProviderTrustProbe {
    /// Composes the probe over a transport.
    #[must_use]
    pub fn new(transport: Arc<dyn PveTransport>) -> Self {
        Self { transport }
    }
}

#[async_trait]
impl ProxmoxTrustProbe for ProviderTrustProbe {
    async fn observe(&self, host: &str, port: u16) -> Result<String, ProxmoxSourceError> {
        // A probe carries no credential: the token fields are placeholders
        // that are never sent, because the observe policy refuses the
        // handshake before any HTTP request is completed.
        let request = PveHttpRequest {
            host: host.to_owned(),
            port,
            path: "/api2/json/version".to_owned(),
            pinned_fingerprint: None,
            credentials: Arc::new(PveCredentials {
                token_id: "observe-only".to_owned(),
                token: SensitiveString::new("observe-only"),
            }),
        };
        match self.transport.execute(request).await {
            Err(fleet_provider_proxmox::PveTransportError::ObserveRefused { observed }) => {
                Ok(observed)
            }
            Err(fleet_provider_proxmox::PveTransportError::NoCertificate) => {
                Err(ProxmoxSourceError::Connect {
                    detail: "the host presented no certificate".to_owned(),
                })
            }
            Err(other) => Err(ProxmoxSourceError::Connect {
                detail: other.to_string(),
            }),
            // A host that accepts the observe probe cannot exist: the
            // policy refuses every handshake. If a future transport changes
            // that, refuse here rather than trusting silently.
            Ok(_) => Err(ProxmoxSourceError::Connect {
                detail: "the observe probe must refuse; refusing to trust".to_owned(),
            }),
        }
    }
}

/// The discovery source over the provider client.
#[derive(Debug)]
pub struct ProviderDiscovery {
    client: fleet_provider_proxmox::ProxmoxClient,
}

impl ProviderDiscovery {
    /// Composes the source over the provider client.
    #[must_use]
    pub fn new(client: fleet_provider_proxmox::ProxmoxClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ProxmoxDiscoverPort for ProviderDiscovery {
    async fn discover(
        &self,
        account: &fleet_application::proxmox::ProxmoxAccount,
        secret: &SensitiveString,
    ) -> Result<RawDiscovery, ProxmoxSourceError> {
        let Some(pinned) = account.fingerprint.clone() else {
            // The use case gates this; a source call without a pin is a
            // composition defect. Refuse loudly rather than probing with a
            // credential.
            return Err(ProxmoxSourceError::Connect {
                detail: "the account has no confirmed fingerprint; refusing to send credentials"
                    .to_owned(),
            });
        };
        let request = PveHttpRequest {
            host: account.host.clone(),
            port: account.port,
            path: "/api2/json/cluster/resources".to_owned(),
            pinned_fingerprint: Some(pinned.clone()),
            credentials: Arc::new(PveCredentials {
                token_id: account.token_id.clone(),
                token: SensitiveString::new(secret.expose().to_owned()),
            }),
        };
        match self.client.discover(request).await {
            Ok(discovery) => Ok(RawDiscovery {
                version: discovery.version.clone(),
                resources: discovery
                    .resources
                    .into_iter()
                    .map(|resource| fleet_application::proxmox::ProxmoxResource {
                        kind: resource.kind,
                        id: resource.id,
                        node: resource.node,
                        vmid: resource.vmid,
                        name: resource.name,
                        status: resource.status,
                        account_id: account.id.clone(),
                        pve_version: discovery.version.clone(),
                        observed_at: 0,
                    })
                    .collect(),
                warnings: discovery.warnings,
                reported_count: discovery.reported_count,
            }),
            Err(fleet_provider_proxmox::PveApiError::Auth) => Err(ProxmoxSourceError::Auth),
            Err(fleet_provider_proxmox::PveApiError::Forbidden { detail }) => {
                Err(ProxmoxSourceError::Forbidden { detail })
            }
            Err(fleet_provider_proxmox::PveApiError::Http { status, detail }) => {
                Err(ProxmoxSourceError::Http { status, detail })
            }
            Err(fleet_provider_proxmox::PveApiError::InvalidPayload { detail }) => {
                Err(ProxmoxSourceError::InvalidPayload { detail })
            }
            Err(fleet_provider_proxmox::PveApiError::Transport(
                fleet_provider_proxmox::PveTransportError::FingerprintMismatch { observed, pinned },
            )) => Err(ProxmoxSourceError::FingerprintMismatch {
                observed,
                pinned: pinned.unwrap_or(pinned_placeholder()),
            }),
            Err(fleet_provider_proxmox::PveApiError::Transport(other)) => {
                Err(ProxmoxSourceError::Connect {
                    detail: other.to_string(),
                })
            }
        }
    }
}

fn pinned_placeholder() -> String {
    // Unreachable in practice: the discovery request always pins. Kept for
    // exhaustive matching without a panic path.
    String::new()
}

/// Composes the Proxmox use cases over its ports.
#[must_use]
pub fn compose_proxmox(
    pool: sqlx::SqlitePool,
    secrets: Arc<SecretStore>,
    transport: Arc<dyn PveTransport>,
    audit: Arc<dyn fleet_application::operation::AuditPort>,
) -> fleet_application::proxmox::ProxmoxAccounts {
    let client = fleet_provider_proxmox::ProxmoxClient::new(transport.clone());
    fleet_application::proxmox::ProxmoxAccounts::new(
        Arc::new(fleet_storage_sqlite::ProxmoxAccountRepository::new(pool)),
        Arc::new(SecretBackedProxmoxCredentials::new(secrets)),
        Arc::new(ProviderDiscovery::new(client)),
        Arc::new(ProviderTrustProbe::new(transport)),
        audit,
    )
}
