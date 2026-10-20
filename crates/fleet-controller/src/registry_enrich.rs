//! The domain lookup enricher's composition (FM-1020): the RDAP and DNS
//! adapters that translate provider types into the application's ports,
//! the process-wide shared pieces, and the scheduled sweep.
//!
//! The RDAP client (and its cached IANA bootstrap file), the DNS resolver,
//! and the per-server rate limiter are process-wide: the API builds its
//! state more than once (the direct and the Tailscale routers), and the
//! per-server spacing must hold across all of them and the scheduler.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use fleet_application::registry::RegistryReadModel;
use fleet_application::registry::enrich::{
    DnsFailure, DnsKind, DnsPort, DomainEnricher, EnrichSettings, INTERVAL_VAR, ObservationStore,
    RdapAnswer, RdapFailure, RdapPort, SharedLimiter, WINDOW_VAR, WhoisAnswer, WhoisFailure,
    WhoisPort, shared_limiter,
};
use fleet_provider_dns::{DnsError, Kind, SystemResolver};
use fleet_provider_rdap::whois::{TcpWhoisTransport, WhoisClient, WhoisError};
use fleet_provider_rdap::{RdapClient, RdapError, ReqwestRdapTransport};
use sqlx::SqlitePool;

/// How long after startup the first scheduled sweep waits, so a restart
/// loop never hammers public servers.
const FIRST_SWEEP_DELAY: Duration = Duration::from_secs(60);

/// The enricher's settings from the environment
/// (`FLEET_REGISTRY_ENRICH_INTERVAL_SECONDS`,
/// `FLEET_REGISTRY_EXPIRY_WINDOW_DAYS`).
///
/// # Errors
///
/// Fails on a malformed value, naming the variable.
pub fn enrich_settings_from_env() -> Result<EnrichSettings, String> {
    EnrichSettings::from_env_values(
        std::env::var(INTERVAL_VAR).ok().as_deref(),
        std::env::var(WINDOW_VAR).ok().as_deref(),
    )
}

/// The RDAP provider behind the application port.
#[derive(Debug)]
pub struct RdapAdapter {
    client: RdapClient,
}

#[async_trait::async_trait]
impl RdapPort for RdapAdapter {
    async fn server_for(&self, fqdn: &str) -> Result<Option<String>, String> {
        self.client
            .server_for(fqdn)
            .await
            .map_err(|error| error.to_string())
    }

    async fn lookup(&self, server: &str, fqdn: &str) -> Result<RdapAnswer, RdapFailure> {
        match self.client.query(server, fqdn).await {
            Ok(record) => Ok(RdapAnswer {
                registrar: record.registrar,
                expires: record.expires,
                statuses: record.statuses,
                nameservers: record.nameservers,
            }),
            Err(RdapError::NotFound) => Err(RdapFailure::NotFound),
            Err(error) => Err(RdapFailure::Failed(error.to_string())),
        }
    }
}

/// The WHOIS fallback behind the application port.
#[derive(Debug)]
pub struct WhoisAdapter {
    client: WhoisClient,
}

#[async_trait::async_trait]
impl WhoisPort for WhoisAdapter {
    fn referral_is_cached(&self, fqdn: &str) -> bool {
        self.client.referral_is_cached(fqdn)
    }

    async fn server_for(&self, fqdn: &str) -> Result<Option<String>, String> {
        self.client
            .server_for(fqdn)
            .await
            .map_err(|error| error.to_string())
    }

    async fn lookup(&self, server: &str, fqdn: &str) -> Result<WhoisAnswer, WhoisFailure> {
        match self.client.query(server, fqdn).await {
            Ok(record) => Ok(WhoisAnswer {
                registrar: record.registrar,
                expires: record.expires,
            }),
            Err(WhoisError::NotFound) => Err(WhoisFailure::NotFound),
            Err(WhoisError::Unreadable) => Err(WhoisFailure::Unreadable),
            Err(error) => Err(WhoisFailure::Failed(error.to_string())),
        }
    }
}

/// The DNS provider behind the application port. A resolver that could not
/// start answers every query with that fixed failure, so the sweep records
/// an honest `error` instead of the controller refusing to start.
#[derive(Debug)]
pub struct DnsAdapter {
    resolver: Result<SystemResolver, String>,
}

#[async_trait::async_trait]
impl DnsPort for DnsAdapter {
    async fn resolve(&self, name: &str, kind: DnsKind) -> Result<Vec<String>, DnsFailure> {
        let resolver = self
            .resolver
            .as_ref()
            .map_err(|detail| DnsFailure::Failed(detail.clone()))?;
        let kind = match kind {
            DnsKind::Ns => Kind::Ns,
            DnsKind::A => Kind::A,
            DnsKind::Aaaa => Kind::Aaaa,
            DnsKind::Cname => Kind::Cname,
        };
        resolver
            .query(name, kind)
            .await
            .map_err(|error| match error {
                DnsError::NameDoesNotExist => DnsFailure::NameDoesNotExist,
                DnsError::Failed(detail) => DnsFailure::Failed(detail),
            })
    }
}

struct Shared {
    rdap: Arc<RdapAdapter>,
    whois: Arc<WhoisAdapter>,
    dns: Arc<DnsAdapter>,
    limiter: SharedLimiter,
}

static SHARED: OnceLock<Option<Shared>> = OnceLock::new();

fn shared(settings: &EnrichSettings) -> Option<&'static Shared> {
    SHARED
        .get_or_init(|| {
            let transport = ReqwestRdapTransport::new().ok()?;
            Some(Shared {
                rdap: Arc::new(RdapAdapter {
                    client: RdapClient::new(Arc::new(transport)),
                }),
                whois: Arc::new(WhoisAdapter {
                    client: WhoisClient::new(Arc::new(TcpWhoisTransport)),
                }),
                dns: Arc::new(DnsAdapter {
                    resolver: SystemResolver::new().map_err(|error| error.to_string()),
                }),
                limiter: shared_limiter(settings.rdap_gap),
            })
        })
        .as_ref()
}

/// Composes the enricher over the store. `None` only when the HTTP client
/// cannot start, in which case the observation endpoints answer 503.
#[must_use]
pub fn compose_domain_enricher(
    pool: &SqlitePool,
    registry: Arc<RegistryReadModel>,
    settings: EnrichSettings,
) -> Option<Arc<DomainEnricher>> {
    let shared = shared(&settings)?;
    let store: Arc<dyn ObservationStore> = Arc::new(
        fleet_storage_sqlite::ObservationRepository::new(pool.clone()),
    );
    Some(Arc::new(
        DomainEnricher::new(
            registry,
            shared.rdap.clone(),
            shared.dns.clone(),
            store,
            Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
            settings,
        )
        .with_whois(shared.whois.clone())
        .with_limiter(shared.limiter.clone()),
    ))
}

/// The scheduled sweep: after a short startup delay, every `interval`, look
/// up every domain entry whose observation is older than half the interval
/// (so a restart does not repeat a recent sweep). Runs as the system's LAN
/// principal through the same authorization and audit as an on-demand
/// refresh. Returns when `shutdown` resolves; an in-flight sweep is
/// abandoned, and every stored observation is already committed.
pub async fn run_sweeper(
    enricher: Arc<DomainEnricher>,
    interval: Duration,
    shutdown: impl std::future::Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    let authorizer = fleet_auth::LanAllowAllAuthorizer;
    let mut wait = FIRST_SWEEP_DELAY.min(interval);
    loop {
        tokio::select! {
            () = &mut shutdown => return,
            () = tokio::time::sleep(wait) => {}
        }
        wait = interval;
        let sweep = enricher.sweep(
            &authorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            Some(interval / 2),
        );
        let result = tokio::select! {
            () = &mut shutdown => return,
            result = sweep => result,
        };
        match result {
            Ok(report) if report.observed > 0 || report.failed > 0 => eprintln!(
                "registry enrichment: {} observed, {} recent, {} failed to store",
                report.observed, report.fresh, report.failed
            ),
            Ok(_) => {}
            Err(error) => eprintln!("registry enrichment sweep failed: {error}"),
        }
    }
}
