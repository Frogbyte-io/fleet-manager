//! FM-1031: the running-services use case over in-memory ports: each input
//! is filtered by its own permission, and a caller who may read none of
//! them is denied.

use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::coolify::{
    ClassObservation, CoolifyApplication, CoolifyObservationPort, CoolifyServer, CoolifySnapshot,
};
use fleet_application::external_accounts::{
    ExternalAccount, ExternalAccountPort, NewExternalAccount, StoredProbe,
};
use fleet_application::machine::MachineStatus;
use fleet_application::registry::RegistryEntryRecord;
use fleet_application::services::{
    ContainerObservationPort, InputError, InputState, MachineContainers, NoContainerObservations,
    ObservedContainer, RunningServices, ServiceFilter, ServiceMachine, ServiceMachines,
    ServiceRegistry, ServiceSource, ServicesError,
};
use fleet_core::{ExternalProviderKind, SystemClock};

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }
}

#[derive(Debug)]
struct Deny(Vec<Permission>);

impl Authorizer for Deny {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if self.0.contains(&request.action) {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

#[derive(Debug)]
struct Accounts;

#[async_trait]
impl ExternalAccountPort for Accounts {
    async fn create(&self, _: &NewExternalAccount) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn get(&self, _: &str) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn list(&self) -> Result<Vec<ExternalAccount>, String> {
        Ok(vec![ExternalAccount {
            id: "acc1".to_owned(),
            kind: ExternalProviderKind::Coolify,
            label: "prod".to_owned(),
            base_url: "https://coolify.example.test".to_owned(),
            scope_id: None,
            notes: String::new(),
            last_probe: None,
            created_at: 0,
            updated_at: 0,
        }])
    }
    async fn update(
        &self,
        _: &str,
        _: &NewExternalAccount,
        _: bool,
    ) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn record_probe(
        &self,
        _: &str,
        _: Option<&StoredProbe>,
    ) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn delete(&self, _: &str) -> Result<(), String> {
        Err("unsupported".to_owned())
    }
}

fn fresh<T>(now: i64, items: Vec<T>) -> ClassObservation<T> {
    ClassObservation {
        attempted_at: now,
        observed_at: Some(now),
        items,
        ..ClassObservation::default()
    }
}

#[derive(Debug)]
struct Observations;

#[async_trait]
impl CoolifyObservationPort for Observations {
    async fn load(&self, _: &str) -> Result<Option<(CoolifySnapshot, i64)>, String> {
        let now = SystemClock::now_unix_millis();
        Ok(Some((
            CoolifySnapshot {
                servers: fresh(
                    now,
                    vec![CoolifyServer {
                        uuid: "s1".to_owned(),
                        name: "local".to_owned(),
                        address: "10.0.0.9".to_owned(),
                        ..CoolifyServer::default()
                    }],
                ),
                applications: fresh(
                    now,
                    vec![CoolifyApplication {
                        uuid: "a1".to_owned(),
                        name: "web".to_owned(),
                        status: "running:healthy".to_owned(),
                        ..CoolifyApplication::default()
                    }],
                ),
                projects: fresh(now, Vec::new()),
                services: fresh(now, Vec::new()),
                databases: fresh(now, Vec::new()),
                deployments: fresh(now, Vec::new()),
                ..CoolifySnapshot::default()
            },
            now,
        )))
    }
    async fn save(&self, _: &str, _: &CoolifySnapshot, _: i64, _: i64) -> Result<bool, String> {
        Ok(false)
    }
}

#[derive(Debug)]
struct Machines;

#[async_trait]
impl ServiceMachines for Machines {
    async fn machines(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        _: i64,
    ) -> Result<Vec<ServiceMachine>, InputError> {
        fleet_application::authz::authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: None,
            },
        )
        .map_err(InputError::Denied)?;
        Ok(vec![ServiceMachine {
            id: "m1".to_owned(),
            name: "box".to_owned(),
            status: MachineStatus::Connected,
            addresses: vec!["10.0.0.9".to_owned()],
            tags: Vec::new(),
            readable: true,
        }])
    }
}

#[derive(Debug)]
struct Containers;

#[async_trait]
impl ContainerObservationPort for Containers {
    async fn observed(&self, ids: &[String]) -> Result<Vec<MachineContainers>, String> {
        Ok(ids
            .iter()
            .map(|id| MachineContainers {
                machine_id: id.clone(),
                observed_at: Some(SystemClock::now_unix_millis()),
                containers: vec![ObservedContainer {
                    id: "c1".to_owned(),
                    name: "redis".to_owned(),
                    state: "running".to_owned(),
                    ..ObservedContainer::default()
                }],
            })
            .collect())
    }
}

#[derive(Debug)]
struct Registry;

#[async_trait]
impl ServiceRegistry for Registry {
    async fn entries(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<Vec<RegistryEntryRecord>, InputError> {
        fleet_application::authz::authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::RegistryRead,
                resource: None,
            },
        )
        .map_err(InputError::Denied)?;
        Ok(Vec::new())
    }
}

fn use_case(containers: Arc<dyn ContainerObservationPort>) -> RunningServices {
    RunningServices::new(
        Arc::new(Accounts),
        Arc::new(Observations),
        Arc::new(Machines),
        containers,
        Some(Arc::new(Registry)),
    )
}

#[tokio::test]
async fn a_caller_sees_the_union_of_what_each_input_allows() {
    let all = use_case(Arc::new(Containers))
        .list(&Deny(vec![]), &principal(), &ServiceFilter::default())
        .await
        .unwrap();
    let ids: Vec<_> = all.services.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["coolify:acc1:a1", "docker:m1:redis"]);
    assert_eq!(all.coverage.coolify, InputState::Available);
    assert_eq!(all.coverage.containers, InputState::Available);

    // Without external_account.read the Coolify part is left out, and the
    // coverage says so instead of failing the read.
    let no_coolify = use_case(Arc::new(Containers))
        .list(
            &Deny(vec![Permission::ExternalAccountRead]),
            &principal(),
            &ServiceFilter::default(),
        )
        .await
        .unwrap();
    let ids: Vec<_> = no_coolify.services.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["docker:m1:redis"]);
    assert_eq!(no_coolify.coverage.coolify, InputState::Denied);

    // Without machine.read neither machines nor their containers appear.
    let no_machines = use_case(Arc::new(Containers))
        .list(
            &Deny(vec![Permission::MachineRead]),
            &principal(),
            &ServiceFilter::default(),
        )
        .await
        .unwrap();
    let ids: Vec<_> = no_machines.services.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["coolify:acc1:a1"]);
    assert_eq!(no_machines.coverage.containers, InputState::Denied);
    assert_eq!(no_machines.coverage.registry, InputState::Available);
}

#[tokio::test]
async fn a_caller_who_may_read_nothing_is_denied() {
    let denied = use_case(Arc::new(Containers))
        .list(
            &Deny(vec![
                Permission::ExternalAccountRead,
                Permission::MachineRead,
                Permission::RegistryRead,
            ]),
            &principal(),
            &ServiceFilter::default(),
        )
        .await;
    assert!(matches!(denied, Err(ServicesError::Denied(_))));
}

#[tokio::test]
async fn without_a_docker_store_the_coverage_says_so_and_filters_apply() {
    let view = use_case(Arc::new(NoContainerObservations))
        .list(
            &Deny(vec![]),
            &principal(),
            &ServiceFilter {
                source: Some(ServiceSource::Coolify),
                ..ServiceFilter::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(view.coverage.containers, InputState::NotConfigured);
    assert_eq!(view.services.len(), 1);

    let one = use_case(Arc::new(NoContainerObservations))
        .get(&Deny(vec![]), &principal(), "coolify:acc1:a1")
        .await
        .unwrap();
    assert_eq!(one.0.name, "web");
    let missing = use_case(Arc::new(NoContainerObservations))
        .get(&Deny(vec![]), &principal(), "coolify:acc1:zzz")
        .await;
    assert!(matches!(missing, Err(ServicesError::NotFound)));
}

/// Denies `machine.read` on one machine only, like a per-machine policy.
#[derive(Debug)]
struct DenyMachine(&'static str);

impl Authorizer for DenyMachine {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == Permission::MachineRead && request.resource == Some(self.0) {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

/// Two machines on the same address, flagged by the per-machine decision.
#[derive(Debug)]
struct TwinMachines;

#[async_trait]
impl ServiceMachines for TwinMachines {
    async fn machines(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        _: i64,
    ) -> Result<Vec<ServiceMachine>, InputError> {
        let mut out = Vec::new();
        for id in ["m1", "m2"] {
            let readable = fleet_application::authz::authorize(
                authorizer,
                AccessRequest {
                    principal_id: &principal.id,
                    action: Permission::MachineRead,
                    resource: Some(id),
                },
            )
            .is_ok();
            out.push(ServiceMachine {
                id: id.to_owned(),
                name: format!("box-{id}"),
                status: MachineStatus::Connected,
                addresses: vec!["10.0.0.9".to_owned()],
                tags: Vec::new(),
                readable,
            });
        }
        Ok(out)
    }
}

#[tokio::test]
async fn per_machine_denial_does_not_turn_a_duplicate_into_a_match() {
    let twins = RunningServices::new(
        Arc::new(Accounts),
        Arc::new(Observations),
        Arc::new(TwinMachines),
        Arc::new(NoContainerObservations),
        None,
    );
    let view = twins
        .list(&DenyMachine("m2"), &principal(), &ServiceFilter::default())
        .await
        .unwrap();
    let web = &view.services[0];
    assert_eq!(web.placement.state.id(), "ambiguous");
    assert!(web.placement.machine.is_none());
    assert_eq!(web.placement.candidates.len(), 1);
    assert_eq!(web.placement.hidden_candidates, 1);
    assert_eq!(view.ambiguous_servers[0].hidden_candidates, 1);
}

#[tokio::test]
async fn a_denied_machine_input_leaves_placement_unknown() {
    let view = use_case(Arc::new(NoContainerObservations))
        .list(
            &Deny(vec![Permission::MachineRead]),
            &principal(),
            &ServiceFilter::default(),
        )
        .await
        .unwrap();
    assert_eq!(view.services[0].placement.state.id(), "unknown");
}
