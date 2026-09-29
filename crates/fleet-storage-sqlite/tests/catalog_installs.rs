//! Fleet's record of installed catalog versions (FM-411): round trip,
//! replacement, guarded removal, machine isolation, and cascade.

use fleet_application::catalog_installs::{CatalogInstall, CatalogInstallPort as _};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_core::EndpointKind;
use fleet_storage_sqlite::{MachineRepository, SkillsRepository, Store};

async fn machine(machines: &MachineRepository, name: &str) -> String {
    machines
        .register(&RegisterMachine {
            name: name.to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: format!("ops@{name}.lan:22"),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap()
        .id
}

fn install(machine_id: &str, version: &str, agent: &str, at: i64) -> CatalogInstall {
    CatalogInstall {
        machine_id: machine_id.to_owned(),
        catalog_id: "builtin-fleet".to_owned(),
        version_id: version.to_owned(),
        agent: agent.to_owned(),
        skill_name: "fleet".to_owned(),
        installed_at: at,
    }
}

#[tokio::test]
async fn installs_round_trip_replace_and_remove_per_machine() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let machines = MachineRepository::new(store.pool().clone());
    let a = machine(&machines, "a").await;
    let b = machine(&machines, "b").await;
    let repo = SkillsRepository::new(store.pool().clone());

    repo.record_installs(&[
        install(&a, "builtin-fleet@1", "codex", 10),
        install(&a, "builtin-fleet@1", "claude_code", 10),
        install(&b, "builtin-fleet@1", "codex", 10),
    ])
    .await
    .unwrap();
    assert_eq!(repo.list_installs(&a).await.unwrap().len(), 2);
    assert_eq!(repo.list_installs(&b).await.unwrap().len(), 1);

    // A newer rollout replaces the record for that agent.
    repo.record_installs(&[install(&a, "builtin-fleet@2", "codex", 20)])
        .await
        .unwrap();
    let listed = repo.list_installs(&a).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(
        listed
            .iter()
            .find(|i| i.agent == "codex")
            .unwrap()
            .version_id,
        "builtin-fleet@2"
    );

    // A probe that predates the newer install cannot remove it.
    repo.remove_install(&a, "builtin-fleet", "codex", 15)
        .await
        .unwrap();
    assert_eq!(repo.list_installs(&a).await.unwrap().len(), 2);
    repo.remove_install(&a, "builtin-fleet", "codex", 25)
        .await
        .unwrap();
    assert_eq!(repo.list_installs(&a).await.unwrap().len(), 1);
    assert_eq!(repo.list_installs(&b).await.unwrap().len(), 1);
}
