//! The onboarding-draft repository: the SQLite implementation of the
//! application's [`OnboardingPort`].
//!
//! A draft is one row: its address, its authentication mode, its proposed
//! machine identity, its host-key trust state, and its discovered facts as
//! one bounded JSON document. Deleting the row deletes everything — there is
//! no cascade to clean up and no orphan to leak, which is what the draft
//! cleanup contract requires. The store interprets nothing: trust stages and
//! fingerprint comparisons are use-case rules.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::onboarding::{
    DraftEndpoint, HostKeyStage, NewDraft, OnboardAuth, OnboardHostKey, OnboardingDraft,
    OnboardingPort, TestOutcome,
};
use fleet_application::operation::PortFailure;
use fleet_core::CapabilityFact;

/// The facts payload bound; the same bound the machine snapshot path uses.
const MAX_FACTS_JSON: usize = 64 * 1024;

/// The onboarding-draft repository over a pool.
#[derive(Debug)]
pub struct OnboardingRepository {
    pool: SqlitePool,
}

impl OnboardingRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OnboardingPort for OnboardingRepository {
    async fn create(&self, draft: &NewDraft) -> Result<OnboardingDraft, PortFailure> {
        let id = Uuid::now_v7().to_string();
        let now = fleet_core::SystemClock::now_unix_millis();
        let (auth_type, identity_path) = split_auth(&draft.auth);
        sqlx::query(
            "INSERT INTO onboarding_drafts \
             (id, endpoint_user, endpoint_host, endpoint_port, auth_type, identity_path, \
              name, description, tags_json, groups_json, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
        )
        .bind(&id)
        .bind(&draft.endpoint.user)
        .bind(&draft.endpoint.host)
        .bind(i64::from(draft.endpoint.port))
        .bind(auth_type)
        .bind(identity_path)
        .bind(effective_name(draft))
        .bind(&draft.description)
        .bind(to_json(&draft.tags)?)
        .bind(to_json(&draft.groups)?)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|error| backend("create", &error))?;
        self.get(&id).await
    }

    async fn get(&self, id: &str) -> Result<OnboardingDraft, PortFailure> {
        let row: Option<sqlx::sqlite::SqliteRow> =
            sqlx::query("SELECT * FROM onboarding_drafts WHERE id = ?1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| backend("get", &error))?;
        let row = row.ok_or_else(|| PortFailure::NotFound {
            what: format!("onboarding draft {id:?}"),
        })?;
        hydrate(&row)
    }

    async fn list(&self, limit: u32) -> Result<Vec<OnboardingDraft>, PortFailure> {
        let limit = limit.clamp(1, 200);
        let rows = sqlx::query(
            "SELECT * FROM onboarding_drafts ORDER BY created_at DESC, id DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("list", &error))?;
        rows.iter().map(hydrate).collect()
    }

    async fn update(&self, draft: &OnboardingDraft) -> Result<OnboardingDraft, PortFailure> {
        let (auth_type, identity_path) = split_auth(&draft.auth);
        let last_test_json = draft
            .last_test
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| PortFailure::Backend {
                detail: format!("the test outcome does not serialize: {error}"),
            })?;
        let facts_json =
            serde_json::to_string(&draft.facts).map_err(|error| PortFailure::Backend {
                detail: format!("the fact set does not serialize: {error}"),
            })?;
        if facts_json.len() > MAX_FACTS_JSON {
            return Err(PortFailure::Backend {
                detail: "the discovered facts exceed the draft's 64 KiB bound".to_owned(),
            });
        }
        let updated = sqlx::query(
            "UPDATE onboarding_drafts SET \
             endpoint_user = ?2, endpoint_host = ?3, endpoint_port = ?4, \
             auth_type = ?5, identity_path = ?6, name = ?7, description = ?8, \
             tags_json = ?9, groups_json = ?10, key_type = ?11, observed_fingerprint = ?12, \
             key_raw_line = ?13, host_key_stage = ?14, confirmed_fingerprint = ?15, \
             last_test_json = ?16, facts_json = ?17, discovery_source = ?18, \
             discovered_at = ?19, updated_at = ?20 \
             WHERE id = ?1",
        )
        .bind(&draft.id)
        .bind(&draft.endpoint.user)
        .bind(&draft.endpoint.host)
        .bind(i64::from(draft.endpoint.port))
        .bind(auth_type)
        .bind(identity_path)
        .bind(&draft.name)
        .bind(&draft.description)
        .bind(to_json(&draft.tags)?)
        .bind(to_json(&draft.groups)?)
        .bind(draft.host_key.as_ref().map(|key| key.key_type.as_str()))
        .bind(draft.host_key.as_ref().map(|key| key.fingerprint.as_str()))
        .bind(draft.host_key.as_ref().map(|key| key.raw_line.as_str()))
        .bind(draft.host_key_stage.id())
        .bind(&draft.confirmed_fingerprint)
        .bind(last_test_json)
        .bind(&facts_json)
        .bind(&draft.discovery_source)
        .bind(draft.discovered_at)
        .bind(draft.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|error| backend("update", &error))?;
        if updated.rows_affected() == 0 {
            return Err(PortFailure::NotFound {
                what: format!("onboarding draft {:?}", draft.id),
            });
        }
        self.get(&draft.id).await
    }

    async fn delete(&self, id: &str) -> Result<(), PortFailure> {
        let deleted = sqlx::query("DELETE FROM onboarding_drafts WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| backend("delete", &error))?;
        if deleted.rows_affected() == 0 {
            return Err(PortFailure::NotFound {
                what: format!("onboarding draft {id:?}"),
            });
        }
        Ok(())
    }
}

/// Assembles one draft from a row. The trust stage and authentication mode
/// round-trip through their stable ids; an unreadable one degrades to the
/// safest default (`unseen`, agent-less identity) rather than failing a read
/// of otherwise valid state.
fn hydrate(row: &sqlx::sqlite::SqliteRow) -> Result<OnboardingDraft, PortFailure> {
    let auth_type: String = row.get("auth_type");
    let identity_path: Option<String> = row.get("identity_path");
    let auth = match auth_type.as_str() {
        "agent" => OnboardAuth::Agent,
        "identityFile" => OnboardAuth::IdentityFile {
            path: identity_path.unwrap_or_default(),
        },
        other => {
            return Err(PortFailure::Backend {
                detail: format!("onboarding draft carries an unknown auth type {other:?}"),
            });
        }
    };
    let host_key_stage = HostKeyStage::from_id(&row.get::<String, _>("host_key_stage"))
        .unwrap_or(HostKeyStage::Unseen);
    let key_type: Option<String> = row.get("key_type");
    let observed_fingerprint: Option<String> = row.get("observed_fingerprint");
    let key_raw_line: Option<String> = row.get("key_raw_line");
    let host_key = key_type.zip(observed_fingerprint).zip(key_raw_line).map(
        |((key_type, fingerprint), raw_line)| OnboardHostKey {
            key_type,
            fingerprint,
            raw_line,
        },
    );
    let last_test_json: Option<String> = row.get("last_test_json");
    let last_test = last_test_json
        .as_deref()
        .map(serde_json::from_str::<TestOutcome>)
        .transpose()
        .map_err(|error| PortFailure::Backend {
            detail: format!("the stored test outcome does not parse: {error}"),
        })?;
    let facts_json: String = row.get("facts_json");
    let facts: Vec<CapabilityFact> =
        serde_json::from_str(&facts_json).map_err(|error| PortFailure::Backend {
            detail: format!("the stored facts do not parse: {error}"),
        })?;

    Ok(OnboardingDraft {
        id: row.get("id"),
        endpoint: DraftEndpoint {
            user: row.get("endpoint_user"),
            host: row.get("endpoint_host"),
            port: u16::try_from(row.get::<i64, _>("endpoint_port")).unwrap_or(22),
        },
        auth,
        name: row.get("name"),
        description: row.get("description"),
        tags: from_json(&row.get::<String, _>("tags_json"))?,
        groups: from_json(&row.get::<String, _>("groups_json"))?,
        host_key,
        host_key_stage,
        confirmed_fingerprint: row.get("confirmed_fingerprint"),
        last_test,
        facts,
        discovery_source: row.get("discovery_source"),
        discovered_at: row.get("discovered_at"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn split_auth(auth: &OnboardAuth) -> (&'static str, Option<&str>) {
    match auth {
        OnboardAuth::Agent => ("agent", None),
        OnboardAuth::IdentityFile { path } => ("identityFile", Some(path)),
    }
}

fn effective_name(draft: &NewDraft) -> String {
    draft
        .name
        .clone()
        .unwrap_or_else(|| draft.endpoint.host.clone())
}

fn to_json(value: &[String]) -> Result<String, PortFailure> {
    serde_json::to_string(value).map_err(|error| PortFailure::Backend {
        detail: format!("a draft string list does not serialize: {error}"),
    })
}

fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, PortFailure> {
    serde_json::from_str(text).map_err(|error| PortFailure::Backend {
        detail: format!("a stored draft document does not parse: {error}"),
    })
}

fn backend(context: &str, error: &sqlx::Error) -> PortFailure {
    PortFailure::Backend {
        detail: format!("onboarding draft {context} failed: {error}"),
    }
}
