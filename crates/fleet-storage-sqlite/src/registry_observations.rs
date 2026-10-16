//! Domain observations (FM-1020): the latest RDAP and DNS lookup result per
//! Registry domain entry. Not derived from Git and never written back to
//! it; see migration 0058.

use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use fleet_application::registry::enrich::{DOMAIN_TYPE, DomainObservation, ObservationStore};
use fleet_application::registry::normalize_key;

/// The observation repository over the controller's pool.
#[derive(Debug, Clone)]
pub struct ObservationRepository {
    pool: SqlitePool,
}

impl ObservationRepository {
    /// Composes the repository over the pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn decode(json: &str) -> Result<DomainObservation, String> {
    serde_json::from_str(json).map_err(|_| "a stored observation is unreadable".to_owned())
}

#[async_trait::async_trait]
impl ObservationStore for ObservationRepository {
    async fn save(&self, key: &str, observation: &DomainObservation) -> Result<(), String> {
        let json = serde_json::to_string(observation)
            .map_err(|_| "the observation could not be encoded".to_owned())?;
        sqlx::query(
            "INSERT INTO registry_observations \
             (entry_type, entry_key_norm, entry_key, observed_at, observation_json) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (entry_type, entry_key_norm) DO UPDATE SET \
                 entry_key = excluded.entry_key, \
                 observed_at = excluded.observed_at, \
                 observation_json = excluded.observation_json",
        )
        .bind(DOMAIN_TYPE)
        .bind(normalize_key(key))
        .bind(key)
        .bind(observation.observed_at)
        .bind(json)
        .execute(&self.pool)
        .await
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<DomainObservation>, String> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT observation_json FROM registry_observations \
             WHERE entry_type = ? AND entry_key_norm = ?",
        )
        .bind(DOMAIN_TYPE)
        .bind(normalize_key(key))
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| error.to_string())?;
        row.map(|(json,)| decode(&json)).transpose()
    }

    async fn list(&self) -> Result<Vec<(String, DomainObservation)>, String> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT entry_key, observation_json FROM registry_observations \
             WHERE entry_type = ? ORDER BY entry_key_norm",
        )
        .bind(DOMAIN_TYPE)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(|(key, json)| decode(&json).map(|observation| (key, observation)))
            .collect()
    }

    async fn retain(&self, keep: &[String]) -> Result<(), String> {
        let keep: Vec<String> = keep.iter().map(|key| normalize_key(key)).collect();
        let mut tx = self.pool.begin().await.map_err(|error| error.to_string())?;
        let stored: Vec<(String,)> =
            sqlx::query_as("SELECT entry_key_norm FROM registry_observations WHERE entry_type = ?")
                .bind(DOMAIN_TYPE)
                .fetch_all(&mut *tx)
                .await
                .map_err(|error| error.to_string())?;
        let gone: Vec<String> = stored
            .into_iter()
            .map(|(key,)| key)
            .filter(|key| !keep.contains(key))
            .collect();
        // Chunked so a large set stays under SQLite's bound-parameter limit.
        for chunk in gone.chunks(200) {
            let mut query: QueryBuilder<Sqlite> =
                QueryBuilder::new("DELETE FROM registry_observations WHERE entry_type = ");
            query.push_bind(DOMAIN_TYPE);
            query.push(" AND entry_key_norm IN (");
            let mut separated = query.separated(", ");
            for key in chunk {
                separated.push_bind(key);
            }
            query.push(")");
            query
                .build()
                .execute(&mut *tx)
                .await
                .map_err(|error| error.to_string())?;
        }
        tx.commit().await.map_err(|error| error.to_string())
    }
}
