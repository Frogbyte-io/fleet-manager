//! DNS record observations: the SQLite implementation of the application's
//! [`DnsObservationPort`] (FM-1042).
//!
//! Observations attach to a Registry entry by name and never change it. This
//! storage is separate from every other enricher's, and additive.

use std::collections::BTreeMap;

use async_trait::async_trait;
use fleet_application::dns::{DnsObservation, DnsObservationPort, DnsRecord};
use sqlx::Row as _;
use sqlx::SqlitePool;

/// The DNS observation repository over a pool.
#[derive(Debug)]
pub struct DnsObservationRepository {
    pool: SqlitePool,
}

impl DnsObservationRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnsObservationPort for DnsObservationRepository {
    async fn replace(
        &self,
        observation: &DnsObservation,
        record_type: Option<&str>,
    ) -> Result<(), String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| format!("begin failed: {error}"))?;
        sqlx::query(
            "DELETE FROM dns_record_observations \
             WHERE account_id = ?1 AND zone_id = ?2 AND name = ?3 \
             AND (?4 IS NULL OR record_type = ?4)",
        )
        .bind(&observation.account_id)
        .bind(&observation.zone_id)
        .bind(&observation.name)
        .bind(record_type)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("clearing observations failed: {error}"))?;
        for record in &observation.records {
            let Some(record_id) = record.id.as_deref() else {
                continue;
            };
            sqlx::query(
                "INSERT INTO dns_record_observations \
                 (account_id, record_id, zone_id, zone_name, name, record_type, content, ttl, \
                  proxied, priority, registry_entry, observed_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                 ON CONFLICT (account_id, record_id) DO UPDATE SET \
                  zone_id = excluded.zone_id, zone_name = excluded.zone_name, \
                  name = excluded.name, record_type = excluded.record_type, \
                  content = excluded.content, ttl = excluded.ttl, proxied = excluded.proxied, \
                  priority = excluded.priority, registry_entry = excluded.registry_entry, \
                  observed_at = excluded.observed_at",
            )
            .bind(&observation.account_id)
            .bind(record_id)
            .bind(&observation.zone_id)
            .bind(&observation.zone_name)
            .bind(&record.name)
            .bind(&record.record_type)
            .bind(&record.content)
            .bind(i64::from(record.ttl))
            .bind(i64::from(record.proxied))
            .bind(record.priority.map(i64::from))
            .bind(observation.registry_entry.as_deref())
            .bind(observation.observed_at)
            .execute(&mut *tx)
            .await
            .map_err(|error| format!("recording an observation failed: {error}"))?;
        }
        tx.commit()
            .await
            .map_err(|error| format!("commit failed: {error}"))
    }

    async fn for_name(&self, name: &str) -> Result<Vec<DnsObservation>, String> {
        let rows = sqlx::query(
            "SELECT account_id, record_id, zone_id, zone_name, name, record_type, content, ttl, \
                    proxied, priority, registry_entry, observed_at \
             FROM dns_record_observations WHERE name = ?1 \
             ORDER BY observed_at DESC, account_id, record_type, content",
        )
        .bind(name)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("reading observations failed: {error}"))?;
        let mut grouped: BTreeMap<(String, String), DnsObservation> = BTreeMap::new();
        let mut order: Vec<(String, String)> = Vec::new();
        for row in rows {
            let account_id: String = row.get("account_id");
            let zone_id: String = row.get("zone_id");
            let key = (account_id.clone(), zone_id.clone());
            let observation = grouped.entry(key.clone()).or_insert_with(|| {
                order.push(key.clone());
                DnsObservation {
                    account_id,
                    zone_id,
                    zone_name: row.get("zone_name"),
                    name: row.get("name"),
                    registry_entry: row.get("registry_entry"),
                    records: Vec::new(),
                    observed_at: row.get("observed_at"),
                }
            });
            let ttl: i64 = row.get("ttl");
            let priority: Option<i64> = row.get("priority");
            observation.records.push(DnsRecord {
                id: Some(row.get("record_id")),
                record_type: row.get("record_type"),
                name: row.get("name"),
                content: row.get("content"),
                ttl: u32::try_from(ttl).unwrap_or(1),
                proxied: row.get::<i64, _>("proxied") != 0,
                priority: priority.and_then(|value| u16::try_from(value).ok()),
            });
        }
        Ok(order
            .into_iter()
            .filter_map(|key| grouped.remove(&key))
            .collect())
    }
}
