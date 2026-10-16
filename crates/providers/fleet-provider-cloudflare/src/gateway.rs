//! The Cloudflare implementation of the application's DNS port.
//!
//! This is the translation boundary: Cloudflare's zone and record shapes
//! and error classes become Fleet's [`DnsZone`], [`DnsRecord`], and
//! [`DnsFailure`], and nothing Cloudflare-specific crosses it.

use async_trait::async_trait;
use fleet_application::dns::{
    DnsCredentials, DnsFailure, DnsFailureClass, DnsGateway, DnsRecord, DnsZone,
};

use crate::api::{ApiError, CloudflareClient, ErrorClass, Record, RecordInput};

/// The Cloudflare DNS gateway.
#[derive(Debug, Default)]
pub struct CloudflareDns;

fn failure(error: ApiError) -> DnsFailure {
    DnsFailure::new(
        match error.class {
            ErrorClass::Auth => DnsFailureClass::Auth,
            ErrorClass::Permission => DnsFailureClass::Permission,
            ErrorClass::NotFound => DnsFailureClass::NotFound,
            ErrorClass::Conflict => DnsFailureClass::Conflict,
            ErrorClass::RateLimited => DnsFailureClass::RateLimited,
            ErrorClass::Invalid => DnsFailureClass::Invalid,
            ErrorClass::Unavailable => DnsFailureClass::Unavailable,
        },
        error.detail,
    )
}

fn client(credentials: &DnsCredentials) -> Result<CloudflareClient, DnsFailure> {
    CloudflareClient::new(&credentials.base_url, credentials.token.expose()).map_err(failure)
}

fn record_from(record: Record) -> DnsRecord {
    DnsRecord {
        id: Some(record.id),
        record_type: record.record_type,
        name: record.name,
        content: record.content,
        ttl: record.ttl,
        proxied: record.proxied.unwrap_or(false),
        priority: record.priority,
    }
}

fn input_from(record: &DnsRecord) -> RecordInput {
    RecordInput {
        record_type: record.record_type.clone(),
        name: record.name.clone(),
        content: record.content.clone(),
        ttl: record.ttl,
        proxied: record.proxied,
        priority: record.priority,
    }
}

#[async_trait]
impl DnsGateway for CloudflareDns {
    async fn list_zones(
        &self,
        credentials: &DnsCredentials,
        name: Option<&str>,
    ) -> Result<Vec<DnsZone>, DnsFailure> {
        Ok(client(credentials)?
            .list_zones(name)
            .await
            .map_err(failure)?
            .into_iter()
            .map(|zone| DnsZone {
                id: zone.id,
                name: zone.name.to_ascii_lowercase(),
                status: zone.status,
            })
            .collect())
    }

    async fn list_records(
        &self,
        credentials: &DnsCredentials,
        zone_id: &str,
        name: Option<&str>,
        record_type: Option<&str>,
    ) -> Result<Vec<DnsRecord>, DnsFailure> {
        Ok(client(credentials)?
            .list_records(zone_id, name, record_type)
            .await
            .map_err(failure)?
            .into_iter()
            .map(record_from)
            .collect())
    }

    async fn create_record(
        &self,
        credentials: &DnsCredentials,
        zone_id: &str,
        record: &DnsRecord,
    ) -> Result<DnsRecord, DnsFailure> {
        client(credentials)?
            .create_record(zone_id, &input_from(record))
            .await
            .map(record_from)
            .map_err(failure)
    }

    async fn update_record(
        &self,
        credentials: &DnsCredentials,
        zone_id: &str,
        record_id: &str,
        record: &DnsRecord,
    ) -> Result<DnsRecord, DnsFailure> {
        client(credentials)?
            .update_record(zone_id, record_id, &input_from(record))
            .await
            .map(record_from)
            .map_err(failure)
    }

    async fn delete_record(
        &self,
        credentials: &DnsCredentials,
        zone_id: &str,
        record_id: &str,
    ) -> Result<(), DnsFailure> {
        client(credentials)?
            .delete_record(zone_id, record_id)
            .await
            .map_err(failure)
    }
}
