//! The DNS provider (FM-1020): public NS, A, AAAA, and CNAME lookups
//! through a maintained stub resolver (hickory-resolver, MIT OR
//! Apache-2.0) over the system's resolver configuration
//! (`/etc/resolv.conf`, or the Windows registry).
//!
//! The provider answers one question per call: the values of one record
//! type at one name. A name with no such records is an empty answer, a
//! name that does not exist is [`DnsError::NameDoesNotExist`], and
//! anything else is a short, fixed-category failure that never carries the
//! resolver's text.
#![warn(missing_docs)]

use std::collections::BTreeSet;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};

/// The record types Fleet reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Delegated nameservers.
    Ns,
    /// IPv4 addresses.
    A,
    /// IPv6 addresses.
    Aaaa,
    /// A canonical name alias.
    Cname,
}

/// Why a query produced no answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsError {
    /// The name does not exist (NXDOMAIN).
    NameDoesNotExist,
    /// The resolver could not answer; a fixed category.
    Failed(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameDoesNotExist => write!(f, "the name does not exist"),
            Self::Failed(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for DnsError {}

/// The system stub resolver.
#[derive(Clone, Debug)]
pub struct SystemResolver {
    resolver: TokioResolver,
}

impl SystemResolver {
    /// Builds a resolver from the system configuration.
    ///
    /// # Errors
    ///
    /// Fails when the system resolver configuration cannot be read.
    pub fn new() -> Result<Self, DnsError> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|_| DnsError::Failed("the system resolver configuration is unreadable".to_owned()))?
            .build()
            .map_err(|_| DnsError::Failed("the resolver could not start".to_owned()))?;
        Ok(Self { resolver })
    }

    /// The values of `kind` records at `name`: sorted, deduplicated,
    /// lowercase, names without a trailing dot, addresses in canonical
    /// text form.
    ///
    /// # Errors
    ///
    /// [`DnsError::NameDoesNotExist`] for NXDOMAIN, [`DnsError::Failed`]
    /// for a timeout or server failure. No records is `Ok(vec![])`.
    pub async fn query(&self, name: &str, kind: Kind) -> Result<Vec<String>, DnsError> {
        let record_type = match kind {
            Kind::Ns => RecordType::NS,
            Kind::A => RecordType::A,
            Kind::Aaaa => RecordType::AAAA,
            Kind::Cname => RecordType::CNAME,
        };
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        let lookup = match self.resolver.lookup(fqdn.as_str(), record_type).await {
            Ok(lookup) => lookup,
            Err(error) if error.is_no_records_found() => {
                return if error.is_nx_domain() {
                    Err(DnsError::NameDoesNotExist)
                } else {
                    Ok(Vec::new())
                };
            }
            Err(_) => {
                return Err(DnsError::Failed(
                    "the resolver did not answer in time or refused the query".to_owned(),
                ));
            }
        };
        let values: BTreeSet<String> = lookup
            .answers()
            .iter()
            .filter_map(|record| match (&record.data, kind) {
                (RData::NS(ns), Kind::Ns) => Some(name_text(&ns.0.to_string())),
                (RData::CNAME(cname), Kind::Cname) => Some(name_text(&cname.0.to_string())),
                (RData::A(a), Kind::A) => Some(a.0.to_string()),
                (RData::AAAA(aaaa), Kind::Aaaa) => Some(aaaa.0.to_string()),
                _ => None,
            })
            .collect();
        Ok(values.into_iter().collect())
    }
}

fn name_text(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}
