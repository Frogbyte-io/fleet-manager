//! The machine domain: stable identity, capability facts, and staleness.
//!
//! A machine's identity is an opaque id minted by the controller. Hostnames,
//! addresses, and endpoints are *facts about the machine*, recorded as
//! endpoints and observations — never the identity itself — so a machine can
//! move networks, change hostnames, or gain addresses without breaking its
//! history or its associations.
//!
//! Capability facts are namespaced observations (`os.family`, `tool.git`,
//! `agent.fleetd`) with an explicit status. The status vocabulary is what
//! makes an absent fact honest: **unknown** means the probe never answered
//! for it, **unavailable** means the machine answered and reported the
//! capability missing or broken, **stale** means the fact aged past its
//! freshness threshold, and **known** means it is fresh and believed.
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::time::Timestamp;

/// The status of one capability fact, as recorded and as displayed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Fresh and believed.
    Known,
    /// No probe ever answered for this capability.
    Unknown,
    /// The machine answered: the capability is missing or broken.
    Unavailable,
    /// Recorded as known once, but older than the freshness threshold.
    Stale,
}

impl CapabilityStatus {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Unknown => "unknown",
            Self::Unavailable => "unavailable",
            Self::Stale => "stale",
        }
    }

    /// Parses the stable string.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "known" => Some(Self::Known),
            "unknown" => Some(Self::Unknown),
            "unavailable" => Some(Self::Unavailable),
            "stale" => Some(Self::Stale),
            _ => None,
        }
    }
}

/// One namespaced capability fact about a machine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFact {
    /// The namespace, e.g. `os`, `tool`, `agent`. Lowercase; an empty
    /// namespace is a malformed fact.
    pub namespace: String,
    /// The capability name within the namespace, e.g. `git`, `family`.
    pub name: String,
    /// The observed value, when the capability has one.
    pub value: Option<String>,
    /// The status the observation carried.
    pub status: CapabilityStatus,
    /// When the fact was observed (epoch milliseconds).
    pub observed_at: Timestamp,
    /// What observed it: a probe name and version, e.g. `agentless/1`.
    pub source: String,
}

impl CapabilityFact {
    /// Validates the namespacing rules: lowercase namespace and name, both
    /// non-empty, bounded to 64 characters each.
    ///
    /// # Errors
    ///
    /// Returns the malformed part when validation fails.
    pub fn validate(&self) -> Result<(), String> {
        for (label, part) in [("namespace", &self.namespace), ("name", &self.name)] {
            if part.is_empty() || part.len() > 64 {
                return Err(format!("capability {label} must be 1..=64 characters"));
            }
            if !part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
            {
                return Err(format!(
                    "capability {label} must be lowercase [a-z0-9_-], not {part:?}"
                ));
            }
        }
        Ok(())
    }

    /// The displayed status: a recorded `known` fact ages into `stale` once
    /// its observation is older than the threshold; every other status is
    /// what was recorded. This is the rule that keeps "we do not know
    /// anymore" visibly different from "the machine says it is missing".
    #[must_use]
    pub fn effective_status(
        &self,
        now: Timestamp,
        freshness_threshold_ms: i64,
    ) -> CapabilityStatus {
        if self.status == CapabilityStatus::Known
            && now.unix_millis() - self.observed_at.unix_millis() > freshness_threshold_ms
        {
            CapabilityStatus::Stale
        } else {
            self.status
        }
    }
}

/// The kinds of connection endpoint a machine can have. Endpoints coexist:
/// an agentless SSH endpoint and a fleetd node endpoint describe the same
/// machine reached two ways.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// Reached by the controller over SSH (agentless).
    Ssh,
    /// Reached over the node protocol (fleetd).
    Fleetd,
}

impl EndpointKind {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Fleetd => "fleetd",
        }
    }

    /// Parses the stable string.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "ssh" => Some(Self::Ssh),
            "fleetd" => Some(Self::Fleetd),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(status: CapabilityStatus, observed_at: i64) -> CapabilityFact {
        CapabilityFact {
            namespace: "os".to_owned(),
            name: "family".to_owned(),
            value: Some("linux".to_owned()),
            status,
            observed_at: Timestamp::from_unix_millis(observed_at),
            source: "agentless/1".to_owned(),
        }
    }

    #[test]
    fn validation_enforces_namespacing() {
        let mut fact = fact(CapabilityStatus::Known, 0);
        assert!(fact.validate().is_ok());

        fact.namespace = "Os".to_owned();
        assert!(fact.validate().is_err());
        fact.namespace = String::new();
        assert!(fact.validate().is_err());
        fact.namespace = "os".to_owned();
        fact.name = "a".repeat(65);
        assert!(fact.validate().is_err());
        fact.name = "has space".to_owned();
        assert!(fact.validate().is_err());
    }

    #[test]
    fn known_facts_age_into_stale_others_do_not() {
        let now = Timestamp::from_unix_millis(10_000);
        let threshold = 5_000;

        let fresh = fact(CapabilityStatus::Known, 8_000);
        assert_eq!(
            fresh.effective_status(now, threshold),
            CapabilityStatus::Known
        );

        let aged = fact(CapabilityStatus::Known, 1_000);
        assert_eq!(
            aged.effective_status(now, threshold),
            CapabilityStatus::Stale
        );

        // "The machine says it is missing" never quietly becomes "stale":
        // unavailable means something different from unknown and from aged.
        let unavailable = fact(CapabilityStatus::Unavailable, 0);
        assert_eq!(
            unavailable.effective_status(now, threshold),
            CapabilityStatus::Unavailable
        );
        let unknown = fact(CapabilityStatus::Unknown, 0);
        assert_eq!(
            unknown.effective_status(now, threshold),
            CapabilityStatus::Unknown
        );
    }

    #[test]
    fn status_and_endpoint_ids_round_trip() {
        for status in [
            CapabilityStatus::Known,
            CapabilityStatus::Unknown,
            CapabilityStatus::Unavailable,
            CapabilityStatus::Stale,
        ] {
            assert_eq!(CapabilityStatus::from_id(status.id()), Some(status));
        }
        for kind in [EndpointKind::Ssh, EndpointKind::Fleetd] {
            assert_eq!(EndpointKind::from_id(kind.id()), Some(kind));
        }
    }
}
