//! The desired-source use cases (FM-403): candidate fetching, activation
//! gating, and explicit rollback.
//!
//! A Git repository becomes the canonical source of desired resources
//! only when validation gates activation: a candidate carrying
//! diagnostics can never become active, the last valid revision stays
//! active on failure, activation is serialized and audited, and rollback
//! is an explicit authorized operation naming a prior valid revision —
//! never automatic.
//!
//! The active revision's identity is durable state: (commit SHA + content
//! digest), so a controller restart resumes truthfully.
#![warn(missing_docs)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One active revision: the candidate digest that was activated.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveRevision {
    /// The commit SHA of the active revision.
    pub commit_sha: String,
    /// The content digest of the active revision.
    pub content_digest: String,
}

/// The storage contract for the desired source's durable state.
#[async_trait::async_trait]
pub trait SourcePort: std::fmt::Debug + Send + Sync {
    /// Reads the active revision, when one has been activated.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn active_revision(&self) -> Result<Option<ActiveRevision>, String>;
    /// Records the active revision, replacing any prior one.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn set_active_revision(&self, revision: &ActiveRevision) -> Result<(), String>;
    /// The digests of prior valid revisions, for manual rollback.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn prior_revisions(&self) -> Result<Vec<ActiveRevision>, String>;
    /// Records a candidate's digest as a prior valid revision (only valid
    /// candidates are recorded — a candidate carrying diagnostics is
    /// reported and forgotten).
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn record_valid_revision(&self, revision: &ActiveRevision) -> Result<(), String>;
    /// Atomically activates a revision: the backend serializes the
    /// check-and-set so concurrent activations cannot race — the method
    /// returns the revision that is active AFTER the call, which is the
    /// caller's requested revision only if the activation won.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn activate_serialized(
        &self,
        revision: &ActiveRevision,
    ) -> Result<ActiveRevision, String>;
}

/// The outcome of one fetch: the candidate's digest and validation
/// diagnostics, plus whether the fetch could complete at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FetchOutcome {
    /// The candidate was fetched and validated; `diagnostics` empty means
    /// it may be activated.
    Candidate {
        /// The candidate's digest.
        digest: fleet_core::CandidateDigest,
        /// The validation diagnostics, empty when valid.
        diagnostics: Vec<String>,
    },
    /// The fetch failed at the transport level (clone/checkout); the
    /// active revision is untouched.
    TransportFailed {
        /// The bounded, redacted failure detail.
        detail: String,
    },
}

/// The authorized desired-source use cases.
#[derive(Clone, Debug)]
pub struct DesiredSource {
    port: std::sync::Arc<dyn SourcePort>,
    audit: std::sync::Arc<dyn crate::operation::AuditPort>,
}

impl DesiredSource {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(
        port: std::sync::Arc<dyn SourcePort>,
        audit: std::sync::Arc<dyn crate::operation::AuditPort>,
    ) -> Self {
        Self { port, audit }
    }

    /// Handles one fetch outcome: a valid candidate is recorded as a
    /// prior valid revision (available for manual rollback); a candidate
    /// carrying diagnostics is reported and forgotten; a transport
    /// failure leaves everything untouched. The active revision only
    /// changes through [`activate`](Self::activate).
    ///
    /// # Errors
    ///
    /// Fails when the audit or backend errors.
    pub async fn handle_fetch(
        &self,
        authorizer: &dyn crate::authz::Authorizer,
        principal_id: &str,
        outcome: FetchOutcome,
    ) -> Result<FetchOutcome, crate::project::ProjectUseCaseError> {
        use crate::authz::{AccessRequest, Permission, authorize};
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::SourceFetch,
                resource: None,
            },
        )
        .map_err(crate::project::ProjectUseCaseError::Denied)?;
        match outcome {
            FetchOutcome::Candidate {
                ref digest,
                ref diagnostics,
            } => {
                if diagnostics.is_empty() {
                    self.port
                        .record_valid_revision(&ActiveRevision {
                            commit_sha: digest.commit_sha.clone(),
                            content_digest: digest.content_digest.clone(),
                        })
                        .await
                        .map_err(|detail| crate::project::ProjectUseCaseError::Backend {
                            context: "source_record",
                            detail,
                        })?;
                }
                Ok(outcome)
            }
            transport_failure @ FetchOutcome::TransportFailed { .. } => Ok(transport_failure),
        }
    }

    /// Activates one revision by digest: the candidate must be valid and
    /// known (fetched before), activation is serialized and audited, and
    /// the active revision is replaced only on success.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown or invalid revision, or a backend
    /// failure.
    pub async fn activate(
        &self,
        authorizer: &dyn crate::authz::Authorizer,
        principal_id: &str,
        digest: &fleet_core::CandidateDigest,
        candidate_valid: bool,
        candidate_known: bool,
        operation_id: Option<&str>,
    ) -> Result<ActiveRevision, crate::project::ProjectUseCaseError> {
        use crate::authz::{AccessRequest, Permission, authorize};
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::SourceActivate,
                resource: None,
            },
        )
        .map_err(crate::project::ProjectUseCaseError::Denied)?;
        // An invalid candidate can never become active, and an unknown
        // digest was never fetched: both are refusals, not errors. The
        // caller's claims are verified against the recorded candidate
        // state: only a candidate the fetch path recorded as valid AND
        // known may activate.
        let recorded = self.port.prior_revisions().await.map_err(|detail| {
            crate::project::ProjectUseCaseError::Backend {
                context: "source_verify",
                detail,
            }
        })?;
        let known_and_valid = recorded
            .iter()
            .any(|revision| revision.commit_sha == digest.commit_sha);
        if !candidate_valid {
            return Err(crate::project::ProjectUseCaseError::Invalid {
                detail: "the candidate carries validation diagnostics and cannot become active"
                    .to_owned(),
            });
        }
        if !candidate_known || !known_and_valid {
            return Err(crate::project::ProjectUseCaseError::Invalid {
                detail: "the candidate was never fetched as valid; fetch it before activating"
                    .to_owned(),
            });
        }
        // The audit intent lands BEFORE the mutation: a failure to audit
        // prevents the activation, so durable state can never exist
        // without its intent.
        let mut metadata = crate::audit::AuditMetadata::default();
        metadata
            .insert("event", "source_activation")
            .map_err(|error| crate::project::ProjectUseCaseError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        metadata
            .insert("commitSha", &digest.commit_sha)
            .map_err(|error| crate::project::ProjectUseCaseError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal_id.to_owned(),
                action: Permission::SourceActivate.id().to_owned(),
                resource: None,
                decision: crate::authz::Decision::allow(),
                correlation_id: None,
                operation_id: operation_id.map(str::to_owned),
                metadata,
            })
            .await
            .map_err(|detail| crate::project::ProjectUseCaseError::Backend {
                context: "audit",
                detail,
            })?;
        let revision = ActiveRevision {
            commit_sha: digest.commit_sha.clone(),
            content_digest: digest.content_digest.clone(),
        };
        // The backend serializes the check-and-set: a concurrent
        // activation cannot race.
        self.port
            .activate_serialized(&revision)
            .await
            .map_err(|detail| crate::project::ProjectUseCaseError::Backend {
                context: "source_activate",
                detail,
            })
    }

    /// The prior valid revisions available for manual rollback.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn prior_revisions(
        &self,
        authorizer: &dyn crate::authz::Authorizer,
        principal_id: &str,
    ) -> Result<Vec<ActiveRevision>, crate::project::ProjectUseCaseError> {
        use crate::authz::{AccessRequest, Permission, authorize};
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::SourceFetch,
                resource: None,
            },
        )
        .map_err(crate::project::ProjectUseCaseError::Denied)?;
        self.port.prior_revisions().await.map_err(|detail| {
            crate::project::ProjectUseCaseError::Backend {
                context: "source_prior",
                detail,
            }
        })
    }
}

/// Reports the conflict between two revisions as data: the two digests
/// and the divergent file paths. Fleet never auto-resolves conflicts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictReport {
    /// The active revision's digest.
    pub active: ActiveRevision,
    /// The fetched revision's digest.
    pub fetched: ActiveRevision,
    /// The files that differ between the two revisions.
    pub divergent_files: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    use super::{ActiveRevision, DesiredSource, FetchOutcome, SourcePort};
    use crate::authz::{AccessRequest, Authorizer, Decision};
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct AllowAll;
    impl Authorizer for AllowAll {
        fn decide(&self, _request: AccessRequest<'_>) -> Decision {
            Decision::allow()
        }
    }

    #[derive(Debug, Default)]
    struct FakePort {
        active: Mutex<Option<ActiveRevision>>,
        valid: Mutex<Vec<ActiveRevision>>,
    }

    #[async_trait::async_trait]
    impl SourcePort for FakePort {
        async fn active_revision(&self) -> Result<Option<ActiveRevision>, String> {
            Ok(self.active.lock().unwrap().clone())
        }
        async fn set_active_revision(&self, revision: &ActiveRevision) -> Result<(), String> {
            *self.active.lock().unwrap() = Some(revision.clone());
            Ok(())
        }
        async fn prior_revisions(&self) -> Result<Vec<ActiveRevision>, String> {
            Ok(self.valid.lock().unwrap().clone())
        }
        async fn record_valid_revision(&self, revision: &ActiveRevision) -> Result<(), String> {
            self.valid.lock().unwrap().push(revision.clone());
            Ok(())
        }
        async fn activate_serialized(
            &self,
            revision: &ActiveRevision,
        ) -> Result<ActiveRevision, String> {
            *self.active.lock().unwrap() = Some(revision.clone());
            Ok(revision.clone())
        }
    }

    #[derive(Debug, Default)]
    struct FakeAudit {
        intents: Mutex<Vec<crate::audit::AuditIntent>>,
    }
    #[async_trait::async_trait]
    impl crate::operation::AuditPort for FakeAudit {
        async fn record_intent(&self, intent: &crate::audit::AuditIntent) -> Result<(), String> {
            self.intents.lock().unwrap().push(intent.clone());
            Ok(())
        }
        async fn record_outcome(
            &self,
            _operation_id: &str,
            _outcome: crate::audit::AuditOutcome,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    fn digest(sha: &str, content: &str) -> fleet_core::CandidateDigest {
        fleet_core::CandidateDigest {
            commit_sha: sha.to_owned(),
            content_digest: content.to_owned(),
        }
    }

    fn service() -> (DesiredSource, Arc<FakeAudit>, Arc<FakePort>) {
        let port = Arc::new(FakePort::default());
        let audit = Arc::new(FakeAudit::default());
        (DesiredSource::new(port.clone(), audit.clone()), audit, port)
    }

    #[tokio::test]
    async fn a_valid_candidate_is_recorded_for_rollback() {
        let (service, _, port) = service();
        let outcome = FetchOutcome::Candidate {
            digest: digest("abc", "digest-1"),
            diagnostics: vec![],
        };
        let handled = service
            .handle_fetch(&AllowAll, "anonymous-lan-admin", outcome)
            .await
            .unwrap();
        let FetchOutcome::Candidate { diagnostics, .. } = handled else {
            panic!("the candidate outcome is preserved");
        };
        assert!(diagnostics.is_empty());
        assert_eq!(port.prior_revisions().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_candidate_with_diagnostics_is_reported_and_forgotten() {
        let (service, _, port) = service();
        let outcome = FetchOutcome::Candidate {
            digest: digest("abc", "digest-bad"),
            diagnostics: vec!["the document does not match".to_owned()],
        };
        service
            .handle_fetch(&AllowAll, "anonymous-lan-admin", outcome)
            .await
            .unwrap();
        assert!(
            port.prior_revisions().await.unwrap().is_empty(),
            "an invalid candidate is never a rollback point"
        );
    }

    #[tokio::test]
    async fn activation_refuses_an_invalid_candidate() {
        let (service, _, _) = service();
        let error = service
            .activate(
                &AllowAll,
                "anonymous-lan-admin",
                &digest("abc", "bad"),
                false,
                true,
                None,
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("cannot become active"),
            "{error}"
        );
        assert!(service.port.active_revision().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn activation_refuses_an_unknown_candidate() {
        let (service, _, _) = service();
        let error = service
            .activate(
                &AllowAll,
                "anonymous-lan-admin",
                &digest("abc", "d"),
                true,
                false,
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("never fetched"), "{error}");
    }

    #[tokio::test]
    async fn activation_is_audited_and_durable() {
        let (service, audit, port) = service();
        // The candidate must have been fetched as valid before activation:
        // the fetch records it.
        service
            .handle_fetch(
                &AllowAll,
                "anonymous-lan-admin",
                FetchOutcome::Candidate {
                    digest: digest("abc", "digest-1"),
                    diagnostics: vec![],
                },
            )
            .await
            .unwrap();
        let revision = service
            .activate(
                &AllowAll,
                "anonymous-lan-admin",
                &digest("abc", "digest-1"),
                true,
                true,
                Some("op-1"),
            )
            .await
            .unwrap();
        assert_eq!(revision.commit_sha, "abc");
        let active = port.active_revision().await.unwrap().unwrap();
        assert_eq!(active.content_digest, "digest-1");
        // The activation is audited: the intent names the action, carries
        // the commit SHA, and is correlated with the operation.
        let intents = audit.intents.lock().unwrap();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].action, "source.activate");
        assert!(
            intents[0]
                .metadata
                .entries()
                .any(|(key, value)| key == "commitSha" && value == "abc"),
            "the intent carries the commit SHA"
        );
        assert!(intents[0].operation_id.is_some());
    }

    #[tokio::test]
    async fn a_denied_fetch_or_activation_never_touches_state() {
        #[derive(Debug)]
        struct DenyAll;
        impl Authorizer for DenyAll {
            fn decide(&self, _request: AccessRequest<'_>) -> Decision {
                Decision::deny(crate::authz::ReasonId::UnknownPrincipal)
            }
        }
        let (service, _, port) = service();
        let outcome = FetchOutcome::Candidate {
            digest: digest("abc", "d"),
            diagnostics: vec![],
        };
        assert!(service.handle_fetch(&DenyAll, "x", outcome).await.is_err());
        assert!(
            service
                .activate(&DenyAll, "x", &digest("abc", "d"), true, true, None)
                .await
                .is_err()
        );
        assert!(port.active_revision().await.unwrap().is_none());
        assert!(port.prior_revisions().await.unwrap().is_empty());
    }
}
