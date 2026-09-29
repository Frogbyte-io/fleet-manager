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

/// One validated desired resource held by a revision's snapshot. The
/// snapshot is a rebuildable cache of the Git revision, not a second
/// desired-state authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesiredResourceRecord {
    /// The resource kind id.
    pub kind: String,
    /// The stable resource identity.
    pub id: String,
    /// The mutable human-facing label.
    pub name: String,
    /// The kind-specific non-secret spec.
    pub spec: serde_json::Value,
}

/// The active revision with what its snapshot holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveSummary {
    /// The active revision.
    pub revision: ActiveRevision,
    /// When it was activated (epoch milliseconds).
    pub activated_at: i64,
    /// Whether a snapshot of its resources is held. A revision activated
    /// before snapshots existed has none until it is fetched again.
    pub snapshot_held: bool,
    /// The number of held resources per kind.
    pub kind_counts: std::collections::BTreeMap<String, i64>,
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
    /// The digests of prior valid revisions, for manual rollback.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn prior_revisions(&self) -> Result<Vec<ActiveRevision>, String>;
    /// Records a candidate's digest as a prior valid revision together
    /// with its validated resources, in one transaction (only valid
    /// candidates are recorded — a candidate carrying diagnostics is
    /// reported and forgotten). Recording the same revision again keeps
    /// the first snapshot: a digest names its content.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn record_valid_revision(
        &self,
        revision: &ActiveRevision,
        resources: &[DesiredResourceRecord],
    ) -> Result<(), String>;
    /// Whether a snapshot of the revision's resources is held.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn snapshot_held(&self, revision: &ActiveRevision) -> Result<bool, String>;
    /// The active revision with its snapshot summary.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn active_summary(&self) -> Result<Option<ActiveSummary>, String>;
    /// The active revision's resources ordered by identity: at most
    /// `limit` after the `after` identity, optionally of one kind.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn active_resources(
        &self,
        kind: Option<&str>,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DesiredResourceRecord>, String>;
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
        /// The validated resources; empty whenever `diagnostics` is not.
        resources: Vec<DesiredResourceRecord>,
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
                ref resources,
            } => {
                if diagnostics.is_empty() {
                    self.port
                        .record_valid_revision(
                            &ActiveRevision {
                                commit_sha: digest.commit_sha.clone(),
                                content_digest: digest.content_digest.clone(),
                            },
                            resources,
                        )
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
        // Activation only switches to a revision whose resources are held:
        // an active revision the controller cannot read is no state at all.
        let target = ActiveRevision {
            commit_sha: digest.commit_sha.clone(),
            content_digest: digest.content_digest.clone(),
        };
        if !self.port.snapshot_held(&target).await.map_err(|detail| {
            crate::project::ProjectUseCaseError::Backend {
                context: "source_verify",
                detail,
            }
        })? {
            return Err(crate::project::ProjectUseCaseError::Invalid {
                detail: "the revision holds no resource snapshot; fetch it again before activating"
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

    /// The active revision and what its snapshot holds.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn status(
        &self,
        authorizer: &dyn crate::authz::Authorizer,
        principal_id: &str,
    ) -> Result<Option<ActiveSummary>, crate::project::ProjectUseCaseError> {
        Self::authorize_read(authorizer, principal_id)?;
        self.port.active_summary().await.map_err(|detail| {
            crate::project::ProjectUseCaseError::Backend {
                context: "source_status",
                detail,
            }
        })
    }

    /// The active revision's resources, ordered by identity: up to
    /// `limit + 1` entries after the cursor so the caller can tell whether
    /// more follow.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn resources(
        &self,
        authorizer: &dyn crate::authz::Authorizer,
        principal_id: &str,
        kind: Option<&str>,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DesiredResourceRecord>, crate::project::ProjectUseCaseError> {
        Self::authorize_read(authorizer, principal_id)?;
        self.port
            .active_resources(kind, after, limit.saturating_add(1))
            .await
            .map_err(|detail| crate::project::ProjectUseCaseError::Backend {
                context: "source_resources",
                detail,
            })
    }

    fn authorize_read(
        authorizer: &dyn crate::authz::Authorizer,
        principal_id: &str,
    ) -> Result<(), crate::project::ProjectUseCaseError> {
        use crate::authz::{AccessRequest, Permission, authorize};
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::SourceFetch,
                resource: None,
            },
        )
        .map(|_| ())
        .map_err(crate::project::ProjectUseCaseError::Denied)
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
    use super::{
        ActiveRevision, ActiveSummary, DesiredResourceRecord, DesiredSource, FetchOutcome,
        SourcePort,
    };
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
        snapshots: Mutex<Vec<(ActiveRevision, Vec<DesiredResourceRecord>)>>,
    }

    #[async_trait::async_trait]
    impl SourcePort for FakePort {
        async fn active_revision(&self) -> Result<Option<ActiveRevision>, String> {
            Ok(self.active.lock().unwrap().clone())
        }
        async fn prior_revisions(&self) -> Result<Vec<ActiveRevision>, String> {
            Ok(self.valid.lock().unwrap().clone())
        }
        async fn record_valid_revision(
            &self,
            revision: &ActiveRevision,
            resources: &[DesiredResourceRecord],
        ) -> Result<(), String> {
            self.valid.lock().unwrap().push(revision.clone());
            self.snapshots
                .lock()
                .unwrap()
                .push((revision.clone(), resources.to_vec()));
            Ok(())
        }
        async fn snapshot_held(&self, revision: &ActiveRevision) -> Result<bool, String> {
            Ok(self
                .snapshots
                .lock()
                .unwrap()
                .iter()
                .any(|(held, _)| held == revision))
        }
        async fn active_summary(&self) -> Result<Option<ActiveSummary>, String> {
            let Some(revision) = self.active.lock().unwrap().clone() else {
                return Ok(None);
            };
            let snapshots = self.snapshots.lock().unwrap();
            let held = snapshots.iter().find(|(held, _)| *held == revision);
            let mut kind_counts = std::collections::BTreeMap::new();
            for resource in held.map(|(_, resources)| resources).into_iter().flatten() {
                *kind_counts.entry(resource.kind.clone()).or_insert(0) += 1;
            }
            Ok(Some(ActiveSummary {
                revision,
                activated_at: 1,
                snapshot_held: held.is_some(),
                kind_counts,
            }))
        }
        async fn active_resources(
            &self,
            kind: Option<&str>,
            after: Option<&str>,
            limit: i64,
        ) -> Result<Vec<DesiredResourceRecord>, String> {
            let Some(active) = self.active.lock().unwrap().clone() else {
                return Ok(vec![]);
            };
            let snapshots = self.snapshots.lock().unwrap();
            let mut resources: Vec<_> = snapshots
                .iter()
                .find(|(held, _)| *held == active)
                .map(|(_, resources)| resources.clone())
                .unwrap_or_default();
            resources.retain(|resource| {
                kind.is_none_or(|kind| resource.kind == kind)
                    && after.is_none_or(|after| resource.id.as_str() > after)
            });
            resources.sort_by(|a, b| a.id.cmp(&b.id));
            resources.truncate(usize::try_from(limit).unwrap_or(0));
            Ok(resources)
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

    fn resource(id: &str) -> DesiredResourceRecord {
        DesiredResourceRecord {
            kind: "Machine".to_owned(),
            id: id.to_owned(),
            name: id.to_owned(),
            spec: serde_json::json!({}),
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
            resources: vec![],
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
            resources: vec![],
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
                    resources: vec![resource("a"), resource("b")],
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
            resources: vec![],
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

    #[tokio::test]
    async fn activation_refuses_a_revision_without_a_snapshot() {
        let (service, _, port) = service();
        // A revision recorded before snapshots existed: known and valid,
        // but no resources are held for it.
        port.valid.lock().unwrap().push(ActiveRevision {
            commit_sha: "abc".to_owned(),
            content_digest: "old".to_owned(),
        });
        let error = service
            .activate(
                &AllowAll,
                "anonymous-lan-admin",
                &digest("abc", "old"),
                true,
                true,
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("fetch it again"), "{error}");
        assert!(port.active_revision().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_active_revisions_resources_are_readable_and_paged() {
        let (service, _, _) = service();
        service
            .handle_fetch(
                &AllowAll,
                "anonymous-lan-admin",
                FetchOutcome::Candidate {
                    digest: digest("abc", "digest-1"),
                    diagnostics: vec![],
                    resources: vec![resource("a"), resource("b"), resource("c")],
                },
            )
            .await
            .unwrap();
        assert!(
            service
                .status(&AllowAll, "anonymous-lan-admin")
                .await
                .unwrap()
                .is_none(),
            "nothing is active before an activation"
        );
        service
            .activate(
                &AllowAll,
                "anonymous-lan-admin",
                &digest("abc", "digest-1"),
                true,
                true,
                None,
            )
            .await
            .unwrap();
        let summary = service
            .status(&AllowAll, "anonymous-lan-admin")
            .await
            .unwrap()
            .unwrap();
        assert!(summary.snapshot_held);
        assert_eq!(summary.kind_counts["Machine"], 3);
        // limit 2 asks for 3: the extra entry tells the caller more follow.
        let page = service
            .resources(&AllowAll, "anonymous-lan-admin", None, None, 2)
            .await
            .unwrap();
        assert_eq!(page.len(), 3);
        let rest = service
            .resources(&AllowAll, "anonymous-lan-admin", None, Some("b"), 2)
            .await
            .unwrap();
        assert_eq!(
            rest.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["c"]
        );
    }

    #[tokio::test]
    async fn a_denied_read_reveals_nothing() {
        #[derive(Debug)]
        struct DenyAll;
        impl Authorizer for DenyAll {
            fn decide(&self, _request: AccessRequest<'_>) -> Decision {
                Decision::deny(crate::authz::ReasonId::UnknownPrincipal)
            }
        }
        let (service, _, _) = service();
        assert!(service.status(&DenyAll, "x").await.is_err());
        assert!(
            service
                .resources(&DenyAll, "x", None, None, 10)
                .await
                .is_err()
        );
    }
}
