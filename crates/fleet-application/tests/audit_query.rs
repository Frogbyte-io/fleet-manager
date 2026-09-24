use std::sync::Arc;

use fleet_application::audit::{
    AuditFilter, AuditPage, AuditQueries, AuditQueryError, AuditQueryPort,
};
use fleet_application::authz::{AccessRequest, Decision, ReasonId};

#[derive(Debug)]
struct RecordingPort {
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl AuditQueryPort for RecordingPort {
    async fn query(&self, _filter: &AuditFilter) -> Result<AuditPage, String> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(AuditPage {
            events: Vec::new(),
            next_seq: None,
        })
    }
}

#[derive(Debug)]
struct DenyAll;

impl fleet_application::authz::Authorizer for DenyAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

#[tokio::test]
async fn audit_query_authorization_is_checked_before_storage() {
    let port = Arc::new(RecordingPort {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let queries = AuditQueries::new(port.clone());
    let result = queries
        .list(&DenyAll, "unauthorized", AuditFilter::default())
        .await;

    assert!(matches!(result, Err(AuditQueryError::Denied(_))));
    assert_eq!(port.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[derive(Debug)]
struct PermitAll;

impl fleet_application::authz::Authorizer for PermitAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[tokio::test]
async fn malformed_audit_filters_are_rejected_before_storage() {
    let port = Arc::new(RecordingPort {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let queries = AuditQueries::new(port.clone());
    for filter in [
        AuditFilter {
            outcome: Some("unknown".to_owned()),
            ..AuditFilter::default()
        },
        AuditFilter {
            from: Some(20),
            to: Some(10),
            ..AuditFilter::default()
        },
    ] {
        assert!(matches!(
            queries.list(&PermitAll, "operator", filter).await,
            Err(AuditQueryError::Invalid { .. })
        ));
    }
    assert_eq!(port.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}
