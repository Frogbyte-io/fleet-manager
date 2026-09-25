//! The node enrollment repository: the SQLite implementation of the
//! application's [`NodePort`].
//!
//! Every security-state mutation here runs in one `BEGIN IMMEDIATE`
//! transaction, and the transactional ones write their audit intent inside
//! that same transaction, so an accepted action and its audit record commit
//! together. Single use is a compare-and-set (`UPDATE … WHERE status =
//! 'pending'`), so concurrent claims race through the database rather than
//! through application locking: exactly one wins, and the losers are
//! classified honestly as used or expired.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use fleet_application::node::{
    ChallengePurpose, EnrollClaim, EnrolledNode, EnrollmentTokenRecord, EnrollmentTokenView,
    GatewayState, NewChallenge, NewEnrollmentToken, NodeChallenge, NodeCredential, NodeIdentity,
    NodePort, NodePortError, NodeSessionIssued, NodeStatus, NodeView, RevokeClaim, RotateClaim,
    RotationOutcome, SessionClaim, SessionValidity, TokenFacts,
};

use crate::audit::append_intent_tx;

/// The node repository over a pool.
#[derive(Debug)]
pub struct NodeRepository {
    pool: SqlitePool,
}

impl NodeRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NodePort for NodeRepository {
    async fn create_token(
        &self,
        new: &NewEnrollmentToken,
    ) -> Result<EnrollmentTokenRecord, NodePortError> {
        let id = Uuid::now_v7().to_string();
        let result = sqlx::query(
            "INSERT INTO node_enrollment_tokens \
             (id, machine_id, token_hash, status, created_by, created_at, expires_at) \
             VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6)",
        )
        .bind(&id)
        .bind(&new.machine_id)
        .bind(&new.token_hash)
        .bind(&new.created_by)
        .bind(new.now)
        .bind(new.now + new.ttl_millis)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(EnrollmentTokenRecord {
                id,
                machine_id: new.machine_id.clone(),
                expires_at: new.now + new.ttl_millis,
            }),
            Err(error) if is_foreign_key_violation(&error) => Err(NodePortError::NotFound {
                what: format!("machine {:?}", new.machine_id),
            }),
            Err(error) => Err(backend("create_token", &error)),
        }
    }

    async fn list_tokens(
        &self,
        machine_id: &str,
        now: i64,
    ) -> Result<Vec<EnrollmentTokenView>, NodePortError> {
        let rows = sqlx::query(
            "SELECT id, machine_id, status, created_at, expires_at, consumed_at \
             FROM node_enrollment_tokens WHERE machine_id = ?1 ORDER BY created_at DESC",
        )
        .bind(machine_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("list_tokens", &error))?;
        Ok(rows.iter().map(|row| token_view(row, now)).collect())
    }

    async fn token_facts(&self, token_hash: &str) -> Result<Option<TokenFacts>, NodePortError> {
        let row = sqlx::query(
            "SELECT id, machine_id, status, expires_at FROM node_enrollment_tokens \
             WHERE token_hash = ?1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| backend("token_facts", &error))?;
        Ok(row.map(|row| TokenFacts {
            id: row.get("id"),
            machine_id: row.get("machine_id"),
            status: row.get("status"),
            expires_at: row.get("expires_at"),
        }))
    }

    async fn enroll(&self, claim: &EnrollClaim) -> Result<EnrolledNode, NodePortError> {
        let mut tx = self.begin("enroll").await?;

        let token = sqlx::query(
            "SELECT id, machine_id, status, expires_at FROM node_enrollment_tokens \
             WHERE token_hash = ?1",
        )
        .bind(&claim.token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| backend_tx("enroll_token", &error))?;
        let Some(token) = token else {
            return Err(NodePortError::NotFound {
                what: "enrollment token".to_owned(),
            });
        };
        let machine_id: String = token.get("machine_id");
        claim_token(&mut tx, token.get("id"), claim.now).await?;

        let machine_exists: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM machines WHERE id = ?1")
                .bind(&machine_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|error| backend_tx("enroll_machine", &error))?;
        if machine_exists.is_none() {
            return Err(NodePortError::NotFound {
                what: "machine".to_owned(),
            });
        }

        let (key_version, rebind) = bind_identity(&mut tx, &machine_id, claim).await?;

        let credential_id = Uuid::now_v7().to_string();
        let expires_at = claim.now + claim.credential_ttl_millis;
        sqlx::query(
            "INSERT INTO node_credentials \
             (id, machine_id, key_version, issued_at, expires_at, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'active')",
        )
        .bind(&credential_id)
        .bind(&machine_id)
        .bind(key_version)
        .bind(claim.now)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("enroll_credential", &error))?;

        append_intent_tx(&mut tx, &claim.audit)
            .await
            .map_err(|detail| NodePortError::Backend {
                detail: format!("audit: {detail}"),
            })?;
        tx.commit()
            .await
            .map_err(|error| backend_tx("enroll", &error))?;

        Ok(EnrolledNode {
            machine_id,
            credential_id,
            node_key_version: key_version,
            credential_expires_at: expires_at,
            rebind,
        })
    }

    async fn identity(&self, machine_id: &str) -> Result<Option<NodeIdentity>, NodePortError> {
        let row = sqlx::query(
            "SELECT machine_id, public_key, key_version, status, os, arch, node_version, \
             enrolled_at, rotated_at, gateway_state, last_seen_at, boot_session_id \
             FROM node_identities WHERE machine_id = ?1",
        )
        .bind(machine_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| backend("identity", &error))?;
        Ok(row.map(|row| NodeIdentity {
            machine_id: row.get("machine_id"),
            public_key: row.get("public_key"),
            key_version: row.get("key_version"),
            status: NodeStatus::from_id(&row.get::<String, _>("status"))
                .unwrap_or(NodeStatus::Active),
            os: row.get("os"),
            arch: row.get("arch"),
            node_version: row.get("node_version"),
            enrolled_at: row.get("enrolled_at"),
            rotated_at: row.get("rotated_at"),
            gateway_state: GatewayState::from_id(&row.get::<String, _>("gateway_state"))
                .unwrap_or(GatewayState::Offline),
            last_seen_at: row.get("last_seen_at"),
            boot_session_id: row.get("boot_session_id"),
        }))
    }

    async fn issue_challenge(&self, new: &NewChallenge) -> Result<NodeChallenge, NodePortError> {
        let mut tx = self.begin("issue_challenge").await?;
        let identity = sqlx::query("SELECT status FROM node_identities WHERE machine_id = ?1")
            .bind(&new.machine_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| backend_tx("issue_challenge", &error))?;
        match identity {
            None => {
                return Err(NodePortError::NotFound {
                    what: "node identity".to_owned(),
                });
            }
            Some(row) if row.get::<String, _>("status") != "active" => {
                return Err(NodePortError::Rejected {
                    detail: "the node identity is revoked".to_owned(),
                });
            }
            Some(_) => {}
        }
        let id = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO node_challenges \
             (id, machine_id, nonce, purpose, new_public_key, issued_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(&id)
        .bind(&new.machine_id)
        .bind(&new.nonce)
        .bind(new.purpose.id())
        .bind(&new.new_public_key)
        .bind(new.now)
        .bind(new.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("issue_challenge_insert", &error))?;
        tx.commit()
            .await
            .map_err(|error| backend_tx("issue_challenge", &error))?;
        Ok(NodeChallenge {
            id,
            machine_id: new.machine_id.clone(),
            nonce: new.nonce.clone(),
            purpose: new.purpose,
            new_public_key: new.new_public_key.clone(),
            expires_at: new.expires_at,
        })
    }

    async fn challenge(&self, challenge_id: &str) -> Result<Option<NodeChallenge>, NodePortError> {
        let row = sqlx::query(
            "SELECT id, machine_id, nonce, purpose, new_public_key, expires_at, consumed_at \
             FROM node_challenges WHERE id = ?1",
        )
        .bind(challenge_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| backend("challenge", &error))?;
        Ok(row.map(|row| NodeChallenge {
            id: row.get("id"),
            machine_id: row.get("machine_id"),
            nonce: row.get("nonce"),
            purpose: ChallengePurpose::from_id(&row.get::<String, _>("purpose"))
                .unwrap_or(ChallengePurpose::Session),
            new_public_key: row.get("new_public_key"),
            expires_at: row.get("expires_at"),
        }))
    }

    async fn credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<NodeCredential>, NodePortError> {
        let row = sqlx::query(
            "SELECT id, machine_id, key_version, issued_at, expires_at, status, last_used_at \
             FROM node_credentials WHERE id = ?1",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| backend("credential", &error))?;
        Ok(row.map(|row| NodeCredential {
            id: row.get("id"),
            machine_id: row.get("machine_id"),
            node_key_version: row.get("key_version"),
            issued_at: row.get("issued_at"),
            expires_at: row.get("expires_at"),
            status: NodeStatus::from_id(&row.get::<String, _>("status"))
                .unwrap_or(NodeStatus::Active),
            last_used_at: row.get("last_used_at"),
        }))
    }

    async fn consume_challenge_and_issue_session(
        &self,
        claim: &SessionClaim,
    ) -> Result<NodeSessionIssued, NodePortError> {
        let mut tx = self.begin("issue_session").await?;

        let consumed = sqlx::query(
            "UPDATE node_challenges SET consumed_at = ?2 \
             WHERE id = ?1 AND consumed_at IS NULL AND expires_at > ?2",
        )
        .bind(&claim.challenge_id)
        .bind(claim.now)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("session_consume", &error))?;
        if consumed.rows_affected() == 0 {
            return Err(classify_challenge(&mut tx, &claim.challenge_id).await?);
        }
        let challenge =
            sqlx::query("SELECT machine_id, purpose FROM node_challenges WHERE id = ?1")
                .bind(&claim.challenge_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|error| backend_tx("session_challenge", &error))?;
        if challenge.get::<String, _>("purpose") != "session" {
            return Err(NodePortError::Rejected {
                detail: "the challenge is not for a session proof".to_owned(),
            });
        }

        let (machine_id, credential_key_version) =
            live_credential_tx(&mut tx, &claim.credential_id, claim.now).await?;
        if challenge.get::<String, _>("machine_id") != machine_id {
            return Err(NodePortError::Rejected {
                detail: "the challenge does not belong to this credential's machine".to_owned(),
            });
        }

        let identity =
            sqlx::query("SELECT status, key_version FROM node_identities WHERE machine_id = ?1")
                .bind(&machine_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|error| backend_tx("session_identity", &error))?
                .ok_or(NodePortError::Rejected {
                    detail: "the machine has no node identity".to_owned(),
                })?;
        if identity.get::<String, _>("status") != "active"
            || identity.get::<i64, _>("key_version") != credential_key_version
        {
            return Err(NodePortError::Rejected {
                detail: "the node identity is revoked or the key has rotated".to_owned(),
            });
        }

        let session_id = Uuid::now_v7().to_string();
        let expires_at = claim.now + claim.session_ttl_millis;
        sqlx::query(
            "INSERT INTO node_sessions \
             (id, machine_id, credential_id, issued_at, expires_at, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'active')",
        )
        .bind(&session_id)
        .bind(&machine_id)
        .bind(&claim.credential_id)
        .bind(claim.now)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("session_insert", &error))?;

        append_intent_tx(&mut tx, &claim.audit)
            .await
            .map_err(|detail| NodePortError::Backend {
                detail: format!("audit: {detail}"),
            })?;
        tx.commit()
            .await
            .map_err(|error| backend_tx("issue_session", &error))?;
        Ok(NodeSessionIssued {
            session_id,
            machine_id,
            credential_id: claim.credential_id.clone(),
            expires_at,
        })
    }

    async fn rotate_key(&self, claim: &RotateClaim) -> Result<RotationOutcome, NodePortError> {
        let mut tx = self.begin("rotate").await?;

        let consumed = sqlx::query(
            "UPDATE node_challenges SET consumed_at = ?2 \
             WHERE id = ?1 AND consumed_at IS NULL AND expires_at > ?2",
        )
        .bind(&claim.challenge_id)
        .bind(claim.now)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("rotate_consume", &error))?;
        if consumed.rows_affected() == 0 {
            return Err(classify_challenge(&mut tx, &claim.challenge_id).await?);
        }
        let challenge = sqlx::query(
            "SELECT machine_id, purpose, new_public_key FROM node_challenges WHERE id = ?1",
        )
        .bind(&claim.challenge_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| backend_tx("rotate_challenge", &error))?;
        if challenge.get::<String, _>("purpose") != "rotate"
            || challenge
                .get::<Option<String>, _>("new_public_key")
                .as_deref()
                != Some(claim.new_public_key.as_str())
        {
            return Err(NodePortError::Rejected {
                detail: "the challenge does not match this rotation".to_owned(),
            });
        }

        let (machine_id, credential_key_version) =
            live_credential_tx(&mut tx, &claim.credential_id, claim.now).await?;
        if challenge.get::<String, _>("machine_id") != machine_id {
            return Err(NodePortError::Rejected {
                detail: "the challenge does not belong to this credential's machine".to_owned(),
            });
        }

        // The rotation itself: bump the key version, revoke every outstanding
        // credential and session, mint one credential for the new key.
        let rotated = sqlx::query(
            "UPDATE node_identities SET public_key = ?2, key_version = key_version + 1, \
             rotated_at = ?3, status = 'active' WHERE machine_id = ?1 AND status = 'active'",
        )
        .bind(&machine_id)
        .bind(&claim.new_public_key)
        .bind(claim.now)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("rotate_identity", &error))?;
        if rotated.rows_affected() == 0 {
            return Err(NodePortError::Rejected {
                detail: "the node identity is revoked".to_owned(),
            });
        }
        sqlx::query(
            "UPDATE node_credentials SET status = 'revoked' WHERE machine_id = ?1 AND status = 'active'",
        )
        .bind(&machine_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("rotate_revoke_credentials", &error))?;
        sqlx::query(
            "UPDATE node_sessions SET status = 'revoked' WHERE machine_id = ?1 AND status = 'active'",
        )
        .bind(&machine_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("rotate_revoke_sessions", &error))?;

        let new_credential_id = Uuid::now_v7().to_string();
        let new_key_version = credential_key_version + 1;
        let expires_at = claim.now + claim.credential_ttl_millis;
        sqlx::query(
            "INSERT INTO node_credentials \
             (id, machine_id, key_version, issued_at, expires_at, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'active')",
        )
        .bind(&new_credential_id)
        .bind(&machine_id)
        .bind(new_key_version)
        .bind(claim.now)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("rotate_credential_insert", &error))?;

        append_intent_tx(&mut tx, &claim.audit)
            .await
            .map_err(|detail| NodePortError::Backend {
                detail: format!("audit: {detail}"),
            })?;
        tx.commit()
            .await
            .map_err(|error| backend_tx("rotate", &error))?;
        Ok(RotationOutcome {
            machine_id,
            credential_id: new_credential_id,
            node_key_version: new_key_version,
            credential_expires_at: expires_at,
        })
    }

    async fn revoke_identity(&self, claim: &RevokeClaim) -> Result<u64, NodePortError> {
        let mut tx = self.begin("revoke").await?;
        let updated = sqlx::query(
            "UPDATE node_identities SET status = 'revoked' WHERE machine_id = ?1 AND status = 'active'",
        )
        .bind(&claim.machine_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("revoke_identity", &error))?;
        if updated.rows_affected() == 0 {
            return Err(NodePortError::NotFound {
                what: format!("active node identity of machine {:?}", claim.machine_id),
            });
        }
        sqlx::query(
            "UPDATE node_credentials SET status = 'revoked' WHERE machine_id = ?1 AND status = 'active'",
        )
        .bind(&claim.machine_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("revoke_credentials", &error))?;
        sqlx::query(
            "UPDATE node_sessions SET status = 'revoked' WHERE machine_id = ?1 AND status = 'active'",
        )
        .bind(&claim.machine_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("revoke_sessions", &error))?;
        let invalidated = sqlx::query(
            "UPDATE node_enrollment_tokens SET status = 'consumed', consumed_at = ?2 \
             WHERE machine_id = ?1 AND status = 'pending'",
        )
        .bind(&claim.machine_id)
        .bind(claim.now)
        .execute(&mut *tx)
        .await
        .map_err(|error| backend_tx("revoke_enrollment_tokens", &error))?
        .rows_affected();
        let mut audit = claim.audit.clone();
        audit
            .metadata
            .insert("invalidatedEnrollmentCount", &invalidated.to_string())
            .map_err(|error| NodePortError::Backend {
                detail: format!("revoke audit metadata: {error}"),
            })?;
        append_intent_tx(&mut tx, &audit)
            .await
            .map_err(|detail| NodePortError::Backend {
                detail: format!("revoke audit: {detail}"),
            })?;
        tx.commit()
            .await
            .map_err(|error| backend_tx("revoke", &error))?;
        Ok(invalidated)
    }

    async fn node_view(
        &self,
        machine_id: &str,
        now: i64,
    ) -> Result<Option<NodeView>, NodePortError> {
        let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM machines WHERE id = ?1")
            .bind(machine_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| backend("node_view", &error))?;
        if exists.is_none() {
            return Ok(None);
        }
        let identity = self.identity(machine_id).await?;
        let token_rows = sqlx::query(
            "SELECT id, machine_id, status, created_at, expires_at, consumed_at \
             FROM node_enrollment_tokens WHERE machine_id = ?1 AND status = 'pending' \
             AND expires_at > ?2 ORDER BY created_at DESC",
        )
        .bind(machine_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("node_view_tokens", &error))?;
        let credential_rows = sqlx::query(
            "SELECT id, machine_id, key_version, issued_at, expires_at, status, last_used_at \
             FROM node_credentials WHERE machine_id = ?1 AND status = 'active' AND expires_at > ?2 \
             ORDER BY issued_at DESC",
        )
        .bind(machine_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("node_view_credentials", &error))?;
        let active_sessions: i64 = sqlx::query(
            "SELECT COUNT(*) FROM node_sessions WHERE machine_id = ?1 AND status = 'active' \
             AND expires_at > ?2",
        )
        .bind(machine_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| backend("node_view_sessions", &error))?
        .get(0);

        Ok(Some(NodeView {
            machine_id: machine_id.to_owned(),
            identity,
            pending_tokens: token_rows.iter().map(|row| token_view(row, now)).collect(),
            active_credentials: credential_rows
                .iter()
                .map(|row| NodeCredential {
                    id: row.get("id"),
                    machine_id: row.get("machine_id"),
                    node_key_version: row.get("key_version"),
                    issued_at: row.get("issued_at"),
                    expires_at: row.get("expires_at"),
                    status: NodeStatus::from_id(&row.get::<String, _>("status"))
                        .unwrap_or(NodeStatus::Active),
                    last_used_at: row.get("last_used_at"),
                })
                .collect(),
            active_sessions,
        }))
    }

    async fn validate_session(
        &self,
        session_id: &str,
        now: i64,
    ) -> Result<SessionValidity, NodePortError> {
        let row = sqlx::query(
            "SELECT machine_id, credential_id, status, expires_at FROM node_sessions WHERE id = ?1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| backend("validate_session", &error))?;
        let Some(session) = row else {
            return Ok(SessionValidity::Invalid {
                detail: "the session does not exist".to_owned(),
            });
        };
        if session.get::<String, _>("status") != "active"
            || session.get::<i64, _>("expires_at") <= now
        {
            return Ok(SessionValidity::Invalid {
                detail: "the session is revoked or expired".to_owned(),
            });
        }
        let machine_id: String = session.get("machine_id");
        let credential_id: String = session.get("credential_id");
        let Some(credential) = self.credential(&credential_id).await? else {
            return Ok(SessionValidity::Invalid {
                detail: "the session's credential does not exist".to_owned(),
            });
        };
        if credential.status != NodeStatus::Active || credential.expires_at <= now {
            return Ok(SessionValidity::Invalid {
                detail: "the session's credential is revoked or expired".to_owned(),
            });
        }
        let Some(identity) = self.identity(&machine_id).await? else {
            return Ok(SessionValidity::Invalid {
                detail: "the machine has no node identity".to_owned(),
            });
        };
        if identity.status != NodeStatus::Active
            || identity.key_version != credential.node_key_version
        {
            return Ok(SessionValidity::Invalid {
                detail: "the node identity is revoked or the key has rotated".to_owned(),
            });
        }
        Ok(SessionValidity::Valid {
            machine_id,
            credential_id,
        })
    }

    async fn touch_credential(
        &self,
        credential_id: &str,
        used_at: i64,
    ) -> Result<(), NodePortError> {
        sqlx::query("UPDATE node_credentials SET last_used_at = ?2 WHERE id = ?1")
            .bind(credential_id)
            .bind(used_at)
            .execute(&self.pool)
            .await
            .map_err(|error| backend("touch_credential", &error))?;
        Ok(())
    }

    async fn record_gateway_state(
        &self,
        machine_id: &str,
        state: GatewayState,
        boot_session: Option<&str>,
        last_seen: i64,
    ) -> Result<(), NodePortError> {
        let updated = sqlx::query(
            "UPDATE node_identities SET gateway_state = ?2, last_seen_at = ?3, \
             boot_session_id = ?4 WHERE machine_id = ?1",
        )
        .bind(machine_id)
        .bind(state.id())
        .bind(last_seen)
        .bind(boot_session)
        .execute(&self.pool)
        .await
        .map_err(|error| backend("record_gateway_state", &error))?;
        if updated.rows_affected() == 0 {
            return Err(NodePortError::NotFound {
                what: format!("node identity of machine {machine_id:?}"),
            });
        }
        Ok(())
    }
}

impl NodeRepository {
    /// Begins a write transaction with `BEGIN IMMEDIATE`, the store's write
    /// discipline.
    async fn begin(
        &self,
        context: &'static str,
    ) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, NodePortError> {
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| backend(context, &error))
    }
}

/// The single-use token claim: a compare-and-set that only a still-pending,
/// unexpired token survives. Concurrent claims of the same token race here,
/// and exactly one commit wins; the losers are classified honestly.
async fn claim_token(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    token_id: &str,
    now: i64,
) -> Result<(), NodePortError> {
    let claimed = sqlx::query(
        "UPDATE node_enrollment_tokens SET status = 'consumed', consumed_at = ?2 \
         WHERE id = ?1 AND status = 'pending' AND expires_at > ?2",
    )
    .bind(token_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|error| backend_tx("enroll_claim", &error))?;
    if claimed.rows_affected() == 0 {
        let status: String = sqlx::query("SELECT status FROM node_enrollment_tokens WHERE id = ?1")
            .bind(token_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(|error| backend_tx("enroll_classify", &error))?
            .get(0);
        return Err(if status == "consumed" {
            NodePortError::AlreadyUsed {
                what: "enrollment token".to_owned(),
            }
        } else {
            NodePortError::Expired {
                what: "enrollment token".to_owned(),
            }
        });
    }
    Ok(())
}

/// Inserts or re-binds the node identity inside the enrollment transaction.
/// A machine that already has an active identity is refused — rotation, not
/// enrollment, changes a live identity. Re-enrollment over a *revoked*
/// identity is the explicit path: a fresh operator token, a new key, and a
/// version bump so every old credential stays invalid.
async fn bind_identity(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    machine_id: &str,
    claim: &EnrollClaim,
) -> Result<(i64, bool), NodePortError> {
    let existing =
        sqlx::query("SELECT key_version, status FROM node_identities WHERE machine_id = ?1")
            .bind(machine_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| backend_tx("enroll_identity", &error))?;
    match existing {
        Some(row) if row.get::<String, _>("status") == "active" => Err(NodePortError::Conflict {
            detail: "the machine already has an active node identity; rotate the key instead"
                .to_owned(),
        }),
        Some(row) => {
            let version = row.get::<i64, _>("key_version") + 1;
            sqlx::query(
                "UPDATE node_identities SET public_key = ?2, key_version = ?3, status = 'active', \
                 os = ?4, arch = ?5, node_version = ?6, rotated_at = ?7, gateway_state = 'offline', \
                 boot_session_id = NULL WHERE machine_id = ?1",
            )
            .bind(machine_id)
            .bind(&claim.public_key)
            .bind(version)
            .bind(&claim.os)
            .bind(&claim.arch)
            .bind(&claim.node_version)
            .bind(claim.now)
            .execute(&mut **tx)
            .await
            .map_err(|error| backend_tx("enroll_rebind", &error))?;
            Ok((version, true))
        }
        None => {
            sqlx::query(
                "INSERT INTO node_identities \
                 (machine_id, public_key, key_version, status, os, arch, node_version, enrolled_at) \
                 VALUES (?1, ?2, 1, 'active', ?3, ?4, ?5, ?6)",
            )
            .bind(machine_id)
            .bind(&claim.public_key)
            .bind(&claim.os)
            .bind(&claim.arch)
            .bind(&claim.node_version)
            .bind(claim.now)
            .execute(&mut **tx)
            .await
            .map_err(|error| backend_tx("enroll_insert", &error))?;
            Ok((1, false))
        }
    }
}

/// The credential gate both challenge-claim transactions share: the
/// credential must exist, be active, be unexpired, and belong to the
/// challenge's machine. Returns its machine and key version.
async fn live_credential_tx(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    credential_id: &str,
    now: i64,
) -> Result<(String, i64), NodePortError> {
    let credential = sqlx::query(
        "SELECT machine_id, key_version, status, expires_at FROM node_credentials WHERE id = ?1",
    )
    .bind(credential_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| backend_tx("credential_gate", &error))?
    .ok_or(NodePortError::NotFound {
        what: "credential".to_owned(),
    })?;
    if credential.get::<String, _>("status") != "active"
        || credential.get::<i64, _>("expires_at") <= now
    {
        return Err(NodePortError::Rejected {
            detail: "the credential is revoked or expired".to_owned(),
        });
    }
    Ok((credential.get("machine_id"), credential.get("key_version")))
}

/// Classifies why a challenge could not be consumed, after the CAS lost.
async fn classify_challenge(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    challenge_id: &str,
) -> Result<NodePortError, NodePortError> {
    let row = sqlx::query("SELECT consumed_at, expires_at FROM node_challenges WHERE id = ?1")
        .bind(challenge_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| backend_tx("challenge_classify", &error))?;
    Ok(match row {
        None => NodePortError::NotFound {
            what: "challenge".to_owned(),
        },
        Some(row) if row.get::<i64, _>("expires_at") <= epoch_millis() => NodePortError::Expired {
            what: "challenge".to_owned(),
        },
        Some(_) => NodePortError::AlreadyUsed {
            what: "challenge".to_owned(),
        },
    })
}

/// Computes a token view's effective status against the read time.
fn token_view(row: &sqlx::sqlite::SqliteRow, now: i64) -> EnrollmentTokenView {
    let stored: String = row.get("status");
    let consumed_at: Option<i64> = row.get("consumed_at");
    let expires_at: i64 = row.get("expires_at");
    let status = if consumed_at.is_some() {
        "consumed".to_owned()
    } else if expires_at <= now {
        "expired".to_owned()
    } else {
        stored
    };
    EnrollmentTokenView {
        id: row.get("id"),
        machine_id: row.get("machine_id"),
        status,
        created_at: row.get("created_at"),
        expires_at,
        consumed_at,
    }
}

fn backend(context: &'static str, error: &sqlx::Error) -> NodePortError {
    NodePortError::Backend {
        detail: format!("{context}: {error}"),
    }
}

fn backend_tx(context: &'static str, error: &sqlx::Error) -> NodePortError {
    backend(context, error)
}

fn is_foreign_key_violation(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database_error| {
        database_error.kind() == sqlx::error::ErrorKind::ForeignKeyViolation
    })
}

fn epoch_millis() -> i64 {
    fleet_core::SystemClock::now_unix_millis()
}
