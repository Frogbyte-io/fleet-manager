# ADR 0004: Separate desired, runtime, and secret state

Status: Accepted  
Proposed: 2026-08-25  
Accepted: 2026-08-25 (FM-000)

## Context

Git is useful for reviewable desired state but unsuitable for volatile observations, coordination, leases, audit, and secrets. A controller database alone would lose the requested optional GitOps authority and human workflow.

## Decision

An optional Git repository is canonical for versioned non-secret desired resources. Controller SQLite owns runtime/observed state, operations, leases, audit, caches, and the active imported revision. Controller credentials are individually encrypted; the master key is mounted separately. Frogenv owns project environment secrets and its machine keys.

## Consequences

- Status is forbidden in Fleet Git.
- Invalid Git revisions never replace the last valid active revision.
- Secret references, not values, appear in desired resources and operations.
- Backup and recovery must document database, artifacts, Git revision, and separate key recovery.

## Rejected

- Git as runtime/event/lease database.
- Plaintext credentials in YAML or environment-only singleton configuration.
- Fleet reading Frogenv's encrypted repository internals or displaying decrypted values.
