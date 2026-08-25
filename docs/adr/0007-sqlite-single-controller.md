# ADR 0007: SQLite and one active controller initially

Status: Accepted  
Proposed: 2026-08-25  
Accepted: 2026-08-25 (FM-000)

## Context

The default installation should remain a simple self-hosted Compose deployment. PostgreSQL and multi-controller coordination add operational cost without current scale evidence, but runtime state and work must survive restart.

## Decision

Use SQLx with SQLite WAL, explicit migrations, short bounded transactions, backup/restore tooling, and one active controller per data directory. Design application repository ports around domain needs, not a fake lowest-common-denominator SQL abstraction. Record scale/HA metrics before a PostgreSQL ADR.

## Consequences

- No external database is required for the first release.
- Network filesystems and multiple controllers against one SQLite file are unsupported.
- Background operations and reservations need database constraints and restart recovery.
- PostgreSQL/multi-controller support is a real migration with distributed coordination, not a configuration flag promised now.

## Rejected

- In-memory/runtime JSON files.
- PostgreSQL as a mandatory default.
- Claiming transparent SQLite/PostgreSQL interchangeability before queries and concurrency needs exist.
