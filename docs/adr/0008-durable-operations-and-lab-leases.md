# ADR 0008: Durable operations and explicit Lab leases

Status: Accepted  
Proposed: 2026-08-25  
Accepted: 2026-08-25 (FM-000)

## Context

Remote commands and Proxmox work outlive API requests and fail across process/network boundaries. Disposable VMs and exclusive hardware cannot rely on an in-memory job or a boolean VM state without leaking resources.

## Decision

Represent accepted work as durable operations with actor, authorization, idempotency, deadline, progress, cancellation, result, and audit correlation. Represent Lab leases, instances, and resource reservations as separate persistent state machines with cleanup compensation and external reconciliation. Delivery to nodes/providers is at least once.

## Consequences

- Mutating APIs return operation/lease handles.
- Nodes deduplicate command IDs; providers classify retry/idempotency.
- Scheduler transactions reserve internal resources before external calls, then sagas reconcile/compensate.
- Failure injection and restart recovery are release gates.
- A generic embedded queue such as Effectum may execute work, but it cannot replace Fleet's domain operation/lease records.

## Rejected

- Fire-and-forget Tokio tasks as accepted work.
- Treating Proxmox power state as Lab lease state.
- Exactly-once delivery claims or best-effort expiry cleanup.
