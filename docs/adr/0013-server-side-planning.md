# ADR 0013: The controller computes plans; apply executes by plan identity

Status: Proposed

Proposed: 2026-09-29 (FM-407).

## Context

`POST /machines/{id}/apply` and `fleetctl apply` take the plan as JSON from the caller: the actions, their differences, and a caller-chosen `planId` that approvals bind to. The controller validates the shape of each action but never checks that the plan is what desired state and observations imply. A client can therefore apply actions no plan would produce, and an approval bound to a caller-chosen id proves nothing about the plan's content.

Desired state is now readable at runtime (FM-404) and a machine's observed state can be assembled from the stores (FM-406), so the controller can compute plans itself.

## Decision

1. **The controller computes plans.** `POST /machines/{id}/plans` composes the active revision's skill assignments (including the built-in default from ADR 0012) for the machine, compares them with the machine's assembled observed state, and returns the planner's output. Creating a plan requires the `apply.execute` permission for the machine and is audited.
2. **A plan's identity is a digest of its content.** The plan id is the SHA-256 of the canonical JSON of the machine id, the active revision (commit SHA and content digest), and the ordered actions with their differences. The same desired state and observations always yield the same id, and any change to what would be done yields a different one.
3. **Apply executes by plan id.** `POST /machines/{id}/plans/{planId}/apply` recomputes the plan and refuses with `409 stale_plan` when the recomputed id differs from the requested one, so a reviewed plan is executed only if it is still exactly what the controller would compute. The executed actions are the controller's own, never the client's. Approvals bind to this content-derived id, so an approval now proves the reviewed content.
4. **No stored plan.** Because the id is derived from content, the controller keeps no plan table: a stale or forged id cannot match, and there is nothing to expire or clean up. A client that wants to show what it reviewed keeps the plan it received.
5. **The caller-supplied plan path stays, documented as a low-level escape hatch.** `POST /machines/{id}/apply` continues to work unchanged for scripts and the existing tests. It is not the reviewed path, and the console and the Fleet skill use plan ids.
6. **Scope: skills first.** Desired state has no binding from a machine to a `Profile` or `Project` (a `Machine` resource declares identity facts, groups, and tags only), so tool versions and checkouts cannot be composed per machine yet. Skill assignments already select machines by scope, so plans cover skill deployments and catalog pins now. Binding machines to profiles and projects is a schema change and is proposed separately; when it lands, the same plan path gains tool and checkout actions with no contract change.
7. **No active revision means no plan.** Without an activated revision there is nothing to converge toward, and the request fails with `409 no_active_revision` rather than planning against an empty desired state.

## Consequences

- The reviewed-plan property (approve exactly what runs) holds end to end for controller-computed plans.
- Planning reads the machine's stores on every plan and every apply. It is cheap next to the work it gates.
- A plan can go stale because observations changed, not just because desired state did; the client is told to re-plan, which is the honest outcome.
- The legacy apply path still lets an authorized caller submit arbitrary supported actions. Removing it is a later decision once nothing depends on it.
