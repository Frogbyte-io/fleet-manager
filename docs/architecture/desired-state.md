# Desired, observed, and applied state

Status: proposed

## Ownership

Fleet optionally uses a Git repository as the canonical source of non-secret desired resources. SQLite is always the runtime system of record. Git is not an event store, observed-state cache, lease database, secret store, or controller backup.

```text
Git commit -> parse -> schema validate -> semantic validate -> immutable candidate
                                                        |
                                             activate desired revision
                                                        |
observations -> normalize ---------------------> compare/plan
                                                        |
                                              authorize/review/apply
                                                        |
                                              re-observe/verify/audit
```

## Proposed Fleet Git layout

```text
fleet/
├── fleet.yaml                 # schema version and controller-neutral settings
├── machines/
├── profiles/
├── projects/
├── skill-presets/
├── recipes/
├── actions/
├── lab-templates/
└── policies/                  # non-secret bindings/policy documents when enabled
```

Each resource has `apiVersion`, `kind`, stable metadata name/ID policy, and `spec`. Status is forbidden in Git. File layout is for humans and may not define identity by filename except where the schema explicitly says so.

## Composition and provenance

Profiles compose desired outcomes. Composition must be deterministic and explainable:

- Ordered profile application with an explicit conflict rule; silent last-write-wins for incompatible scalar requirements is rejected.
- Set-valued requirements have stable identity and explicit remove/deny semantics.
- A resolved field records source resource/path so the UI can explain why it is desired.
- Cycles and unresolved references fail semantic validation.
- Capability requirements select compatible machines/providers; capabilities themselves remain observed facts.
- Secret fields contain secret-reference IDs only.

Fleet-managed `SkillPreset` resources are assignments, not copies of
Skills Manager state. Their `scope` selects all machines, a group, a tag,
or one stable machine ID; omitted scope means all machines. Assignment
composition matches the machine's Fleet groups/tags, deduplicates each
skill/agent pair, and retains source provenance. Fleet desired state is
the only authority for managed membership. An offline or stale observation
is `unknown` and remains queued; a missing or unsupported Skills Manager
CLI is `unsupported` and cannot produce apply steps. Manual changes appear
as drift and are never imported into desired state.

Legacy roles/packs provide fixtures for these semantics but do not force the old wrapper/filename schema into v1.

## Import and activation

- The controller maintains an isolated clone/worktree and never runs hooks from the desired repository.
- Fetching a commit creates an immutable candidate identified by commit SHA plus content digest.
- Schema and semantic validation complete before activation.
- The last valid revision remains active on fetch/validation failure.
- Activation is serialized and audited. Users can inspect and manually select a prior valid revision.
- Fleet does not auto-resolve Git conflicts or push UI changes behind the user's back.
- UI editing, when added, creates a reviewed commit/branch/PR or an explicit direct commit. It never mutates only the imported SQLite copy.

Database tables may cache parsed active resources and validation diagnostics for performance. That cache is rebuildable from the recorded Git revision and is not a second desired-state authority.

## Observed state

An observation includes resource identity, source, source version, observed timestamp, expiry/staleness policy, payload schema version, and confidence/availability. Inventory snapshots may normalize frequently queried facts while retaining provider raw metadata only when needed for debugging and after redaction.

Unknown, unavailable, stale, absent, and explicitly disabled are distinct. For example, a disconnected laptop does not prove Docker was uninstalled.

## Difference model

Every managed field is classified as:

- `in_sync`
- `missing` — desired but observed absent with sufficient confidence
- `extra` — observed and Fleet-managed but no longer desired
- `changed` — desired/observed values conflict
- `unknown` — observation unavailable or stale
- `unsupported` — no route/provider can converge it
- `blocked` — prerequisite, permission, approval, or external ceremony missing

The plan contains ordered typed steps with target, provider/route, reason/provenance, risk, required permission/approval, idempotency/compensation metadata, and verification probe. A plan is bound to desired revision and relevant observation revisions; stale inputs trigger replan rather than blind execution.

## Apply semantics

- Dry-run/plan is always available and has no remote side effects.
- Authorization is checked at planning for visibility and again immediately before execution.
- The controller records the operation and audit intent before dispatch.
- Steps form a dependency DAG; independent nodes may execute concurrently within configured limits.
- Retry occurs only when the provider classifies it as safe or the idempotency key proves duplication is safe.
- Removal/destruction and shell execution use stronger policy/approval.
- Compensation is explicit and best effort; Fleet reports partial convergence rather than claiming transactional rollback across external systems.
- Apply ends by re-observing affected facts. A successful command without verified outcome is `completed_unverified`, not in sync.
- Offline nodes can keep a pending plan only when policy allows; expired/stale plans are recomputed after reconnect.

## GitHub one-click repository

The web flow uses a GitHub App user authorization flow and expiring token. Fleet requests only repository administration/contents permissions required to create a private repository and initialize files. Credentials are encrypted controller secrets. Initialization is one serialized commit. Organization creation, branch protection, and PR-based editing may require installation/organization approval and must report that explicitly.

## Scope boundary

Fleet profiles should cover developer-fleet outcomes such as project roots, required tools/runtimes, agent tools, skill presets, Frogenv readiness, node settings, and selected service integrations. They do not become a generic file/package/service language. If a team needs broad configuration management, a Fleet action invokes Ansible, Nix, chezmoi, or a project-owned tool and verifies its bounded outcome.
