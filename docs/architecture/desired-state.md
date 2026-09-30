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

Composition contract for built-in skills (not yet active: Fleet Git activation
does not compose assignments at runtime until M4): the skills the controller
ships (the official `fleet` skill) receive an implicit global assignment to the
default agents (`claude_code`, `codex`) unless Fleet Git already names the skill
in a `SkillPreset`. Once Git names it, Git owns it: its presets
replace the default, and a preset with an empty `deployTo` removes the skill
everywhere. Because the controller never writes Git, a later release cannot
re-add a removed built-in skill ([ADR 0012](../adr/0012-builtin-skills.md)).

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

### Active snapshot (FM-404)

A fetch that produces a candidate without diagnostics stores that revision's validated resources (kind, identity, name, and non-secret spec) as an immutable snapshot keyed by commit SHA and content digest, in the same transaction that records the revision as a rollback point. An invalid candidate stores nothing. Activation only switches to a revision whose snapshot is held; a revision activated before snapshots existed reports `resourcesAvailable: false` until it is fetched again.

Reads go straight to SQLite, so a controller restart resumes on the same revision with the same resources. `GET /api/v1/desired/revision` reports the active revision and per-kind counts; `GET /api/v1/desired/resources` pages the resources by identity and filters by kind. Both use the `source.fetch` read permission.

### Source management (FM-405)

The remote is configured with `PUT /api/v1/desired/source` (permission `source.activate`, audited before the write). It must be non-secret text: a leading `-`, whitespace, and embedded credentials (`user:password@`) are refused. By default git authenticates with the controller host's own configuration (ssh agent, credential helper). `POST /api/v1/desired/{fetch,activate,rollback}` create the `source.fetch`, `source.activate`, and `source.rollback` operations; the fetch remote always comes from the configured source. A rollback names a revision in the append-only history whose snapshot is held and activates from that snapshot, so it needs no worktree. `GET /api/v1/desired/history` lists the recorded revisions and marks the active one.

### Git credential references (FM-412)

The remote may also name a credential by reference. `POST /api/v1/desired/source/credential` (permissions `secret.write` and `source.activate`, audited) stores an HTTPS token or an SSH private key as a `git/<uuid>` record in the controller's encrypted secret store (ADR 0004) and returns the record id; the value is write-only and no endpoint returns it. `PUT /api/v1/desired/source` takes an optional `credentialRef`, verifies it names a live `git/` record (other integrations' secrets are not referenceable), and audits the reference id only; omitting it clears the reference. `GET` returns the reference, never a value. `fleetctl desired source credential` reads the value from stdin and prints the reference; `fleetctl desired source set <remote> --credential <ref>` configures it.

The `source.fetch` payload carries no credential reference: the executor reads the configured reference itself and attaches the credential only when the payload's remote is exactly the configured remote (a generic-operation fetch of any other remote runs without credentials), then resolves the value just in time. Token fetches also pass `http.followRedirects=false`. The kind is derived from the value (a `-----BEGIN` block is an SSH key, anything else an HTTPS token) and must fit the remote's transport (`https://` for a token, `ssh://` or scp-style for a key), otherwise the fetch fails with a stable reason. The provider writes the secret to 0600 files in a private 0700 directory under the git work root, outside every worktree, and passes git only their paths: `GIT_ASKPASS` (a helper that answers the username prompt with a placeholder and the password prompt from the file, with `credential.helper=` reset so no other helper stores it) or `GIT_SSH_COMMAND` (`ssh -i <key> -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes`; host keys are verified against the controller's own `known_hosts`). The secret is never in argv, the environment, `.git/config`, logs, audit metadata, operation payloads, or results; the directory is deleted when the fetch ends, and the secret is scrubbed from any failure output. A missing or revoked reference fails the fetch with `the configured Git credential is missing or revoked`. Not covered: revoking through the API (delete the record with the secret store), per-host credential scoping, and the GitHub App flow.

### Per-machine observed-state assembly (FM-406)

`ObservedStateAssembler` builds a machine's `ObservedState` from the stores that hold its observations, mapping each store's freshness onto the answered flags the comparison already understands: tool facts past the 24 h window are `unknown` and a machine with no fresh tool fact leaves the inventory unanswered; a missing or stale Skills Manager snapshot is `stale`, an unreachable machine is `offline`, and fresh `absent`/`unsupported` snapshots pass through; checkouts join the project remote, and because nothing is stored when discovery finds nothing, an unobserved checkout is `unknown` rather than assumed missing. Installed Fleet catalog versions (FM-411) come from Fleet's own record, not from Skills Manager: a `skills.catalog-rollout` that passes its verification writes (machine, catalog id, agent, version id, skill name, time) to `catalog_skill_installs`, and each skills probe deletes records whose skill is no longer listed as deployed to that agent (an `absent` CLI invalidates all; an `unsupported` one changes nothing; a snapshot older than the record cannot invalidate it). The assembler reports the records the fresh snapshot still confirms and marks the catalog observation answered only when the snapshot is fresh and `available`; a stale, offline, or unsupported machine, or an assembler without the record store, leaves catalog differences `unknown`/`unsupported`, never in-sync. A skill deployed without a Fleet record (hand-installed, or installed before FM-411) has an unknown version and is reported `missing`, so a reviewed rollout re-pins it. A recorded catalog version whose catalog id no `SkillPreset` (or the built-in) names is reported as unsupported and never removed. Assembly reads only; the planner authorizes.

### Server-side planning (FM-407, ADR 0013)

`POST /api/v1/machines/{id}/plans` composes the active revision's `SkillPreset` assignments (plus the built-in default, ADR 0012) for the machine's groups and tags, compares them with its assembled observed state, and returns the planner's actions and unactionable differences. The plan id is a SHA-256 digest of the machine, the active revision, and the ordered actions; `POST /api/v1/machines/{id}/plans/{planId}/apply` recomputes the plan and refuses with `409 stale_plan` if the id differs, then runs the controller's own actions through the apply workflow. An observed skill that no `SkillPreset` names is reported as unactionable and never planned for removal. Catalog-pinned skills (including the built-in) compare against Fleet's record of the verified installed version: in sync when it matches the pin, `changed` when older, `missing` when absent, planned as `skills.catalog-rollout`. Tool versions and checkouts come from machine bindings (below).

### Machine bindings (FM-410, ADR 0014)

A `Machine` resource binds `spec.profiles` and `spec.projects` by `metadata.name`, and is matched to the registered Fleet machine with the same name. Activation validation refuses an unresolved profile or project name (`FM_SCHEMA_SEMANTIC_UNRESOLVED_REFERENCE`), a profile `extends` cycle (`FM_SCHEMA_SEMANTIC_PROFILE_CYCLE`), and duplicate names within Machine, Profile, or Project (`FM_SCHEMA_SEMANTIC_DUPLICATE_NAME`), so such a revision cannot become active. Planning composes the bound profiles as one synthetic profile that extends them (deny wins over include across the whole binding, conflicts refuse with `PlanningError::Composition`), adds each bound project's tools and its checkout (remote and root; a project without a root has no checkout), and yields `mise.install` and `projects.clone` actions through the unchanged planner. Several projects may be bound; one remote at two roots, or two remotes at one root, is a conflict. Profile skill requirements join `SkillPreset` assignments as machine-scoped assignments: assignments union, a `SkillPreset` deny of a profile-required skill refuses the plan, and a profile `deny` removes only requirements within profile composition. Profile capability requirements are report-only: unmet ones appear as `unsupported` differences. Project `skills` are not composed. A machine with no matching `Machine` resource, or one that binds nothing, plans as before.

### Drift read model (FM-408)

`GET /api/v1/desired/drift` (paged over machines) and `GET /api/v1/machines/{id}/drift` return each machine's differences from the active revision, computed by the same path as plans, so drift and plan cannot disagree. Reading drift needs `skills.read` for the machine; unreadable machines are omitted from the list. Each entry is `computed`, `no_revision` (nothing is active, so nothing can drift), or `unavailable` (with a caller-safe reason); one machine's failure never fails the page. Only differing fields are listed, and `unknown`/`unsupported` are counted separately from actionable drift, so an unobserved machine is never reported as in sync. The console shows drift in the Skills matrix (an "Against Fleet Git" row and per-skill markers), the Overview attention queue, and the machine's Desired tab.

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
