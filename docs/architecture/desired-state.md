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
├── registry/                  # RegistryType and RegistryEntry resources, one file per entry (ADR 0016)
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
- Activation is serialized and audited. Users can inspect and manually select a prior valid revision. A valid candidate whose only differences from the active revision are Registry resources activates automatically through the same path (ADR 0016); any other change needs explicit activation.
- **Registry auto-activation (FM-1014).** After a fetch records a valid candidate, `DesiredSource::auto_activate` (`fleet-application/src/source.rs`) compares the candidate's resources with the active snapshot per `(kind, id)`. It activates only when `registry.autoActivate` is on, a revision is already active, the diff is non-empty with every changed kind in `RegistryType`/`RegistryEntry`, the candidate commit is a descendant of the active commit (`RevisionComparer`: `git merge-base --is-ancestor` in the candidate's own clone, no hooks), and every file that differs between the two commits holds only Registry documents in both versions (a changed non-YAML file, `fleet.yaml`, or a mixed file means manual activation). The write is a compare-and-set (`SourcePort::activate_if_active`) inside one `BEGIN IMMEDIATE` section against the active revision the decision was made on, and it re-reads `registry.autoActivate` there; a refusal is audited as `registry_auto_activation_skipped`. It goes through the same authorized, serialized, audited activation (`activate_as`), with the audit actor `system:fleet-controller` (the skill-catalog seeding actor), the commit SHA, the previous commit, `authorizedAs`, the triggering fetch operation, and a per-kind `+added/-removed/~changed` count; resource contents are never recorded. Authorization is decided for the controller's internal caller principal exactly as the fetch and the Lab sweeper do (`authorizedAs` records it); under `LanAllowAllAuthorizer` that is nominal until the controller has a real system principal. A failure to auto-activate never fails the fetch: the candidate stays recorded for manual activation and the fetch result's `autoActivation` says why. See [the Registry workflow guide](../guides/registry-workflow.md).
- **Periodic fetch.** `FLEET_DESIRED_FETCH_INTERVAL_SECONDS` (default `0`, off; minimum 30) starts `SourcePoller` (`fleet-controller/src/source_poller.rs`), which resolves the remote's `HEAD` with `git ls-remote` and queues the ordinary `source.fetch` operation. It skips a tick while any `source.fetch` is pending or running (a kind-and-state filtered query), re-queues a failed one, backs off 1, 2, 4, then 8 ticks after repeated failures, and bounds `git ls-remote` (and every git call) with a deadline. `POST /api/v1/desired/fetch` is the fetch-now endpoint for webhooks.
- **Controller settings.** `registry.autoActivate` (default true) and `registry.changeMode` (`direct` | `pull-request`, default `pull-request`) live in the `controller_settings` table (migration 0055), served at `GET`/`PUT /api/v1/desired/settings` and `fleetctl desired settings`. Reads need `source.fetch`, writes need the dedicated `source.settings` permission (refused to delegated Lab credentials), and each write is audited as an intent before it lands and an outcome record after. The change mode is advice for `fleetctl` and agents; enforcement stays with the Git host.
- Fleet does not auto-resolve Git conflicts or push UI changes behind the user's back. The controller never writes to Fleet Git; Registry edits are commits made by people and agents (`fleetctl registry`), pushed directly or through a pull request per the `registry.changeMode` setting, which the Git host enforces.
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

A `Machine` resource binds `spec.profiles` and `spec.projects` by `metadata.name`, and is matched to the registered Fleet machine with the same name. Activation validation refuses an unresolved profile or project name (`FM_SCHEMA_SEMANTIC_UNRESOLVED_REFERENCE`), a profile `extends` cycle (`FM_SCHEMA_SEMANTIC_PROFILE_CYCLE`), and duplicate names within Machine, Profile, or Project (`FM_SCHEMA_SEMANTIC_DUPLICATE_NAME`), so such a revision cannot become active. Planning composes the bound profiles as one synthetic profile that extends them (deny wins over include across the whole binding, conflicts refuse with `PlanningError::Composition`), adds each bound project's tools and its checkout (remote and root; a project without a root has no checkout), and yields `mise.install` and `projects.clone` actions through the unchanged planner. Applying a `projects.clone` action clones from the fetch form stored with the registered project of that remote (the project registry, not the spelling written in Fleet Git), so the remote must also be registered as a project; an unregistered remote fails the step with `invalid_project_remote` before git runs. Several projects may be bound; one remote at two roots, or two remotes at one root, is a conflict. Profile skill requirements join `SkillPreset` assignments as machine-scoped assignments: assignments union, a `SkillPreset` deny of a profile-required skill refuses the plan, and a profile `deny` removes only requirements within profile composition. Profile capability requirements are report-only: unmet ones appear as `unsupported` differences. Project `skills` are not composed. A machine with no matching `Machine` resource, or one that binds nothing, plans as before.

### Registry kinds (FM-1010, ADR 0016)

`RegistryType` (display name, natural-key field, fields over a closed value-type set, required flags, allowed relation types) and `RegistryEntry` (type, fields, tags, links, notes, relations to `registry` `<type>/<key>`, `machine`, `project`, `coolify`, or `proxmoxGuest` targets) are descriptive: the planner reads only the kinds it names, so Registry resources never produce plan steps. Their semantic validation lives in `fleet-schema` (`registry.rs`), inside the one entry point the controller and the CLI share. It refuses unknown types, unknown fields, wrong value types, missing required fields, duplicate keys per type (case-insensitive), relation types a type does not allow, redefining a built-in type, and any string the controller's credential scrubber (`fleet_core::redact_credentials`) would change (`FM_SCHEMA_SEMANTIC_CREDENTIAL_VALUE`; the diagnostic names the path, never the value, and a field name that is not a plain identifier is never echoed). Dangling relation targets are warnings (`FM_SCHEMA_WARN_REGISTRY_DANGLING_RELATION`) returned by `validate_sources_report` beside the errors; `validate_sources` returns errors only, so warnings never block activation. Built-in types and known machine/project/Coolify/Proxmox targets are supplied through `RegistryContext`. The scrubber also runs over each field as `name: value` and each link as `label: url`, and over map keys; no diagnostic prints a key that is not a plain field name. Because the scrubber treats `<word>password: value` as a credential pair, write "1Password (Webhuset vault)" rather than "1Password: Webhuset" (by design; there is no exception). Value rules: URLs allow `http`, `https`, and `ssh` with a non-empty host and no credentials (also applied to link URLs); hostnames allow underscore-leading labels, refuse a trailing dot, and refuse a bare IPv4 address; list items must be unique; tags are unique lowercase slugs; a registry relation target must name a defined or built-in type (error), and a missing entry of that type is a warning.

### Built-in Registry types (FM-1011, ADR 0016)

`domain` and `service` live in `fleet-schema` (`registry_builtin.rs`), versioned by `BUILTIN_REGISTRY_TYPES_VERSION` like built-in skills (ADR 0012); a test pins the definitions' SHA-256 so any change forces a version bump. `RegistryContext::default()` carries them, so the controller's activation path, `fleet-schema validate`, and a future `fleetctl registry validate` resolve them without a file in the repository, and a repository `RegistryType` of the same name is refused (`FM_SCHEMA_REGISTRY_BUILTIN_REDEFINED`). Every entry also carries the standard `tags`, `links`, `notes`, and `relations`. Field names are the spec keys; `required` marks the natural key and mandatory fields; suggestions are not enforced.

`domain` (key `fqdn`; relations `resolves-to`, `hosted-on`, `used-by`, `depends-on`, `billed-to`):

| Field | Type | Notes |
| --- | --- | --- |
| `fqdn` | hostname, required | natural key |
| `registrar` | enum | suggestions: Hostinger, Webhuset, Porkbun, GoDaddy, Cloudflare, Namecheap |
| `registrarAccount` | string | account label, never a credential |
| `dnsHost` | string | who serves the zone |
| `nameservers` | list of hostname | |
| `expires` | date | |
| `autoRenew` | boolean | |
| `loginAt` | string | where the login lives, e.g. "1Password (Webhuset vault)" |

`service` (key `slug`; relations `used-by`, `hosted-on`, `depends-on`, `serves`, `billed-to`):

| Field | Type | Notes |
| --- | --- | --- |
| `slug` | string, required | natural key |
| `name` | string, required | |
| `vendor`, `plan`, `billingOwner`, `hostingProvider`, `region` | string | |
| `purpose` | text | |
| `cost` | money | `<amount> <ISO 4217 code>` |
| `billingPeriod` | enum | suggestions: monthly, yearly, other |
| `renewal` | date | |
| `loginAt` | string | as for `domain` |
| `url` | url | |

### Registry read model (FM-1012, ADR 0016)

`/api/v1/registry/*` answers "what do we have and how does it connect" from the active revision without a Git checkout. It is read-only and needs the catalog's `registry.read` permission (checked in the `fleet-application` use cases, not the handlers; not risky, since the Registry holds no secrets). Endpoints: `GET /registry/types` (built-in and repository types with `entryCount`), `GET /registry/entries` (filters `type`, `tag`, `q` for a case-insensitive literal substring over key, name, field values, tags, and notes, and `target=<class>:<reference>` with an optional `relation`), `GET /registry/entries/{type}/{key}`, `GET /registry/entries/{type}/{key}/referenced-by`, and `GET /registry/references?target=<class>:<reference>` for reverse relations of an entry (`registry:<type>/<key>`) or of a Fleet resource (`machine:<name>`, `project:<name>`, `coolify:<ref>`, `proxmoxGuest:<ref>`). Lists use keyset cursors (entries by type and key; references by type, key, and relation) and the standard `limit`; a malformed target, filter, or cursor is a 400. Every response carries `revision.commitSha` (and the content digest), which is `null` while no revision is active; each entry and repository type carries `sourcePath`, its repository-relative file, for edit links.

The tables (migration 0054: `registry_cache_state`, `registry_types`, `registry_entries`, `registry_entry_tags`, `registry_relations`) are derived from the active revision's resource snapshot, never from Git directly, and hold nothing the snapshot does not. The derivation is a pure function in `fleet-application` (`registry::derive`) over the snapshot's `RegistryType` and `RegistryEntry` resources plus the built-in types, which are injected into the read model (the controller supplies the validator's built-in set, so a type the validator accepts is a type the API lists). The cache is replaced in one transaction after every activation and rollback, and again lazily on read when its recorded revision or its built-in-type fingerprint differs from the active one, so a failed refresh, a deleted cache, or a controller upgrade that changes the built-ins repairs itself. The write is refused when the revision it was derived from is no longer active. Keys are unique case-insensitively (FM-1010), so entries and registry-class relation targets are stored both as written (returned for display) and lowercased (`entry_key_norm`, `target_ref_norm`), which lookups, joins, and cursors use. A page and its relations are read in one read transaction; a rebuild reads the snapshot of the revision it named (never "the active" join), runs single-flight, and a failed rebuild (including a revision over the size bound, which is refused with a clear error) is remembered for a few seconds instead of being repeated by every read. An entry whose type is unknown or whose key field is missing (impossible in a validated revision) is skipped rather than failing the rebuild. `source_revision_resources.source_path` (also migration 0054) records each document's path at fetch time; snapshots recorded before it keep `NULL` until a repeat fetch of the same revision supplies the path (a path is not content, so that fetch fills a `NULL`, and only a `NULL`, in place and drops the cache state so it rebuilds); until then they report `sourcePath: null`.

### Drift read model (FM-408)

`GET /api/v1/desired/drift` (paged over machines) and `GET /api/v1/machines/{id}/drift` return each machine's differences from the active revision, computed by the same path as plans, so drift and plan cannot disagree. Reading drift needs `skills.read` for the machine; unreadable machines are omitted from the list. Each entry is `computed`, `no_revision` (nothing is active, so nothing can drift), or `unavailable` (with a caller-safe reason); one machine's failure never fails the page. Only differing fields are listed, and `unknown`/`unsupported` are counted separately from actionable drift, so an unobserved machine is never reported as in sync. The console shows drift in the Skills matrix (an "Against Fleet Git" row and per-skill markers), the Overview attention queue, and the machine's Desired tab.

### Registry (proposed, ADR 0016)

`RegistryType` and `RegistryEntry` resources are descriptive: the planner, apply engine, and drift model ignore them. A type is data: a display name, a natural-key field, fields drawn from a closed set of value types (string, text, number, boolean, date, url, hostname, email, money, enum with suggestions, and lists of these), and the relation names it allows. `domain` and `service` are built in and versioned with the controller; a repository may add types but not redefine a built-in one. An entry is addressed as `<type>/<key>` and conventionally lives at `fleet/registry/<type>/<key>.yaml`. Semantic validation refuses an unknown type, a field or relation the type does not declare, a value of the wrong type, a duplicate key within a type, and any string in the spec (fields, notes, tags, links) that the credential scrubber would redact; the diagnostic names the field path, never the value. A relation to a missing entry or an unknown Fleet resource is a warning. Enrichers (RDAP and DNS for domains) store observations against entries in SQLite and never change the entry; differences appear as drift or suggestions.

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

Fleet profiles should cover developer-fleet outcomes such as project roots, required tools/runtimes, agent tools, skill presets, Frogenv readiness, node settings, and selected service integrations. They do not become a generic file/package/service language. Registry resources (ADR 0016) are a separate, descriptive class: they record what exists and how it connects, and are never applied. If a team needs broad configuration management, a Fleet action invokes Ansible, Nix, chezmoi, or a project-owned tool and verifies its bounded outcome.
