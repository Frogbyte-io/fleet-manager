# ADR 0016: A descriptive Registry in Fleet Git and brokered provider actions

Status: Proposed

Proposed: 2026-10-16 (FM-1000). Proposed for maintainer review. It narrows two "Explicitly outside" lines of the master plan and adds a class of desired resources that are never applied; it does not reverse ADR 0004, 0005, or 0013.

## Context

Domains, third-party services, and the sites running on Coolify are tracked in people's heads, registrar dashboards, and scattered notes. Humans and agents need one place to answer "what do we have, where is it, what does it cost, and how does it connect". Agents also need to change the systems behind those things (redeploy a Coolify app, edit a Cloudflare DNS record) without holding the provider keys.

The master plan excludes "asset/license management" and "a secrets-management platform", and the desired-state model assumes every resource is something the planner converges. The M10 plan ([planning/m10-registry-services.md](../planning/m10-registry-services.md)) needs a boundary for each of these before any code lands.

## Decision

### Registry resources

1. **Two new desired-resource kinds.** `RegistryType` and `RegistryEntry` use the existing envelope (`apiVersion`, `kind`, `metadata.id` UUIDv7, `metadata.name` slug, `spec`), with both metadata fields required in the file like every other kind, and live in the Fleet Git repository. Git history is the edit history; a revert is `git revert`.
2. **Types are data, not code.** A `RegistryType` declares a display name, a natural-key field, its fields, and the relation names it allows. Field types come from a closed set: string, text, number, boolean, date, url, hostname, email, money, enum with suggestions, and lists of these. There is no plugin SDK, no code hook, and no JSON Schema passthrough. Adding a value type changes `fleet-schema` and this ADR.
3. **Descriptive only.** Registry resources are never planned, applied, or converged. The M4 planner and drift model ignore them. Giving any Registry kind apply semantics requires a new ADR.
4. **Built-in types.** Fleet ships `domain` and `service` (third-party/SaaS) as built-in types, versioned with the controller like built-in skills (ADR 0012). A repository may add its own types. Redefining a built-in type name is a validation error.
5. **Natural keys.** An entry is addressed as `<type>/<key>` (`domain/example.com`), where the key is the value of the type's key field and is unique per type. Tooling generates `metadata.id` and derives `metadata.name` from the type and key as a slug (`domain-example-com`); a hand-written entry must carry both. A duplicate key within a type is a validation error, and the key, not `metadata.name`, is how people and tools address an entry.
6. **One file per entry.** The convention is `fleet/registry/<type>/<key>.yaml`, so concurrent agent edits rarely conflict. As for all desired resources, identity comes from metadata, not from the path.
7. **Relations.** An entry may relate to other entries or to Fleet-known resources (machine, project, Proxmox guest, Coolify resource) using a relation name its type allows. A dangling relation is a warning, not a failure, because the observed side may be offline.
8. **No secrets.** There is no secret value type. Besides typed fields, an entry has free-text `notes`, `tags`, and `links` (label and URL). Validation runs the controller's credential scrubber over every string in the spec and rejects a resource whose value it would redact; the diagnostic names the field path, never the value, so an author can fix a false positive such as a long opaque ID. A field that says where a login lives (`loginAt: "1Password: Webhuset"`) is a pointer, not a credential.
9. **Observations attach, never overwrite.** Enrichers (RDAP and DNS for domains) record observations against an entry in SQLite. The difference model shows them as drift or suggestions. Only a Git commit changes an entry.

### Editing, activation, and change mode

10. **Agents edit files, not the controller.** `fleetctl registry set|unset|rm|relate` patches YAML in a local checkout of the Fleet Git repository, and `fleetctl registry validate` runs the same validator the controller runs. The controller still never writes to Fleet Git, and the console stays read-only for the Registry in M10.
11. **Change mode is a setting.** A controller setting, `registry.changeMode`, is `direct` (push to the default branch) or `pull-request` (push a branch and open a PR). `fleetctl registry publish` and the `fleet` skill read it and follow it. It is a convention for well-behaved tools; enforcement belongs to the Git host's branch protection, and Fleet does not claim otherwise.
12. **Registry-only revisions auto-activate.** When a fetched, valid candidate differs from the active revision only in `RegistryType` and `RegistryEntry` resources, the controller activates it without a manual step, through the same serialized and audited activation path. It acts as a controller system principal, and the audit event records that principal and the commit SHA. Any other change keeps explicit activation. An optional periodic fetch of the configured source picks up pushed edits; without it, edits arrive on the next manual fetch. An invalid candidate is never activated, and the last valid revision stays active.

### Brokered provider actions

13. **Fleet holds provider credentials and never returns them.** API-token providers (Coolify and Cloudflare in M10) sit behind narrow provider ports with translation at the provider boundary (ADR 0005). They are external provider accounts whose tokens are encrypted secret records (ADR 0004). No API, CLI output, log, audit event, operation payload, or result contains a token. This is not a secrets-management platform: Fleet stores only credentials it uses itself, and project secrets stay in Frogenv.
14. **`ActionRequest`.** A caller asks the controller to run a typed, provider-defined action (for example `coolify.application.redeploy` or `cloudflare.dns.record.upsert`) with structured, validated parameters. The request is a durable SQLite record with its requester, risk class, decision, approver, and the resulting operation. Its lifecycle is `pending → approved → executing → succeeded | failed`, with `denied` and `expired` as terminal branches from `pending`. An `auto` request is created already `approved`; a `deny` action is refused at creation and leaves only an audit event. Execution is an ordinary durable operation (ADR 0008) and passes centralized authorization and audit like every other mutation.
15. **Risk classes.** Each action type has a risk class: `auto` (runs on request), `approve` (waits for a human approval in the console or `fleetctl requests`), or `deny` (refused). Defaults: restart or redeploy an existing application is `auto`; a new deployment, environment variable change, and DNS change are `approve`. A controller setting can raise or lower a class per action type; Registry edits do not go through the broker.
16. **A guardrail, not a security boundary, before M8.** Until authenticated identities are in use, every caller is `anonymous-lan-admin` (or a Tailscale admin) and could approve its own request. The policy therefore protects against agent mistakes, not a hostile LAN caller. Per-agent scoping arrives through delegated credentials (ADR 0011): a delegated principal will be allowed to request and never to approve.

## Consequences

- `fleet-schema` gains two kinds, a value-type validator, and built-in type fixtures. The desired-resource scope boundary gains a descriptive class that the planner skips.
- Auto-activation narrows the "explicit activation" rule in [desired-state.md](../architecture/desired-state.md) for Registry-only diffs. Every activation is still audited and can be rolled back.
- A pushed Registry edit is visible after the next periodic fetch, not instantly.
- The broker adds a pending-approval surface. Running services are observed from Coolify and Docker and are never stored in Git.
- Not decided here: registrar or vendor API sync, billing import, Resend, key provisioning into Frogenv, a console editor that commits to Fleet Git, and more built-in types. Each needs its own issue, and some need an ADR.
