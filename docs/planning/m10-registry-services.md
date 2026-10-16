# M10 — Registry, running services, and brokered provider actions

Status: planned (2026-10-12). Milestone: [M10](https://github.com/Frogbyte-io/fleet-manager/milestone/11). Boundaries: [ADR 0016](../adr/0016-descriptive-registry-and-action-broker.md) (FM-1000, proposed) and the M10 section of [PLAN.md](../PLAN.md).

## Goal

One place to answer "what do we have, where is it, what does it cost, and how does it connect", for humans and for agents. It starts with domains and third-party services and is generic enough to hold more kinds of things later. Agents can read and edit it as easily as code. They can also *request* changes to the systems behind it (deploy to Coolify, edit Cloudflare DNS) without ever holding the provider keys.

## Decisions (maintainer brainstorm, 2026-10-11/12)

- **A generic Registry in Fleet Git.** Domains, third-party services, and future kinds of thing are `RegistryEntry` resources in the Fleet Git repository, typed by `RegistryType` definitions. Git history is the edit history, and a revert is `git revert`. ("Inventory" already names machine inventory snapshots, and "catalog" names the skills catalog.)
- **Manual first.** Domains sit at Hostinger, Webhuset, Porkbun, GoDaddy, and others; third-party services are similarly varied. There are no registrar or vendor integrations. Public RDAP/DNS lookups only suggest and warn.
- **Easy for agents to edit.** `fleetctl registry set …` patches YAML in a local Fleet Git checkout. The agent commits, then pushes or opens a PR.
- **Registry-only revisions auto-activate.** A fetched revision whose only changes are Registry resources is activated without a manual step. Other desired-state changes keep explicit activation.
- **Direct push or PR is a setting.** A controller setting chooses whether Registry edits push to the default branch or open a pull request. `fleetctl` and the `fleet` skill follow it. Enforcement still belongs to the Git host's branch protection.
- **Running services come from Coolify plus Docker.** They are observed, not stored in Git. Registry entries can relate to them.
- **Brokered access.** Fleet holds Coolify and Cloudflare credentials as encrypted secret records. Agents request actions, and policy or a human approves them. Keys never leave Fleet.
- **No Resend integration**, no registrar sync, and no key provisioning into Frogenv in M10.

## The Registry model

Two new desired-resource kinds under the existing envelope (`apiVersion`, `kind`, `metadata.id` UUIDv7, `metadata.name` slug, `spec`):

```yaml
apiVersion: fleet.frogbyte.io/v1alpha1
kind: RegistryType
metadata: { id: 0192…, name: domain }
spec:
  displayName: Domain
  key: fqdn                       # natural key, unique per type
  fields:
    fqdn:        { type: hostname, required: true }
    registrar:   { type: string, suggestions: [Hostinger, Webhuset, Porkbun, GoDaddy, Cloudflare] }
    dnsHost:     { type: string }
    expires:     { type: date }
    autoRenew:   { type: boolean }
    loginAt:     { type: string, description: "Where the login lives, e.g. '1Password: Webhuset'" }
  relations: [hosted-on, used-by, billed-to]
---
apiVersion: fleet.frogbyte.io/v1alpha1
kind: RegistryEntry
metadata: { id: 0192…, name: domain-example-com }
spec:
  type: domain
  fields: { fqdn: example.com, registrar: Webhuset, dnsHost: Cloudflare, autoRenew: true }
  tags: [client-x]
  links: [{ label: DNS, url: https://dash.cloudflare.com/… }]
  notes: Moved from GoDaddy in 2025.
  relations:
    - { type: used-by, target: { registry: service/aptabase } }
    - { type: hosted-on, target: { coolify: "<resource-uuid>" } }   # or machine, project, proxmox guest
```

Rules:

- **Types are data, not code.** Fields use a small closed set of value types: string, text, number, boolean, date, url, hostname, email, money, enum-with-suggestions, and lists of these. This is not a plugin SDK and not a JSON Schema passthrough.
- **Descriptive only.** Registry resources are never planned or applied; the M4 planner ignores them. Giving them apply semantics requires a new ADR.
- **Built-in types ship with Fleet** (`domain`, and `service` for third-party/SaaS) and are versioned like built-in skills (ADR 0012). The repository may add its own types. Redefining a built-in type is a validation error.
- **Natural keys.** Entries are addressed as `<type>/<key>` (`domain/example.com`, `service/aptabase`). Tooling generates `metadata.name` and `metadata.id`.
- **One file per entry** (`fleet/registry/<type>/<key>.yaml`), so concurrent agent edits rarely conflict. Layout is convention; identity stays in metadata.
- **Relations** point at other entries or at Fleet-known resources. Dangling relations are a warning, not a failure, because the observed side may be offline.
- **Never secrets.** No secret value type exists, and validation runs the controller's credential scrubber over every value and rejects matches.
- **Observations attach, never overwrite.** Enrichers (RDAP/DNS for domains) record observations against entries, and the difference model shows them as drift or suggestions.

## Agent editing workflow

```bash
fleetctl registry find aptabase --output json             # read: controller API, active revision
fleetctl registry get domain/example.com --output json

# write: in a checkout of the Fleet Git repository
fleetctl registry set domain/example.com --field registrar=Webhuset --field dnsHost=Cloudflare
fleetctl registry relate domain/example.com used-by service/aptabase
fleetctl registry validate                 # the same validator the controller runs
fleetctl registry publish -m "example.com DNS moved to Cloudflare"   # commit + push or PR, per setting
```

`set` creates or patches (fields left out are untouched), keeps stable YAML formatting, and accepts `--from-json -`. `unset`, `rm`, and `relate` complete the set. A ready-made CI workflow validates Registry changes on every PR.

## Plan boundaries this changes (FM-1000)

1. *"A secrets-management platform"* stays excluded. Fleet brokers actions with credentials it holds and never returns them.
2. *"asset/license management"* is narrowed. A descriptive, manually maintained Registry is in scope because agents need it for discovery. Compliance, seat tracking, discovery agents, and procurement stay out.
3. *Desired-state scope boundary.* Adds a class of descriptive, never-applied resources.
4. *"A Portainer replacement, Compose authoring platform"* is unchanged. Site templates delegate to Coolify.

Security note: until M8 identities are in use, every caller is `anonymous-lan-admin` (or a Tailscale admin). Broker policy is therefore keyed on action risk class. It is a guardrail against agent mistakes, not a boundary against a hostile LAN caller. ADR 0011's delegated credentials are the path to per-agent scoping later.

## Issues

Routing follows the usual split; codex holds at most half.

### Epic A — Foundations (#478)

| ID | Issue | Agent | Depends on |
|---|---|---|---|
| [#457](https://github.com/Frogbyte-io/fleet-manager/issues/457) FM-1000 | Plan revision and ADR: descriptive Registry in Fleet Git, brokered provider actions | claude | — |
| [#458](https://github.com/Frogbyte-io/fleet-manager/issues/458) FM-1001 | External provider accounts (Coolify, Cloudflare) | codex | [#457](https://github.com/Frogbyte-io/fleet-manager/issues/457) FM-1000 |

### Epic B — Registry (#479)

| ID | Issue | Agent | Depends on |
|---|---|---|---|
| [#459](https://github.com/Frogbyte-io/fleet-manager/issues/459) FM-1010 | `RegistryType` / `RegistryEntry` kinds and validation in `fleet-schema` | codex | [#457](https://github.com/Frogbyte-io/fleet-manager/issues/457) FM-1000 |
| [#460](https://github.com/Frogbyte-io/fleet-manager/issues/460) FM-1011 | Built-in Registry types: `domain` and `service` | glm | [#459](https://github.com/Frogbyte-io/fleet-manager/issues/459) FM-1010 |
| [#461](https://github.com/Frogbyte-io/fleet-manager/issues/461) FM-1012 | Registry read model and API | codex | [#459](https://github.com/Frogbyte-io/fleet-manager/issues/459) FM-1010 |
| [#463](https://github.com/Frogbyte-io/fleet-manager/issues/463) FM-1013 | `fleetctl registry` read, edit, validate, and publish | claude | FM-1010, FM-1012, FM-1014 (publish setting) |
| [#462](https://github.com/Frogbyte-io/fleet-manager/issues/462) FM-1014 | Registry-only auto-activation, periodic fetch, change-mode setting, CI validation workflow | codex | [#459](https://github.com/Frogbyte-io/fleet-manager/issues/459) FM-1010 |
| [#464](https://github.com/Frogbyte-io/fleet-manager/issues/464) FM-1015 | Registry console | claude | [#461](https://github.com/Frogbyte-io/fleet-manager/issues/461) FM-1012 |
| [#465](https://github.com/Frogbyte-io/fleet-manager/issues/465) FM-1016 | `fleet` skill: Registry lookup and editing | glm | [#463](https://github.com/Frogbyte-io/fleet-manager/issues/463) FM-1013 |

### Epic C — Domain and service views (#480)

| ID | Issue | Agent | Depends on |
|---|---|---|---|
| [#466](https://github.com/Frogbyte-io/fleet-manager/issues/466) FM-1020 | Domain lookup enricher (RDAP + DNS) with drift and suggestions | codex | FM-1011, FM-1012 |
| [#467](https://github.com/Frogbyte-io/fleet-manager/issues/467) FM-1021 | Domains and third-party services console views | claude | FM-1015, FM-1020 |

### Epic D — Running services (Coolify + Docker) (#481)

| ID | Issue | Agent | Depends on |
|---|---|---|---|
| [#469](https://github.com/Frogbyte-io/fleet-manager/issues/469) FM-1030 | Coolify provider: read discovery with contract fixtures | codex | [#458](https://github.com/Frogbyte-io/fleet-manager/issues/458) FM-1001 |
| [#470](https://github.com/Frogbyte-io/fleet-manager/issues/470) FM-1031 | Running-service read model (Coolify + Docker + Registry) | codex | FM-1030, FM-1012 |
| [#476](https://github.com/Frogbyte-io/fleet-manager/issues/476) FM-1032 | Services console page | claude | [#470](https://github.com/Frogbyte-io/fleet-manager/issues/470) FM-1031 |
| [#473](https://github.com/Frogbyte-io/fleet-manager/issues/473) FM-1033 | Coolify lifecycle actions (start/stop/restart/redeploy, deploy logs) | glm | FM-1031, FM-1040 |
| [#474](https://github.com/Frogbyte-io/fleet-manager/issues/474) FM-1034 | Coolify settings: environment variables, domains, health checks | claude | FM-1031, FM-1040 |
| [#475](https://github.com/Frogbyte-io/fleet-manager/issues/475) FM-1035 | Deploy a new site from a template | claude | FM-1033, FM-1034 |

### Epic E — Agent action broker (#482)

| ID | Issue | Agent | Depends on |
|---|---|---|---|
| [#468](https://github.com/Frogbyte-io/fleet-manager/issues/468) FM-1040 | Action requests and approval policy | codex | [#457](https://github.com/Frogbyte-io/fleet-manager/issues/457) FM-1000 |
| [#471](https://github.com/Frogbyte-io/fleet-manager/issues/471) FM-1041 | Approval inbox (console + `fleetctl requests`) | claude | [#468](https://github.com/Frogbyte-io/fleet-manager/issues/468) FM-1040 |
| [#472](https://github.com/Frogbyte-io/fleet-manager/issues/472) FM-1042 | Cloudflare provider: DNS read and brokered record changes | codex | FM-1001, FM-1040 |
| [#477](https://github.com/Frogbyte-io/fleet-manager/issues/477) FM-1043 | `fleet` skill: requesting brokered actions | glm | FM-1041, FM-1033 |

Totals: codex 9, claude 8, glm 4.

## Suggested order

FM-1000 alone → FM-1010, FM-1001, FM-1040 → FM-1011, FM-1012, FM-1014, FM-1030 → FM-1013, FM-1015, FM-1020, FM-1031, FM-1041, FM-1042 → the rest.

Epics B and C deliver the domain and service overview without Coolify or the broker.

## Deferred

- A console editor that commits or opens PRs to Fleet Git.
- Registrar/vendor API sync, billing import, and key provisioning into Frogenv (originally motivated by Resend).
- More built-in types (certificates, hardware, accounts). The repository can add them as custom types first.

## Open questions

1. Is one Coolify instance enough to start with? (FM-1001/FM-1030 assume several accounts are possible but test with one.)
2. *Resolved by ADR 0016 (proposed).* Default risk classes. Proposed: Registry edits need no broker; restarting or redeploying an existing app is "auto"; new deploys, env changes, and DNS changes are "approve". FM-1040 makes this configurable.

## Sources

- Coolify API authorization and token permissions: https://coolify.io/docs/api-reference/authorization
- Coolify services endpoints: https://coolify.io/docs/api-reference/api/operations/list-services
- RDAP: RFC 9082/9083; IANA bootstrap registry https://data.iana.org/rdap/dns.json
- Fleet desired-state model: `docs/architecture/desired-state.md`, `schemas/README.md`; ADR 0011 (delegated credentials), ADR 0012 (built-in skills)
