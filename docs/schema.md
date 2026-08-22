# agents-registry schema

Implements the initial scope of
[issue #2](https://github.com/Andreas-Froyland/agents-registry/issues/2):
machine manifests, role inheritance, registry-owned skill packs, capability
metadata, and the `agents-registry sync`/`status`/`resolve`/`validate` CLI.

Live infrastructure (Proxmox VM lifecycle, physical USB passthrough) is
tracked separately and not implemented here — see the follow-up issue linked
from #2.

## Directory layout

```text
machines/         one file per machine, id = machine.id (must match filename)
roles/            one file per role, id = filename stem
packs/            one file per skill pack, id = filename stem
devices/          one file per physical/passthrough device, id = filename stem
projects/         one file per project, id = filename stem
test-profiles/    one file per reusable group of test machines, id = filename stem
```

Every entity type **except machines** uses the filename stem as its id and
the YAML file's top-level body *is* the entity — no wrapper key. Machines are
the one exception: they use an explicit `machine:` block (matching the shape
in issue #2) because a machine file also carries sibling top-level keys
(`skills`, `capabilities`, `resources`, `lifecycle`, `requires`) alongside
its identity.

## `machines/<id>.yaml`

```yaml
machine:
  id: test-windows        # required, must equal the filename stem
  host: proxmox-01         # optional, informational
  os: windows-11           # optional
  roles:                   # role ids this machine composes, in order
    - desktop-test

skills:
  packs: []                 # pack ids, merged with what roles contribute
  include: []                # individual skills, always added
  exclude: []                # individual skills, always removed (wins over everything)
  external_packs: []         # skills.sh pack URLs, passed through as-is

capabilities: []            # merged with capabilities contributed by roles

resources:                  # free-form, passed through to CLI output/backends
  cpu:
    cores: 8
  memory: 16GB
  disk: 100GB

lifecycle:
  mode: ephemeral            # "persistent" | "ephemeral"
  reset_strategy: snapshot   # "snapshot" | "clone" | ...
  base_template: win11-test-v1
  reset_after_test: true

requires:
  devices: []                # device ids from devices/, validated to exist
```

## `roles/<id>.yaml`

```yaml
extends: []          # optional: other role ids this role inherits from
skills:
  packs: []
  include: []
  exclude: []
  external_packs: []
capabilities: []
```

`extends` isn't shown explicitly in issue #2's examples but is a natural
extension of "Roles and inheritance" for composing roles (e.g. a
`javascript` role extending `developer`) without duplicating their bodies.
Cycles are detected and rejected by `agents-registry validate`/`resolve`.

## `packs/<id>.yaml`

```yaml
skills:
  - owner/skill-name
```

## `devices/<id>.yaml`

```yaml
type: usb
vendor_id: "2341"
product_id: "8036"
passthrough: true
```

Declarative inventory only — nothing here talks to Proxmox yet.

## `projects/<id>.yaml`

```yaml
repo: git@example.com:org/repo.git
skills:
  packs: []
  include: []
  exclude: []
  external_packs: []
tests:
  - desktop-all        # test-profiles/<id> ids
```

## `test-profiles/<id>.yaml`

```yaml
machines:
  - test-ubuntu
  - test-bazzite
```

## Resolution order

For a machine: `capabilities` and `skills.{packs,include,exclude,external_packs}`
from every role in `machine.roles` (in order, each role's own `extends`
chain resolved first) are merged, then the machine's own `skills`/
`capabilities` are layered on top. Packs expand into their `skills` list;
`skills.include` is added on top of that; `skills.exclude` is applied last
and always wins, regardless of which role/pack/include brought a skill in.

## CLI

```bash
agents-registry status                        # table of all machines
agents-registry resolve <machine-id> [--json]  # full desired state for one machine
agents-registry capabilities <name>            # which machines have a capability
agents-registry validate                       # check the whole registry for errors
agents-registry sync [--machine <id>] [--dry-run]
                      [--install-cmd "skills install {skill}"]
                      [--pack-add-cmd "skills pack add {url}"]
```

`sync` determines which machine to act on via, in order: `--machine`, the
`AGENTS_REGISTRY_MACHINE` env var, a local `.agents-registry-machine` marker
file (gitignored, machine-specific), or a machine whose `id`/`host` matches
this host's hostname.

It then looks for a skills-CLI backend (`AGENTS_REGISTRY_SKILLS_CMD` env var,
or a `skills` binary on `PATH`) and installs/adds each resolved skill/
external pack through it. If no backend is found, it prints what it would
do instead of failing — the exact command contract of "the skills CLI" isn't
specified by issue #2, so the templates above are a configurable default,
not a hard dependency on one specific tool.
