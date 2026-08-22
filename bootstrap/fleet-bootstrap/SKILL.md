---
name: fleet-bootstrap
description: Rules for working with the agents-registry fleet/machine/skill registry - when a machine's desired skill state, roles, packs, or capabilities need to be looked up or reconciled. Use whenever asked to check what's installed on a machine, add/change a machine's roles or skills, or run agents-registry sync/status/resolve.
---

# Fleet bootstrap

`agents-registry` is the declarative source of truth for desired
machine/skill/capability state. This skill documents the rules for working
with it safely.

## Ground rules

1. **Machine configuration lives in the registry, not on the machine.**
   Don't hand-edit a machine's installed skills directly on the box; edit
   its manifest under `machines/` (or the roles/packs it references) and
   run `agents-registry sync`.
2. **Don't manually edit generated skill directories.** Whatever the skills
   CLI backend materializes on disk (see `src/skillsBackend.js`) is
   generated output — treat it like a build artifact, not source.
3. **Use `agents-registry sync` to reconcile desired state**, not ad-hoc
   installs. `agents-registry resolve <machine-id>` shows desired state
   without changing anything; `agents-registry sync` reconciles it via the
   skills CLI backend, or prints a dry run if no backend is configured.
4. **Project-local skills may override or add to global defaults.** A
   project's own skill declarations (`projects/<id>.yaml`) layer on top of,
   they don't replace, whatever its target machines already resolve to.
5. **Global changes go through the registry.** If a change should apply to
   more than one machine, add/edit a role or pack rather than repeating it
   per-machine.
6. **Secrets are managed separately.** Nothing under `machines/`, `roles/`,
   `packs/`, `devices/`, `projects/` should ever contain credentials — see
   `context/security.md`.
7. **Validate before you sync.** Run `agents-registry validate` after
   editing any manifest; it catches unknown role/pack/device references and
   id mismatches before `sync` acts on them.

## Useful commands

```bash
agents-registry status                  # all machines, resolved roles/capabilities
agents-registry resolve <machine-id>     # full desired state for one machine
agents-registry capabilities <name>      # which machines have a capability
agents-registry validate                 # check the registry for errors
agents-registry sync [--machine <id>]    # reconcile this machine's desired state
```

## What this skill does not cover

Live VM lifecycle (Proxmox reset/clone/boot/stop) and physical USB device
passthrough are not implemented yet — `agents-registry status` reports
those machines as `unmanaged`. Don't assume `sync`/`status` reflect actual
VM power state.
