# Machine context

Always-on facts about the fleet, independent of which skills happen to be
loaded (see `bootstrap/fleet-bootstrap/SKILL.md` for the load-bearing rules).

- The canonical list of machines an agent may **SSH into**, with host key
  fingerprints and authorized-key audit info, lives in `AGENTS.md` at the
  repo root. That file is about access, not desired skill/capability state.
- The canonical list of machines with **desired skill/capability state**
  (roles, packs, resources, lifecycle) lives under `machines/`, composed
  through `roles/` and `packs/`. Resolve it with:
  `agents-registry resolve <machine-id>`.
- These two lists describe the same physical/virtual machines from two
  different angles and are kept separately on purpose — access control
  changes on a different cadence than desired skill state, and conflating
  them would make either file harder to audit.
- Ephemeral test VMs (`lifecycle.mode: ephemeral`) are not yet wired to a
  live Proxmox adapter — `agents-registry status` will show them as
  `unmanaged` until that lands (tracked in a separate issue from the one
  that introduced this registry).
