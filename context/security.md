# Security context

- No private keys, passwords, API tokens, or Proxmox credentials belong in
  this repo, in `machines/`, `roles/`, `packs/`, `devices/`, or anywhere
  else — see `AGENTS.md`'s security notes for the existing SSH-registry
  rules, which apply repo-wide.
- Treat every machine listed under `machines/` as production unless its
  manifest says otherwise. `lifecycle.mode: ephemeral` marks a disposable
  test VM; anything else (including no `lifecycle:` block) is not
  disposable.
- `agents-registry sync` only resolves desired state and shells out to an
  external skills CLI for installation — it does not reset, boot, or modify
  any VM. Live infrastructure changes (Proxmox resets/clones/snapshots,
  physical USB passthrough) are intentionally out of scope until a real
  adapter with proper credential handling exists.
- Keep this repo **private** for the same reasons `README.md` already
  states: hostnames, roles, and capability metadata are useful recon for an
  attacker even without secrets in them.
