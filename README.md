# agents-registry

Single source of truth for which machines Claude Code and Codex CLI are allowed to
SSH into, shared across every machine you work from.

## How it's wired up

- **`AGENTS.md`** — the canonical, tool-agnostic machine list. This is the only file
  you edit when a machine is added, retired, or changed.
- Codex CLI reads its global instructions from `~/.codex/AGENTS.md`. `setup.sh`
  symlinks that path to this repo's `AGENTS.md`.
- Claude Code reads global instructions from `~/.claude/CLAUDE.md` and supports
  `@path` imports. `setup.sh` appends an import line pointing at this repo's
  `AGENTS.md` (it won't touch anything else already in your `CLAUDE.md`).

Net effect: one file, two tools, always in sync, on every machine you clone this
repo to.

## First-time setup on a new machine

```bash
git clone <this-repo-url> ~/agents-registry
cd ~/agents-registry
./setup.sh
```

## Staying in sync automatically

`setup.sh` also installs a `systemctl --user` timer, `agents-registry-sync.timer`,
which runs `sync.sh` every 30 minutes. `sync.sh` does a `git fetch` + `git pull
--ff-only`; if the pull brings new commits, it re-runs `setup.sh` so any updated
`AGENTS.md` wiring takes effect without you having to log back in.

- Check status: `systemctl --user status agents-registry-sync.timer`
- Check recent runs: `journalctl --user -u agents-registry-sync.service`
- The timer only runs while you're logged in unless you enable lingering:
  `sudo loginctl enable-linger $(whoami)`.
- If the repo has local commits that don't fast-forward (e.g. someone edited
  `AGENTS.md` directly on the machine), `sync.sh` fails loudly instead of
  silently merging — resolve it manually, then the timer will pick back up.

## Adding a new machine to the registry

1. Copy the template block at the bottom of `AGENTS.md`.
2. SSH in once yourself and fill in the details (see the commands in
   `gather-info.sh` — same ones used to populate the `ananords-dev` entry).
3. Add a matching `Host` block to `~/.ssh/config` on each machine you want to be
   able to reach it from (see `ssh-config.example`).
4. Commit and push. `git pull` on your other machines to sync.

## Security notes

- This repo contains **no private keys, passwords, or tokens** — only host key
  fingerprints and the *comments* of authorized public keys, for audit purposes.
- Keep this repo **private**. Even without secrets in it, it documents your LAN
  layout, hostnames, and which machines trust which keys — useful recon for an
  attacker, not something to publish.
- Any temporary/one-off keys (e.g. added for agent setup sessions) are flagged in
  `AGENTS.md` — remove them from the target machine's `authorized_keys` once
  they're no longer needed, and delete the line here.
