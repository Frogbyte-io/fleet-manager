# agents-registry

Single source of truth for which machines Claude Code and Codex CLI are allowed to
SSH into, shared across every machine you work from.

## How it's wired up

- **`AGENTS.md`** — the canonical, tool-agnostic machine list. This is the only file
  you edit when a machine is added, retired, or changed.
- Codex CLI reads its global instructions from `~/.codex/AGENTS.md`. `setup.sh`
  (Linux/macOS) / `setup.ps1` (Windows) links that path to this repo's `AGENTS.md`.
- Claude Code reads global instructions from `~/.claude/CLAUDE.md` and supports
  `@path` imports. The setup script appends an import line pointing at this repo's
  `AGENTS.md` (it won't touch anything else already in your `CLAUDE.md`).

Net effect: one file, two tools, always in sync, on every machine you clone this
repo to.

## First-time setup on a new machine

Linux / macOS:

```bash
git clone <this-repo-url> ~/agents-registry
cd ~/agents-registry
./setup.sh
```

Windows (PowerShell):

```powershell
git clone <this-repo-url> $HOME\agents-registry
cd $HOME\agents-registry
.\setup.ps1
```

On Windows, linking `~/.codex/AGENTS.md` needs either Developer Mode or admin
rights to create a real symlink; `setup.ps1` falls back to an NTFS hard link
(unprivileged, same effect as long as the repo stays on the same volume as
`%USERPROFILE%`).

## Staying in sync automatically

Linux/macOS: `setup.sh` installs a `systemctl --user` timer,
`agents-registry-sync.timer`, which runs `sync.sh` every 30 minutes.

Windows: `setup.ps1` registers a Scheduled Task, `agents-registry-sync`, which
runs `sync.ps1` every 30 minutes.

Both do the same thing: `git fetch` + `git pull --ff-only`; if the pull brings new
commits, re-run the setup script so any updated `AGENTS.md` wiring takes effect
without you having to log back in.

- Linux/macOS status: `systemctl --user status agents-registry-sync.timer`
- Linux/macOS recent runs: `journalctl --user -u agents-registry-sync.service`
- Linux/macOS: the timer only runs while you're logged in unless you enable
  lingering: `sudo loginctl enable-linger $(whoami)`.
- Windows status: `Get-ScheduledTask -TaskName agents-registry-sync`
- Windows recent runs: `Get-ScheduledTaskInfo -TaskName agents-registry-sync`
- If the repo has local commits that don't fast-forward (e.g. someone edited
  `AGENTS.md` directly on the machine), the sync script fails loudly instead of
  silently merging — resolve it manually, then the timer/task will pick back up.

## Reaching a machine over Tailscale

Machines reachable via Tailscale get a second alias suffixed `-ts` pointing at
their Tailscale IP (see `AGENTS.md` and `ssh-config.example`). Same host, same
host key fingerprints — use the LAN alias when on-LAN, the `-ts` one otherwise.

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
