# Agent Machine Registry

This file is the shared, canonical list of machines that coding agents (Claude Code,
Codex CLI, etc.) are permitted to SSH into, plus enough metadata for an agent to
sanity-check a connection before acting.

**Both tools read this exact file** — see `README.md` for how it's wired in.

## Ground rules for any agent using this file

- Always connect via the SSH **alias** below (defined in `~/.ssh/config` on each of
  your machines), never by typing the raw IP — aliases are portable, IPs aren't.
  Prefer the LAN alias when reachable; fall back to the `-ts` (Tailscale) alias
  otherwise — same host, same fingerprints, just a different path to it.
- Before the *first* connection to a host in a session, confirm the presented host
  key fingerprint matches what's listed here. If it doesn't match, stop and ask —
  don't proceed.
- Treat every host as production unless its "Guardrails" section says otherwise.
  Ask before destructive commands (`rm -rf`, `docker system prune`, package
  removals, service restarts, anything with `sudo`).
- Never write private key material, passwords, or tokens into this file. Fingerprints
  and key *comments* only.

---

## ananords-dev

| | |
|---|---|
| SSH alias | `ananords-dev` (LAN) / `ananords-dev-ts` (Tailscale) |
| Host | `192.168.68.149` (LAN only) — Tailscale IP `100.79.130.64` (reachable off-LAN) |
| User | `ananords` |
| OS | Ubuntu 24.04.4 LTS (Noble Numbat) |
| Kernel | 6.17.0-35-generic, x86_64 |
| Desktop environment | GNOME Shell 46.0 (Wayland), stock Ubuntu desktop spin |
| Hardware | Intel laptop, model "SKYBAY", 4 cores / 7.7 GiB RAM |
| Timezone | Europe/Oslo |
| Package manager | apt |
| Dev tools present | Docker 29.6.1, git 2.43.0, Python 3.12.3, Node 18.19.1 |
| Purpose | _fill in — e.g. "primary dev box"_ |
| Guardrails | _fill in — e.g. "ok to run builds/tests freely; ask before docker prune or apt upgrades"_ |

**SSH host key fingerprints** (verify on first connect):
```
ED25519 SHA256:05cZ19yrrc59vPI28jUIKz6JXLAK7sK4q+HoPSyOS+c
ECDSA   SHA256:OymZ4KEOzY+q9lIV8CLzyFawI59JBOe0uZfbi/GU+6I
RSA     SHA256:YHxDC7t6aW7lj/sbrqo0TCGJMheFRgOXIEsVsYFMSqk
```

**Keys currently authorized on this host** (for audit reference only — rotate/remove
as needed, this is not a list of trusted identities to assume):
```
ananords@192.168.68.91     (ED25519) — another LAN machine, not yet in this registry
ananords@outlook.com       (ED25519) — primary personal key
bazzite-dotx-dev           (ED25519) — see the "bazzite-dotx-dev" entry below
cowork-temp-access-20260703 (ED25519) — added 2026-07-03 for agent setup, kept intentionally for now — private key lives only in an ephemeral Cowork sandbox, so treat it as low-value/rotatable
```

---

## bazzite-dotx-dev

| | |
|---|---|
| SSH alias | `bazzite-dotx-dev` (LAN) / `bazzite-dotx-dev-ts` (Tailscale) |
| Host | `192.168.68.223` (LAN only) — Tailscale IP `100.121.136.79` (reachable off-LAN) |
| User | `ananords` |
| OS | Bazzite 44.20260629.0 (Kinoite), immutable/ostree-based, Fedora 44 |
| Kernel | 7.0.9-ogc3.2.fc44.x86_64 |
| Desktop environment | KDE Plasma 6.7.1 (plasma-desktop), headless at last check (no XDG_CURRENT_DESKTOP) |
| Hardware | ASRock B450 Gaming K4, 8 cores / 15 GiB RAM, Nvidia (open) GPU variant |
| Timezone | Europe/Oslo |
| Package manager | dnf (base image is ostree/rpm-ostree — layering packages needs a reboot; prefer toolbox/distrobox or brew for dev tools) |
| Dev tools present | git 2.54.0, Python 3.14.6, Node v26.4.0, gh (via linuxbrew, not on default non-interactive PATH — use `/home/linuxbrew/.linuxbrew/bin/gh` or `export PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"` over SSH) |
| Purpose | Secondary dev box |
| Guardrails | Ok to run builds/tests freely; ask before `sudo`, `rpm-ostree` base-image changes, `dnf` upgrades, or `docker`/`podman` prune |

**SSH host key fingerprints** (verify on first connect):
```
ED25519 SHA256:+n0FljexZ2sOFA+IpoI2CYzXZLw+U1aVwF/rnAAil+g
ECDSA   SHA256:BavL4ThNF/DdUqcek7zE4M58ttukCbMLunMY5U84Efc
RSA     SHA256:wOqEwTL/qFzwxTKbx/anw6alZR0ZerzO9w1BMpP0GiM
```

**Keys currently authorized on this host** (for audit reference only — rotate/remove
as needed, this is not a list of trusted identities to assume):
```
ananords@outlook.com       (ED25519) — primary personal key
```

---

## windows-dev

| | |
|---|---|
| SSH alias | `windows-dev` (LAN) / `windows-dev-ts` (Tailscale) |
| Host | `192.168.68.115` (LAN only) — Tailscale IP `100.107.236.91` (reachable off-LAN) |
| User | `ananords` |
| OS | Windows |
| Kernel | _fill in_ |
| Desktop environment | _fill in_ |
| Hardware | _fill in_ |
| Timezone | _fill in_ |
| Package manager | winget / Chocolatey / Scoop — _fill in_ |
| Dev tools present | _fill in_ |
| Purpose | _fill in_ |
| Guardrails | Treat as production; ask before destructive commands, package changes, service restarts, or anything requiring elevation |

**SSH host key fingerprints** (verify on first connect):
```
ED25519 SHA256:T2HvKI0cpkScODjCdTiXlboSZgQK1ml3oN3abKgYebs
ECDSA   SHA256:pYCOOuDJnlPHmQ8sLWPUT2Hh60aytPlDf8c2C5qhJ0Q
RSA     SHA256:pcgRwnJRdjRQidD3ZRs/CzCi7STkNGg+hzQNEbXYMFs
```

**Keys currently authorized on this host** (for audit reference only — rotate/remove
as needed, this is not a list of trusted identities to assume):
```
bazzite-dotx-dev           (ED25519) — added 2026-07-04 for agent access from this machine
```

---

## Template — copy this block for each new machine

```
## <friendly-name>

| | |
|---|---|
| SSH alias | `<alias>` (LAN) / `<alias>-ts` (Tailscale, if reachable off-LAN) |
| Host | `<ip-or-hostname>` — Tailscale IP `<tailscale-ip-if-any>` |
| User | `<user>` |
| OS | |
| Kernel | |
| Desktop environment | |
| Hardware | |
| Timezone | |
| Package manager | |
| Dev tools present | |
| Purpose | |
| Guardrails | |

**SSH host key fingerprints:**
```
```

**Keys currently authorized on this host:**
```
```
```
