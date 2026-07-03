# Agent Machine Registry

This file is the shared, canonical list of machines that coding agents (Claude Code,
Codex CLI, etc.) are permitted to SSH into, plus enough metadata for an agent to
sanity-check a connection before acting.

**Both tools read this exact file** — see `README.md` for how it's wired in.

## Ground rules for any agent using this file

- Always connect via the SSH **alias** below (defined in `~/.ssh/config` on each of
  your machines), never by typing the raw IP — aliases are portable, IPs aren't.
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
| SSH alias | `ananords-dev` |
| Host | `192.168.68.149` (LAN only — not reachable from outside the local network) |
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
bazzite-dotx-dev           (ED25519) — another machine, not yet in this registry
cowork-temp-access-20260703 (ED25519) — added 2026-07-03 for agent setup, kept intentionally for now — private key lives only in an ephemeral Cowork sandbox, so treat it as low-value/rotatable
```

---

## Template — copy this block for each new machine

```
## <friendly-name>

| | |
|---|---|
| SSH alias | `<alias>` |
| Host | `<ip-or-hostname>` |
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
