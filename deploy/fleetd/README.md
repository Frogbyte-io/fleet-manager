# fleetd service package

This directory is the source of the node service package. The
`cargo xtask package-fleetd` step builds the release `fleetd` binary and
packs everything here into
`target/dist/fleetd-<version>-linux-x86_64.tar.gz` with a `SHA256SUMS`.

```
fleetd              the daemon binary (release build)
fleetd.service      hardened systemd unit
install.sh          install / upgrade (idempotent)
uninstall.sh        remove the service (keeps state unless --purge)
README.md           this file
SHA256SUMS          checksums of the files above
```

## What install.sh does

1. Creates the system account `fleet` (no login shell) and the state
   directory `/var/lib/fleetd` (0750 `fleet:fleet`; the daemon tightens it
   and the node key to 0700 at runtime).
2. Installs the binary to `/usr/local/bin/fleetd` atomically and the unit to
   `/etc/systemd/system/fleetd.service`, then writes the controller URL to
   `/etc/default/fleetd`.
3. Enrolls — only when no usable enrollment exists. The single-use token is
   piped to `fleetd enroll --token-stdin`: it is never in a process
   argument, never written to disk, and is consumed server-side at enroll.
4. Enables and (re)starts the service, then waits for it to be active.

## Upgrade and rollback

Upgrading is a re-install: the identity in `/var/lib/fleetd` survives, so no
new enrollment token is needed — the installer replaces the binary, reloads
the unit, restarts the service, and the node re-proves the same key. A
downgrade is the same procedure with an older archive; keep protocol
compatibility in mind (the node protocol is separately versioned and both
sides refuse incompatible peers loudly rather than guessing).

## Uninstall and re-enrollment

`uninstall.sh` stops and removes the service, environment file, and binary
but keeps `/var/lib/fleetd`, so a reinstall re-proves the same identity. Use
`uninstall.sh --purge` (or revoke the node identity from Fleet first) when
the machine should re-enroll with a new key; the controller supports
rebinding an existing machine to a new node key.

## Local socket access

The local status surface (`local.sock`, mode 0660) is readable by the
`fleet` account by default. To let another local account or group read it,
run the service with `--local-group <gid>` (strict group admission) and
chgrp the socket after start — e.g. an `ExecStartPost` chgrp. This is a
deliberate configuration step, not a default.

## Layout overrides

For tests, containers, and unusual hosts, install.sh honors
`FLEETD_STATE_DIR`, `FLEETD_BIN_DIR`, `FLEETD_UNIT_DIR`, `FLEETD_ENV_FILE`,
`FLEETD_SERVICE`, `FLEETD_SYSTEMCTL`, and `FLEETD_USER_ADD`. Root is only
needed for the real system paths.

## Checksums and signing

Every archive ships `SHA256SUMS` and the bootstrap operation refuses to
install without the expected digest, which it verifies on the node after
download. Binary signing (a minisign-class signature over the archive) is a
recorded follow-up: it needs a key-management decision (who signs, key
distribution, rotation) that belongs in its own ADR.
