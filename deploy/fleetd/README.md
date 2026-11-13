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

The state directory holds fleetd's own entries: `node.key`, `credential`,
`machine-id`, `journal.ndjson`, `inventory.json`, and the local status socket
`local.sock`. fleetd creates the socket when it starts serving and removes it
on a clean shutdown; an unclean stop (a crash, `SIGKILL`) can leave it
behind, and `--purge` removes it with the rest.

`--purge` deletes the state directory recursively, so it deletes only a
directory that is fleetd's own: an absolute path (a trailing slash is
stripped first, after the path as given was checked for `//`, `.` and `..`),
a real directory (not a symbolic link), owned by the `fleet` account, not a
system directory, and empty or holding fleetd's `node.key` as a regular
file. Every ancestor must be a real directory owned by root, not
writable by group or others, and without a POSIX ACL (read with `getfacl`
when it is installed, otherwise from the `+` that `ls -ld` shows). On Linux
the group mode bits already reflect an ACL's mask, so the ACL test is defense
in depth; remove an ACL with `setfacl -b <dir>`. The state directory path
itself must be normalized (no `//`, `.` or `..`), inside another directory
(not top-level), not a system directory such as `/var/lib` or `/srv`, and
nowhere inside the trees `/etc`, `/root`, `/usr`, `/proc`, `/sys`, `/dev`,
`/boot`, `/run`, `/var/run`, `/tmp` or `/var/tmp` (system, runtime and
temporary trees). The controller refuses the same paths when it accepts a
`machines install-node` layout. On a test layout where no `fleet` account
exists and a non-root user runs the script (as `install.sh` allows with a
stubbed `useradd`), the state directory and its ancestors may belong to that
user instead; run as root without the account, the purge is refused. Anything else is refused before anything is
removed; the checks run again right before the delete, which stays on one
file system (`rm -rf --one-file-system`). `uninstall.sh` also stops with an
error, removing nothing, when the service cannot be stopped (`systemctl
disable --now` fails), or when the unit file is gone and `systemctl
is-active` does not answer `inactive`, `unknown` or `failed`. `install.sh`
refuses to adopt a state directory that is a symbolic link, whose contents
cannot be read, or that already holds files without a regular `node.key`. It
also applies the same path and ancestor rules before it creates anything, and
again once the state directory exists, so a state path or ancestor that
`--purge` would refuse is never installed. The service account is the exception: on
the test layout above, where a stubbed `useradd` leaves no `fleet` account,
the install succeeds with the state directory owned by the invoking user (or
by root, when root runs it). A later `--purge` run as root refuses it because
there is no `fleet` account ("the directory cannot be fleetd's"), whoever owns
it; if a `fleet` account is created afterwards, the purge refuses the
directory instead because it is not owned by `fleet`. Remove such a test
install by hand.

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
