#!/usr/bin/env bash
# Install (or upgrade) fleetd as a systemd system service on a Linux host.
#
# The invoking SSH account needs real root, or passwordless sudo (the
# documented prerequisite of this bootstrap). Privileged steps are prefixed
# with `sudo -n` only when the account is not already root.
#
# Inputs (environment):
#   FLEET_CONTROLLER_URL  the controller base URL, e.g. http://10.0.0.5:8080
#                         (required on first install; ignored on upgrades)
#   FLEET_ENROLL_TOKEN    a single-use enrollment token for this machine.
#                         Required unless a valid enrollment already exists
#                         (the upgrade case). It is piped to
#                         `fleetd enroll --token-stdin` and never written to
#                         disk, never placed in a process argument.
#   FLEET_FORCE_ENROLL    set to 1 to wipe the existing node identity first
#                         (the post-revocation re-enrollment path). The
#                         bootstrap executor sets this when the machine's
#                         node identity was revoked.
#   FLEETD_ARCHIVE_DIR    directory holding the extracted archive contents
#                         (the fleetd binary and the unit file). Default: the
#                         directory of this script.
#
# Layout overrides for tests and unusual hosts (all optional):
#   FLEETD_STATE_DIR   default /var/lib/fleetd
#   FLEETD_BIN_DIR     default /usr/local/bin
#   FLEETD_UNIT_DIR    default /etc/systemd/system
#   FLEETD_ENV_FILE    default /etc/default/fleetd
#   FLEETD_SERVICE     default fleetd
#   FLEETD_SYSTEMCTL   default systemctl (point at a stub to test offline)
#   FLEETD_USER_ADD    default useradd (point at a stub to test offline)
#   FLEETD_RUNUSER     default: runuser under root, `sudo -n -u` otherwise
#                      (point at a stub to test offline)
#
# Behavior:
#   - Creates the system account `fleet` (no login shell) and the state
#     directory 0750 fleet:fleet. Every ancestor of the state directory must
#     pass the rule uninstall.sh --purge applies (a real directory owned by
#     root, not writable by group or others, no POSIX ACL); anything else is
#     refused, so no layout the purge would refuse is ever installed.
#   - Installs the binary atomically (write to temp, rename).
#   - Installs the unit and the environment file, enables the service.
#   - Enrolls only when there is no usable enrollment yet: an existing
#     credential survives upgrades, so a restart re-proves the same
#     identity. FLEET_FORCE_ENROLL=1 wipes the identity first (revocation).
#   - Starts (or restarts) the service and waits for it to be active.
#
# On failure the script removes what it created in this run (unit, env file,
# enabled state) so a retry starts clean, and leaves the agentless SSH
# endpoint — and any previous working installation — untouched.

set -u

die() { printf 'install: %s\n' "$1" >&2; exit 1; }
log() { printf 'install: %s\n' "$1"; }

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCHIVE_DIR="${FLEETD_ARCHIVE_DIR:-$SELF_DIR}"
STATE_DIR="${FLEETD_STATE_DIR:-/var/lib/fleetd}"
# `dir/` would make the checks below look through a symlink.
while [ "${STATE_DIR%/}" != "$STATE_DIR" ]; do STATE_DIR="${STATE_DIR%/}"; done
[ -n "$STATE_DIR" ] || die "the state directory cannot be /"
BIN_DIR="${FLEETD_BIN_DIR:-/usr/local/bin}"
UNIT_DIR="${FLEETD_UNIT_DIR:-/etc/systemd/system}"
ENV_FILE="${FLEETD_ENV_FILE:-/etc/default/fleetd}"
SERVICE="${FLEETD_SERVICE:-fleetd}"
SYSTEMCTL="${FLEETD_SYSTEMCTL:-systemctl}"
USER_ADD="${FLEETD_USER_ADD:-useradd}"
RUNUSER="${FLEETD_RUNUSER:-}"

SERVICE_USER=fleet
BIN="$BIN_DIR/fleetd"
UNIT="$UNIT_DIR/$SERVICE.service"

ON_DISK_UNIT="$(ls "$ARCHIVE_DIR"/*.service 2>/dev/null | head -1)"
[ -n "${ON_DISK_UNIT:-}" ] || die "the archive has no unit file"
[ -x "$ARCHIVE_DIR/fleetd" ] || die "the archive has no fleetd binary"

# --- privilege ----------------------------------------------------------------
IS_ROOT=false
[ "$(id -u)" = "0" ] && IS_ROOT=true
if [ "$IS_ROOT" = true ]; then
    RUN_PRIV=()
elif sudo -n true >/dev/null 2>&1; then
    RUN_PRIV=(sudo -n)
else
    RUN_PRIV=()
    log "warning: this account is neither root nor a passwordless sudoer; \
privileged steps will fail (tests use layout overrides instead)"
fi

# Runs the enroll step as the service account. The token reaches fleetd on
# standard input and is never placed in a process argument. When the account
# does not exist (stubbed useradd in tests), the step runs as the invoking
# user — the state directory is theirs anyway.
run_as_service() {
    if [ -n "$RUNUSER" ]; then
        "$RUNUSER" -u "$SERVICE_USER" -- "$@"
    elif getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        if [ "$IS_ROOT" = true ]; then
            runuser -u "$SERVICE_USER" -- "$@"
        else
            sudo -n -u "$SERVICE_USER" -- "$@"
        fi
    else
        env FLEETD_STATE_DIR="$STATE_DIR" "$@"
    fi
}

# Writes one privileged file.
write_priv_file() {
    target=$1
    shift
    if [ "$IS_ROOT" = true ]; then
        cat >"$target"
    elif [ "${#RUN_PRIV[@]}" -gt 0 ]; then
        sudo -n tee "$target" >/dev/null
    else
        cat >"$target"
    fi
}

# --- idempotency: detect an existing, working installation -------------------
HAD_BINARY=false
[ -x "$BIN" ] && HAD_BINARY=true
HAD_UNIT=false
[ -f "$UNIT" ] && HAD_UNIT=true
FORCE_ENROLL="${FLEET_FORCE_ENROLL:-0}"
HAD_CREDENTIAL=false
# The credential test must be privileged: the state directory is 0700
# fleet:fleet, so an unprivileged check cannot even stat it and would
# misread an upgrade as a first install.
if [ "$FORCE_ENROLL" != "1" ]; then
    if [ "$IS_ROOT" = true ]; then
        [ -s "$STATE_DIR/credential" ] && HAD_CREDENTIAL=true
    elif [ "${#RUN_PRIV[@]}" -gt 0 ]; then
        sudo -n test -s "$STATE_DIR/credential" && HAD_CREDENTIAL=true
    else
        [ -s "$STATE_DIR/credential" ] && HAD_CREDENTIAL=true
    fi
fi

CREATED_UNIT=false
CREATED_ENV=false

cleanup() {
    code=$?
    if [ "$code" -ne 0 ]; then
        if [ "$CREATED_UNIT" = true ]; then
            "${RUN_PRIV[@]}" "$SYSTEMCTL" disable --now "$SERVICE" >/dev/null 2>&1 || true
            "${RUN_PRIV[@]}" rm -f "$UNIT"
        fi
        if [ "$CREATED_ENV" = true ]; then
            "${RUN_PRIV[@]}" rm -f "$ENV_FILE"
        fi
        if [ "$CREATED_UNIT" = true ]; then
            "${RUN_PRIV[@]}" "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true
            log "removed the partially installed service; nothing else was touched"
        fi
    fi
    exit "$code"
}
trap cleanup EXIT

# --- system account and state directory ---------------------------------------
# >>> state directory ancestors: kept identical in install.sh and uninstall.sh
# (a test compares the two copies), so the installer never adopts a state
# directory that the purge would refuse.
#
# $STATE_DIR must be an absolute, normalized path (no `//`, `.` or `..`, so
# every test below names the directory `rm` would act on) that is neither a
# system directory nor inside a system, runtime or temporary tree
# (check_state_path). Every ancestor must be a real directory (not a symbolic
# link), owned by root, not writable by group or others, and without a POSIX
# ACL. Then nobody else can swap a path component. (On Linux the group mode
# bits already show an ACL's mask, so the ACL test is defense in depth: a
# directory root set up plainly has none.) When the service account does not
# exist and a non-root user runs the script (stubbed installs), the invoking
# user may own an ancestor instead. With `missing-ok` as $1, an ancestor that
# does not exist yet passes: install.sh is about to create it. A failure calls
# refuse_state with the reason.
#
# ACLs are read with `getfacl --skip-base` when it is installed, otherwise from
# the `+` that `ls -ld` prints after the mode of a file that has one. An ACL
# that cannot be read counts as present.
ancestor_has_acl() {
    local listing
    if command -v getfacl >/dev/null 2>&1; then
        listing="$(getfacl --absolute-names --skip-base --omit-header -- "$1" 2>/dev/null)" \
            || return 0
        [ -n "$listing" ]
        return
    fi
    listing="$(ls -ld -- "$1" 2>/dev/null)" || return 0
    [ "${listing:10:1}" = "+" ]
}
# The state path alone: absolute, normalized, and not a system directory or
# anything inside a system, runtime or temporary tree. The controller's layout
# validator (fleetd_layout.rs) applies the same rule, and a test checks that
# the two agree.
check_state_path() {
    # A relative path has no ancestors to check (and `dirname .` is `.`).
    case "$STATE_DIR" in
        /*) ;;
        *) refuse_state "it is not an absolute path" ;;
    esac
    # `/home/../var/lib` would pass every lexical test below as something it
    # is not.
    case "$STATE_DIR" in
        *//*|*/./*|*/../*|*/.|*/..)
            refuse_state "it is not a normalized path (no //, . or .. components)" ;;
    esac
    case "$STATE_DIR" in
        /|/bin|/home|/lib|/lib32|/lib64|/libx32|/media|/mnt|/opt|/sbin|/snap|/srv|/var|/var/lib|/var/log|/var/cache|/var/spool)
            refuse_state "it is a system directory" ;;
        # Whole trees: system configuration and binaries, kernel and device
        # file systems, and the volatile or shared temporary directories,
        # whose contents a reboot or another user can replace. The ancestor
        # walk starts above the directory, so these are named here.
        /etc|/etc/*|/root|/root/*|/usr|/usr/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/boot|/boot/*|/run|/run/*|/var/run|/var/run/*|/tmp|/tmp/*|/var/tmp|/var/tmp/*)
            refuse_state "it is a system directory or inside one (system, runtime and temporary trees are refused)" ;;
    esac
    case "$STATE_DIR" in
        /*/*) ;;
        *) refuse_state "it is a top-level directory (it must be inside another directory)" ;;
    esac
}
check_state_ancestors() {
    local ancestor_owner dir a_owner a_mode
    check_state_path
    if [ "$IS_ROOT" = true ] || getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        ancestor_owner=root
    else
        ancestor_owner="$(id -un)"
    fi
    dir="$(dirname -- "$STATE_DIR")"
    while :; do
        if [ -L "$dir" ]; then
            refuse_state "its ancestor $dir is a symbolic link"
        elif [ -e "$dir" ] || [ "${1:-}" != missing-ok ]; then
            [ -d "$dir" ] || refuse_state "its ancestor $dir is not a directory"
            a_owner="$(stat -c %U -- "$dir" 2>/dev/null)" || refuse_state "the owner of $dir cannot be read"
            a_mode="$(stat -c %a -- "$dir" 2>/dev/null)" || refuse_state "the mode of $dir cannot be read"
            [ "$a_owner" = root ] || [ "$a_owner" = "$ancestor_owner" ] \
                || refuse_state "its ancestor $dir is owned by $a_owner, not root"
            [ $(( 8#$a_mode & 8#022 )) -eq 0 ] \
                || refuse_state "its ancestor $dir is writable by group or others (mode $a_mode)"
            ! ancestor_has_acl "$dir" \
                || refuse_state "its ancestor $dir has a POSIX ACL (remove it with setfacl -b)"
        fi
        [ "$dir" = / ] && break
        dir="$(dirname -- "$dir")"
    done
}
# <<< state directory ancestors

refuse_state() { die "refusing to adopt the state directory $STATE_DIR: $1"; }

# Ownership flags derive from the account's actual existence: a stubbed
# useradd (tests) creates nothing, and `install -o fleet` would then fail
# even as root.
# The state directory becomes the service account's, and an uninstall with
# --purge deletes it: never adopt a symlink, or a non-empty directory that is
# not already fleetd's (it would hold fleetd's node key).
# Its ancestors first, the way uninstall.sh --purge checks them: a layout the
# purge would refuse is never installed, so it is never recorded either. An
# ancestor this run creates is checked once it exists, below.
check_state_ancestors missing-ok
if [ -L "$STATE_DIR" ]; then
    die "the state directory $STATE_DIR is a symbolic link; refusing to adopt it"
fi
if [ -d "$STATE_DIR" ]; then
    STATE_ENTRY="$("${RUN_PRIV[@]}" find "$STATE_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" \
        || die "the contents of the state directory $STATE_DIR cannot be read; refusing to adopt it"
    if [ -n "$STATE_ENTRY" ] \
        && ! { "${RUN_PRIV[@]}" test -f "$STATE_DIR/node.key" \
            && ! "${RUN_PRIV[@]}" test -L "$STATE_DIR/node.key"; }; then
        die "the state directory $STATE_DIR already holds files that are not fleetd's (no node.key); refusing to adopt it"
    fi
fi
if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    "${RUN_PRIV[@]}" "$USER_ADD" --system --user-group --home-dir "$STATE_DIR" \
        --shell /usr/sbin/nologin "$SERVICE_USER" \
        || die "cannot create the $SERVICE_USER service account"
fi
if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    "${RUN_PRIV[@]}" install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR" \
        || die "cannot prepare the state directory $STATE_DIR"
else
    # No account (stubbed tests): the state directory belongs to the
    # invoking user, so it is created without privilege escalation —
    # fleetd must be able to restrict it.
    install -d -m 0750 "$STATE_DIR" \
        || die "cannot prepare the state directory $STATE_DIR"
fi
# Again, now that every ancestor exists and the service account is settled:
# the first check let the invoking user own an ancestor while no `fleet`
# account existed, and once it exists the ancestors must be root's.
check_state_ancestors

# --- binary (atomic replace) -------------------------------------------------
"${RUN_PRIV[@]}" install -d -m 0755 "$BIN_DIR"
"${RUN_PRIV[@]}" install -m 0755 "$ARCHIVE_DIR/fleetd" "$BIN.fleet-new" \
    || die "cannot stage the binary"
"${RUN_PRIV[@]}" mv -f "$BIN.fleet-new" "$BIN" || die "cannot move the binary into place"

# --- unit + environment ------------------------------------------------------
if [ "$HAD_UNIT" = false ]; then
    "${RUN_PRIV[@]}" install -d -m 0755 "$UNIT_DIR" \
        || die "cannot prepare the unit directory $UNIT_DIR"
    "${RUN_PRIV[@]}" install -m 0644 "$ON_DISK_UNIT" "$UNIT" \
        || die "cannot install the unit"
    CREATED_UNIT=true
fi

# The controller URL is a deployment fact. On an upgrade it already exists in
# the environment file; refuse to silently change it.
if [ -f "$ENV_FILE" ]; then
    grep -q "^FLEETD_CONTROLLER_URL=" "$ENV_FILE" \
        || die "the environment file exists but has no controller URL"
else
    [ -n "${FLEET_CONTROLLER_URL:-}" ] || die "FLEET_CONTROLLER_URL is required on first install"
    "${RUN_PRIV[@]}" install -d -m 0755 "$(dirname "$ENV_FILE")"
    printf 'FLEETD_CONTROLLER_URL=%s\n' "$FLEET_CONTROLLER_URL" | write_priv_file "$ENV_FILE" \
        || die "cannot write the environment file"
    "${RUN_PRIV[@]}" chmod 0644 "$ENV_FILE"
    CREATED_ENV=true
fi

"${RUN_PRIV[@]}" "$SYSTEMCTL" daemon-reload || die "systemd did not accept the unit"
"${RUN_PRIV[@]}" "$SYSTEMCTL" enable "$SERVICE" >/dev/null 2>&1 \
    || die "cannot enable the service"

# --- enrollment (first install, or forced after revocation) -------------------
if [ "$HAD_CREDENTIAL" = true ]; then
    log "existing enrollment found; the identity survives this upgrade"
else
    [ -n "${FLEET_ENROLL_TOKEN:-}" ] || die "FLEET_ENROLL_TOKEN is required on first install"
    [ -n "${FLEET_CONTROLLER_URL:-}" ] || die "FLEET_CONTROLLER_URL is required on first install"
    if [ "$FORCE_ENROLL" = "1" ]; then
        "${RUN_PRIV[@]}" rm -f "$STATE_DIR/node.key" "$STATE_DIR/credential" \
            "$STATE_DIR/machine-id"
        log "forced re-enrollment: the previous node identity was wiped"
    fi
    printf '%s' "$FLEET_ENROLL_TOKEN" | \
        run_as_service "$BIN" enroll --controller "$FLEET_CONTROLLER_URL" \
        --token-stdin --state-dir "$STATE_DIR" \
        || die "enrollment failed"
    log "enrolled; the single-use token was consumed and never stored"
fi

# --- start -------------------------------------------------------------------
"${RUN_PRIV[@]}" "$SYSTEMCTL" restart "$SERVICE" || die "the service did not start"

# --- wait for active ---------------------------------------------------------
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ "$("${RUN_PRIV[@]}" "$SYSTEMCTL" is-active "$SERVICE" 2>/dev/null)" = "active" ]; then
        log "service is active; installed $("$BIN" --version 2>/dev/null || echo fleetd)"
        exit 0
    fi
    sleep 1
done
die "the service never became active"
